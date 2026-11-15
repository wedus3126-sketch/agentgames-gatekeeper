#!/usr/bin/env python3
"""Agent Games — Proof Gatekeeper agent.

Receives HMAC-signed task envelopes, decides APPROVE/REJECT on proof-backed
payment requests, and answers with a signed, deterministic decision.

Security rules enforced (see Agent Games build guide, section 04):
  1. task signature + timestamp valid before any work
  2. verification key matches the key registered for the condition
  3. circuit + proof system are the ones the task expects
  4. public inputs prove threshold, recipient and action
  5. proof reference has not been used before (replay guard)
  6. verification reached Finalized before approval
  7. response is signed with x-agent-games-signature over the raw body
  8. fail closed: timeout, uncertainty or missing evidence -> REJECT

Run:  uvicorn agent:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, Response

app = FastAPI(title="agent-games-gatekeeper", version="1.0.0")
APP = app  # alias kept for imports

HMAC_SECRET = os.environ.get("AGENT_HMAC_SECRET", "").encode()
RESPONSE_SECRET = os.environ.get("AGENT_RESPONSE_SECRET", "").encode()
CLOCK_SKEW_SECONDS = int(os.environ.get("AGENT_CLOCK_SKEW", "120"))
DECISION_DEADLINE = float(os.environ.get("AGENT_DEADLINE", "55"))  # platform cap is 60s

# vk_hash of the gatekeeper circuit registered on zkVerify mainnet.
GATEKEEPER_VK_HASH = os.environ.get(
    "GATEKEEPER_VK_HASH",
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
).lower()
EXPECTED_PROOF_SYSTEM = os.environ.get("EXPECTED_PROOF_SYSTEM", "groth16").lower()
EXPECTED_CURVE = os.environ.get("EXPECTED_CURVE", "bn128").lower()

_SEEN_REFERENCES: Dict[str, float] = {}
_REPLAY_TTL = 86_400


def _seen_before(reference: str) -> bool:
    now = time.time()
    for key, ts in list(_SEEN_REFERENCES.items()):
        if now - ts > _REPLAY_TTL:
            _SEEN_REFERENCES.pop(key, None)
    if reference in _SEEN_REFERENCES:
        return True
    _SEEN_REFERENCES[reference] = now
    return False


def _verify_task_signature(raw: bytes, signature: str) -> bool:
    if not HMAC_SECRET or not signature:
        return False
    expected = hmac.new(HMAC_SECRET, raw, hashlib.sha256).hexdigest()
    provided = signature.strip()
    if provided.startswith("sha256="):
        provided = provided.split("=", 1)[1]
    return hmac.compare_digest(expected, provided.lower())


def _sign_response(body: bytes) -> str:
    if not RESPONSE_SECRET:
        return ""
    return "sha256=" + hmac.new(RESPONSE_SECRET, body, hashlib.sha256).hexdigest()


def _respond(payload: Dict[str, Any], status: int = 200) -> Response:
    """Every answer is signed, including rejections — the platform checks all of them."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return Response(
        content=body,
        media_type="application/json",
        status_code=status,
        headers={"x-agent-games-signature": _sign_response(body)},
    )


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def decide(task: Dict[str, Any]) -> Dict[str, Any]:
    """Return one deterministic decision plus the reasons behind it."""
    reasons = []

    # 1. timestamp freshness — the platform expects a fast, in-window answer
    issued = task.get("issuedAt") or task.get("timestamp") or task.get("createdAt")
    if isinstance(issued, (int, float)):
        issued_epoch = float(issued) / (1000 if issued > 1e11 else 1)
    elif isinstance(issued, str) and issued:
        try:
            issued_epoch = float(issued)
            if issued_epoch > 1e11:
                issued_epoch /= 1000
        except ValueError:
            issued_epoch = None
    else:
        issued_epoch = None
    if issued_epoch is None:
        reasons.append("MISSING_TIMESTAMP")
    elif abs(time.time() - issued_epoch) > CLOCK_SKEW_SECONDS:
        reasons.append("STALE_TIMESTAMP")

    verification = task.get("verification") or {}
    public_inputs = task.get("publicInputs") or verification.get("publicInputs") or {}
    condition = task.get("condition") or {}
    request = task.get("request") or {}

    # 2. verification key must be the one registered for this condition
    vk_hash = _norm(verification.get("vkHash") or task.get("vkHash"))
    expected_vk = _norm(condition.get("vkHash") or GATEKEEPER_VK_HASH)
    if vk_hash != expected_vk:
        reasons.append("VK_MISMATCH")

    # 3. circuit + proof system must be the expected pair
    if _norm(verification.get("proofSystem") or task.get("proofSystem")) != EXPECTED_PROOF_SYSTEM:
        reasons.append("PROOF_SYSTEM_MISMATCH")
    if _norm(verification.get("curve") or task.get("curve")) != EXPECTED_CURVE:
        reasons.append("CURVE_MISMATCH")
    expected_circuit = _norm(condition.get("circuit") or "gatekeeper")
    if _norm(verification.get("circuit") or task.get("circuit")) != expected_circuit:
        reasons.append("CIRCUIT_MISMATCH")

    # 4. public inputs must prove the exact threshold, recipient and action
    def num(value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    proven_amount = num(public_inputs.get("amount") or public_inputs.get("value"))
    required_min = num(condition.get("minAmount") or condition.get("threshold"))
    if required_min is None:
        reasons.append("MISSING_THRESHOLD")
    elif proven_amount is None or proven_amount < required_min:
        reasons.append("THRESHOLD_MISMATCH")

    proven_recipient = _norm(public_inputs.get("recipient"))
    requested_recipient = _norm(request.get("recipient") or condition.get("recipient"))
    if not proven_recipient or not requested_recipient:
        reasons.append("MISSING_RECIPIENT")
    elif proven_recipient != requested_recipient:
        reasons.append("RECIPIENT_MISMATCH")

    proven_action = _norm(public_inputs.get("action"))
    requested_action = _norm(request.get("action") or condition.get("action"))
    if not proven_action or not requested_action:
        reasons.append("MISSING_ACTION")
    elif proven_action != requested_action:
        reasons.append("ACTION_MISMATCH")

    # 5. replay guard on the proof reference
    reference = verification.get("proofReference") or task.get("proofReference")
    if not reference:
        reasons.append("MISSING_PROOF_REFERENCE")
    elif _seen_before(str(reference)):
        reasons.append("REPLAYED_PROOF")

    # 6. verification must be finalized on-chain
    status = _norm(verification.get("status") or verification.get("state"))
    if status not in ("finalized", "finalised"):
        reasons.append("NOT_FINALIZED")

    decision = "APPROVE" if not reasons else "REJECT"
    return {
        "decision": decision,
        "reasons": reasons or ["VALID_CONDITION"],
        "taskId": task.get("taskId") or task.get("id"),
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "hmacConfigured": bool(HMAC_SECRET),
        "responseSigningConfigured": bool(RESPONSE_SECRET),
        "vkHash": GATEKEEPER_VK_HASH,
    }


@app.post("/agent")
async def agent(request: Request) -> Response:
    started = time.monotonic()
    raw = await request.body()
    signature = request.headers.get("x-agent-games-signature", "")

    if not _verify_task_signature(raw, signature):
        return _respond({"decision": "REJECT", "reasons": ["INVALID_TASK_SIGNATURE"]}, status=401)

    try:
        task = json.loads(raw)
    except json.JSONDecodeError:
        return _respond({"decision": "REJECT", "reasons": ["MALFORMED_ENVELOPE"]}, status=400)

    result = decide(task)
    result["elapsedMs"] = int((time.monotonic() - started) * 1000)
    if result["elapsedMs"] > DECISION_DEADLINE * 1000:
        result = {"decision": "REJECT", "reasons": ["DEADLINE_EXCEEDED"],
                  "taskId": result.get("taskId")}

    return _respond(result)
