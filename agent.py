#!/usr/bin/env python3
"""Agent Games — Proof Gatekeeper agent (protocol v1).

Authoritative spec: https://agentgames.zkverify.io/build
  preflight : {"type":"agent-games.preflight.v1", ...}  ->  {"ok":true,"protocolVersion":"v1"}
  task      : {"type":"agent-games.proof-gatekeeper.v1", "input":{...}}
  response  : {"decision":"APPROVE|REJECT","reason_code":"...","proof_tx":"0x..."}
Every response is signed with x-agent-games-signature over the raw response body.

Decision rules are deterministic code and fail closed: any doubt -> REJECT.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, Response

app = FastAPI(title="agent-games-gatekeeper", version="1.1.0")
APP = app

# Platform secret (dashboard -> Rotate Secret). Legacy env name kept as fallback.
HMAC_SECRET = (os.environ.get("AGENT_GAMES_HMAC_SECRET")
               or os.environ.get("AGENT_HMAC_SECRET") or "").encode()

CLOCK_SKEW_SECONDS = int(os.environ.get("AGENT_CLOCK_SKEW", "180"))
DECISION_DEADLINE = float(os.environ.get("AGENT_DEADLINE", "55"))
EXPECTED_TASK_TYPE = "agent-games.proof-gatekeeper.v1"
PREFLIGHT_TYPE = "agent-games.preflight.v1"
PROTOCOL_VERSION = "v1"

_SEEN_PROOF_TX: Dict[str, float] = {}
_REPLAY_TTL = 86_400


def _sign(body: bytes) -> str:
    """Bare lowercase hex, matching the header format the platform itself sends."""
    if not HMAC_SECRET:
        return ""
    return hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()


def _respond(payload: Dict[str, Any], status: int = 200) -> Response:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return Response(content=body, media_type="application/json", status_code=status,
                    headers={"x-agent-games-signature": _sign(body)})


def _signature_ok(raw: bytes, header: str) -> bool:
    if not HMAC_SECRET or not header:
        print(f"sigcheck: secret={bool(HMAC_SECRET)} header={bool(header)}", flush=True)
        return False
    provided = header.strip()
    if provided.startswith("sha256="):
        provided = provided.split("=", 1)[1]
    expected = hmac.new(HMAC_SECRET, raw, hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(expected, provided.lower())
    if not ok:
        # Hex digests only — never the secret itself.
        print(f"sigcheck MISMATCH expected={expected[:16]} provided={provided[:16]} "
              f"bodylen={len(raw)}", flush=True)
    return ok


def _seen_proof_tx(reference: str) -> bool:
    now = time.time()
    for key, ts in list(_SEEN_PROOF_TX.items()):
        if now - ts > _REPLAY_TTL:
            _SEEN_PROOF_TX.pop(key, None)
    if reference in _SEEN_PROOF_TX:
        return True
    _SEEN_PROOF_TX[reference] = now
    return False


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _parse_iso(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def decide(task: Dict[str, Any]) -> Dict[str, str]:
    """Deterministic verdict: first failing check wins, default is reject."""
    data = task.get("input") or {}

    issued = _parse_iso(task.get("issued_at"))
    if issued is not None and abs(time.time() - issued) > CLOCK_SKEW_SECONDS:
        return {"decision": "REJECT", "reason_code": "STALE_TASK"}

    registered_vk = _norm(data.get("registered_vk"))
    proof_vk = _norm(data.get("proof_vk"))
    if not registered_vk or not proof_vk or registered_vk != proof_vk:
        return {"decision": "REJECT", "reason_code": "VK_SUBSTITUTION"}

    current_block = _to_int(data.get("current_block"))
    expiry_block = _to_int(data.get("expiry_block"))
    if current_block is not None and expiry_block is not None and current_block >= expiry_block:
        return {"decision": "REJECT", "reason_code": "EXPIRED_CONDITION"}

    minimum = _to_int(data.get("minimum"))
    public_balance = _to_int(data.get("public_balance"))
    if minimum is None or public_balance is None or public_balance < minimum:
        return {"decision": "REJECT", "reason_code": "THRESHOLD_MISMATCH"}

    recipient = _norm(data.get("recipient"))
    condition_recipient = _norm(data.get("condition_recipient"))
    if not recipient or not condition_recipient or recipient != condition_recipient:
        return {"decision": "REJECT", "reason_code": "RECIPIENT_MISMATCH"}

    amount = _to_int(data.get("amount"))
    max_transfer = _to_int(data.get("max_transfer"))
    if amount is None or amount <= 0:
        return {"decision": "REJECT", "reason_code": "INVALID_AMOUNT"}
    if max_transfer is not None and amount > max_transfer:
        return {"decision": "REJECT", "reason_code": "AMOUNT_EXCEEDS_MAX"}
    if public_balance is not None and amount > public_balance:
        return {"decision": "REJECT", "reason_code": "INSUFFICIENT_BALANCE"}

    proof_tx = data.get("proof_tx") or task.get("proof_tx")
    if not proof_tx:
        return {"decision": "REJECT", "reason_code": "MISSING_PROOF_TX"}
    if _seen_proof_tx(str(proof_tx).lower()):
        return {"decision": "REJECT", "reason_code": "REPLAYED_PROOF"}

    return {"decision": "APPROVE", "reason_code": "VALID_CONDITION"}


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "protocolVersion": PROTOCOL_VERSION,
            "hmacConfigured": bool(HMAC_SECRET)}


@app.post("/agent")
async def agent(request: Request) -> Response:
    started = time.monotonic()
    raw = await request.body()

    if not _signature_ok(raw, request.headers.get("x-agent-games-signature", "")):
        return _respond({"error": "invalid_signature"}, status=401)

    try:
        task = json.loads(raw)
    except json.JSONDecodeError:
        return _respond({"decision": "REJECT", "reason_code": "MALFORMED_ENVELOPE"}, status=400)

    kind = task.get("type") or task.get("event") or ""

    # Preflight handshake: answer exactly this, signed.
    if kind == PREFLIGHT_TYPE or ("nonce" in task and "input" not in task):
        return _respond({"ok": True, "protocolVersion": PROTOCOL_VERSION})

    if kind and kind != EXPECTED_TASK_TYPE:
        return _respond({"decision": "REJECT", "reason_code": "UNSUPPORTED_TASK_TYPE"})

    if (time.monotonic() - started) > DECISION_DEADLINE:
        return _respond({"decision": "REJECT", "reason_code": "DEADLINE_EXCEEDED"})

    verdict = decide(task)
    data = task.get("input") or {}
    if data.get("proof_tx"):
        verdict["proof_tx"] = data["proof_tx"]
    if task.get("task_id"):
        verdict["task_id"] = task["task_id"]
    return _respond(verdict)
