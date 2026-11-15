#!/usr/bin/env python3
"""Agent Games — Proof Gatekeeper agent (protocol v1, Groth16 proofs via snarkjs CLI).

Spec: https://agentgames.zkverify.io/build
  preflight : {"type":"agent-games.preflight.v1"}  ->  {"ok":true,"protocolVersion":"v1"}
  task      : {"type":"agent-games.proof-gatekeeper.v1","input":{...}}
  response  : {"decision","reason_code","proof","public_signals","proof_tx","task_id"}

Circuit inputs (GatekeeperEvaluation, 13): decision, minimum, publicBalance, amount,
maxTransfer, expiryBlock, currentBlock, recipient, conditionRecipient,
registeredVkHash, proofVkHash, taskId, salt(private). The circuit constrains
`decision` to equal the conjunction of the payment conditions, so a proof is
attached only when our decision matches that conjunction; rejects for
replay/staleness have no circuit counterpart and are returned bare.

Proofs are produced with the snarkjs CLI (`wtns calculate` then `groth16 prove`),
which is ~1s end-to-end; the JS API path hangs in this environment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, Response

app = FastAPI(title="agent-games-gatekeeper", version="1.3.0")
APP = app

HMAC_SECRET = (os.environ.get("AGENT_GAMES_HMAC_SECRET")
               or os.environ.get("AGENT_HMAC_SECRET") or "").encode()

CLOCK_SKEW_SECONDS = int(os.environ.get("AGENT_CLOCK_SKEW", "180"))
PROVE_TIMEOUT = float(os.environ.get("AGENT_PROVE_TIMEOUT", "25"))
PROVE_ENABLED = os.environ.get("AGENT_PROVE", "1") not in ("0", "false", "False")
SNARKJS = os.environ.get("AGENT_SNARKJS", "/opt/agentgames/gatekeeper-agent/node_modules/.bin/snarkjs")
WASM = os.environ.get("GK_WASM", "/opt/agentgames/circuits/gatekeeper.wasm")
ZKEY = os.environ.get("GK_ZKEY", "/opt/agentgames/circuits/gatekeeper_final.zkey")

EXPECTED_TASK_TYPE = "agent-games.proof-gatekeeper.v1"
PREFLIGHT_TYPE = "agent-games.preflight.v1"
PROTOCOL_VERSION = "v1"

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

_SEEN_PROOF_TX: Dict[str, float] = {}
_REPLAY_TTL = 86_400


def _sign(body: bytes) -> str:
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


def _field(value: Any) -> str:
    """Map a decimal/hex value into the BN254 scalar field."""
    text = str(value if value is not None else "0").strip()
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text or "0")
    except ValueError:
        number = int(hashlib.sha256(text.encode()).hexdigest(), 16)
    return str(number % P)


def _hash_field(text: str) -> str:
    return str(int(hashlib.sha256(text.encode()).hexdigest(), 16) % P)


def circuit_verdict(data: Dict[str, Any]) -> Tuple[bool, str]:
    """The five conditions the circuit actually constrains, in check order."""
    registered_vk = _norm(data.get("registered_vk"))
    proof_vk = _norm(data.get("proof_vk"))
    if not registered_vk or not proof_vk or registered_vk != proof_vk:
        return False, "VK_SUBSTITUTION"

    minimum = _to_int(data.get("minimum"))
    public_balance = _to_int(data.get("public_balance"))
    if minimum is None or public_balance is None or public_balance < minimum:
        return False, "THRESHOLD_MISMATCH"

    current_block = _to_int(data.get("current_block"))
    expiry_block = _to_int(data.get("expiry_block"))
    if current_block is None or expiry_block is None or current_block >= expiry_block:
        return False, "EXPIRED_CONDITION"

    recipient = _norm(data.get("recipient"))
    condition_recipient = _norm(data.get("condition_recipient"))
    if not recipient or not condition_recipient or recipient != condition_recipient:
        return False, "RECIPIENT_MISMATCH"

    amount = _to_int(data.get("amount"))
    max_transfer = _to_int(data.get("max_transfer"))
    if amount is None or amount <= 0:
        return False, "INVALID_AMOUNT"
    if max_transfer is not None and amount > max_transfer:
        return False, "AMOUNT_EXCEEDS_MAX"

    return True, "VALID_CONDITION"


def circuit_inputs(data: Dict[str, Any], decision: bool, task_id: str) -> Dict[str, str]:
    salt_seed = hmac.new(HMAC_SECRET or b"local", f"gatekeeper-salt:{task_id}".encode(),
                         hashlib.sha256).hexdigest()
    return {
        "decision": "1" if decision else "0",
        "minimum": _field(data.get("minimum")),
        "publicBalance": _field(data.get("public_balance")),
        "amount": _field(data.get("amount")),
        "maxTransfer": _field(data.get("max_transfer")),
        "expiryBlock": _field(data.get("expiry_block")),
        "currentBlock": _field(data.get("current_block")),
        "recipient": _field(data.get("recipient")),
        "conditionRecipient": _field(data.get("condition_recipient")),
        "registeredVkHash": _field(data.get("registered_vk")),
        "proofVkHash": _field(data.get("proof_vk")),
        "taskId": _hash_field("taskId:" + task_id),
        "salt": _field(salt_seed),
    }


def prove(data: Dict[str, Any], decision: bool, task_id: str) -> Optional[Dict[str, Any]]:
    """Generate a Groth16 proof with the snarkjs CLI. Returns None on any failure."""
    if not PROVE_ENABLED:
        return None
    if not (os.path.exists(SNARKJS) and os.path.exists(WASM) and os.path.exists(ZKEY)):
        print("prover: missing binary or circuit artifacts", flush=True)
        return None

    workdir = tempfile.mkdtemp(prefix="gk-prove-")
    try:
        inp = os.path.join(workdir, "input.json")
        wtns = os.path.join(workdir, "witness.wtns")
        proof_path = os.path.join(workdir, "proof.json")
        public_path = os.path.join(workdir, "public.json")
        with open(inp, "w") as fh:
            json.dump(circuit_inputs(data, decision, task_id), fh)

        for cmd in ([SNARKJS, "wtns", "calculate", WASM, inp, wtns],
                    [SNARKJS, "groth16", "prove", ZKEY, wtns, proof_path, public_path]):
            proc = subprocess.run(cmd, capture_output=True, timeout=PROVE_TIMEOUT)
            if proc.returncode != 0:
                print(f"prover failed: {cmd[1]} rc={proc.returncode} "
                      f"{proc.stderr[:180].decode(errors='ignore')}", flush=True)
                return None

        with open(proof_path) as fh:
            proof = json.load(fh)
        with open(public_path) as fh:
            public_signals = json.load(fh)
        return {"proof": proof, "public_signals": public_signals}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"prover error: {type(exc).__name__}", flush=True)
        return None
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def decide(task: Dict[str, Any]) -> Dict[str, Any]:
    data = task.get("input") or {}
    task_id = str(task.get("task_id") or "")

    issued = _parse_iso(task.get("issued_at"))
    if issued is not None and abs(time.time() - issued) > CLOCK_SKEW_SECONDS:
        return {"decision": "REJECT", "reason_code": "STALE_TASK"}

    proof_tx = data.get("proof_tx") or task.get("proof_tx")
    if not proof_tx:
        return {"decision": "REJECT", "reason_code": "MISSING_PROOF_TX"}
    if _seen_proof_tx(str(proof_tx).lower()):
        # Reused proof is rejected outside the circuit, so no proof is attached.
        return {"decision": "REJECT", "reason_code": "REPLAYED_PROOF", "proof_tx": proof_tx}

    approved, reason = circuit_verdict(data)
    verdict: Dict[str, Any] = {
        "decision": "APPROVE" if approved else "REJECT",
        "reason_code": reason,
        "proof_tx": proof_tx,
    }
    evidence = prove(data, approved, task_id)
    if evidence:
        verdict.update(evidence)
    return verdict


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "protocolVersion": PROTOCOL_VERSION,
            "hmacConfigured": bool(HMAC_SECRET),
            "proverEnabled": PROVE_ENABLED and os.path.exists(SNARKJS)}


@app.post("/agent")
async def agent(request: Request) -> Response:
    raw = await request.body()

    if not _signature_ok(raw, request.headers.get("x-agent-games-signature", "")):
        return _respond({"error": "invalid_signature"}, status=401)

    try:
        task = json.loads(raw)
    except json.JSONDecodeError:
        return _respond({"decision": "REJECT", "reason_code": "MALFORMED_ENVELOPE"}, status=400)

    kind = task.get("type") or task.get("event") or ""

    if kind == PREFLIGHT_TYPE or ("nonce" in task and "input" not in task):
        return _respond({"ok": True, "protocolVersion": PROTOCOL_VERSION})

    if kind and kind != EXPECTED_TASK_TYPE:
        return _respond({"decision": "REJECT", "reason_code": "UNSUPPORTED_TASK_TYPE"})

    verdict = decide(task)
    if task.get("task_id"):
        verdict["task_id"] = task["task_id"]
    return _respond(verdict)
