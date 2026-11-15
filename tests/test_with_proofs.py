#!/usr/bin/env python3
"""End-to-end test: every decision path, and proof validity on the provable ones."""
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = os.environ.get("TEST_BASE", "http://127.0.0.1:8099")
SECRET = os.environ["AGENT_GAMES_HMAC_SECRET"].encode()
VKEY = os.environ.get("GK_VKEY", "/tmp/vk.json")
SNARKJS = os.environ.get("SNARKJS", "/home/user9/agentgames/gatekeeper-agent/node_modules/.bin/snarkjs")
VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
RECIP = "0xDe42000000000000000000000000000000009f01"


def iso(delta=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")


def task(unique="1", **over):
    body = {
        "type": "agent-games.proof-gatekeeper.v1",
        "task_id": f"gk_test_{unique}",
        "mode": "competition",
        "issued_at": iso(),
        "deadline_at": iso(60),
        "input": {
            "registered_vk": VK, "proof_vk": VK,
            "minimum": "1000", "public_balance": "1460",
            "expiry_block": 8430000, "current_block": 8420000,
            "recipient": RECIP, "condition_recipient": RECIP,
            "amount": "500", "max_transfer": "1000",
            "proof_tx": f"0xtx{unique}{time.time_ns()}",
        },
    }
    for k, v in over.items():
        if k in body["input"]:
            body["input"][k] = v
        else:
            body[k] = v
    return body


def post(payload, tamper=False):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    if tamper:
        raw = raw.replace(RECIP.encode(), b"0xdeadbeef")
    req = urllib.request.Request(BASE + "/agent", data=raw,
                                 headers={"Content-Type": "application/json",
                                          "x-agent-games-signature": sig}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.status, json.loads(r.read()), r.headers.get("x-agent-games-signature")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), e.headers.get("x-agent-games-signature")


def verify_proof(proof, public_signals):
    with open("/tmp/_p.json", "w") as f:
        json.dump(proof, f)
    with open("/tmp/_s.json", "w") as f:
        json.dump(public_signals, f)
    r = subprocess.run([SNARKJS, "groth16", "verify", VKEY, "/tmp/_s.json", "/tmp/_p.json"],
                       capture_output=True, text=True, timeout=120)
    return "OK!" in (r.stdout + r.stderr)


def main():
    with urllib.request.urlopen(BASE + "/health", timeout=10) as r:
        print("health:", json.loads(r.read()))

    rows = []

    st, body, sig = post({"type": "agent-games.preflight.v1", "agent_id": "agt_1",
                          "issued_at": iso(), "nonce": "abc123"})
    rows.append(("preflight", body.get("ok") is True and body.get("protocolVersion") == "v1", body, sig))

    st, body, sig = post(task("1"))
    ok_proof = body.get("proof") and body.get("public_signals") and verify_proof(body["proof"], body["public_signals"])
    rows.append(("approve + valid proof", body.get("decision") == "APPROVE" and body.get("reason_code") == "VALID_CONDITION" and ok_proof, body, sig))

    st, body, sig = post(task("2", proof_vk="0xdeadbeef"))
    ok_proof = body.get("proof") and verify_proof(body["proof"], body["public_signals"])
    rows.append(("reject vk + valid proof", body.get("reason_code") == "VK_SUBSTITUTION" and ok_proof, body, sig))

    st, body, sig = post(task("3", public_balance="500"))
    ok_proof = body.get("proof") and verify_proof(body["proof"], body["public_signals"])
    rows.append(("reject threshold + proof", body.get("reason_code") == "THRESHOLD_MISMATCH" and ok_proof, body, sig))

    st, body, sig = post(task("4", current_block=8430000))
    rows.append(("reject expired", body.get("reason_code") == "EXPIRED_CONDITION", body, sig))

    st, body, sig = post(task("5", recipient="0x7a01c4b2"))
    rows.append(("reject recipient", body.get("reason_code") == "RECIPIENT_MISMATCH", body, sig))

    st, body, sig = post(task("6", amount="5000"))
    rows.append(("reject amount cap", body.get("reason_code") == "AMOUNT_EXCEEDS_MAX", body, sig))

    t7 = task("7")
    post(t7)
    st, body, sig = post(t7)
    rows.append(("reject replay (no proof)", body.get("reason_code") == "REPLAYED_PROOF" and "proof" not in body, body, sig))

    st, body, sig = post(task("8", issued_at=iso(-3600)))
    rows.append(("reject stale", body.get("reason_code") == "STALE_TASK", body, sig))

    st, body, sig = post(task("9"), tamper=True)
    rows.append(("bad signature 401", st == 401, body, sig))

    failed = 0
    for name, ok, body, sig in rows:
        signed = bool(sig)
        good = bool(ok) and signed
        failed += 0 if good else 1
        print(f"{'PASS' if good else 'FAIL'} | {name:26s} | {body.get('decision') or body.get('error') or body.get('ok')} "
              f"| {body.get('reason_code') or body.get('protocolVersion') or ''} | proof={'yes' if body.get('proof') else 'no'} | signed={signed}")
    print("ALL PASS" if not failed else f"{failed} FAILED")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
