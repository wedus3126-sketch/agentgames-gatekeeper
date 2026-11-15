#!/usr/bin/env python3
"""Protocol-v1 local test harness: preflight + Proof Gatekeeper envelopes."""
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = os.environ.get("TEST_BASE", "http://127.0.0.1:8099")
SECRET = os.environ["AGENT_GAMES_HMAC_SECRET"].encode()

VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"


def iso(delta=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")


def task(**over):
    body = {
        "type": "agent-games.proof-gatekeeper.v1",
        "task_id": "gk_test_1",
        "mode": "competition",
        "issued_at": iso(),
        "deadline_at": iso(60),
        "input": {
            "registered_vk": VK,
            "proof_vk": VK,
            "minimum": "1000",
            "public_balance": "1460",
            "expiry_block": 8430000,
            "current_block": 8420000,
            "recipient": "0xde429f01",
            "condition_recipient": "0xde429f01",
            "amount": "500",
            "max_transfer": "1000",
            "proof_tx": "0xtx" + str(time.time_ns()),
        },
    }
    body.update(over)
    return body


def inp(**over):
    base = task()["input"].copy()
    base.update(over)
    return {"input": base}


def post(payload, tamper=False):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    if tamper:
        raw = raw.replace(b"0xde429f01", b"0xdeadbeef")
    req = urllib.request.Request(
        BASE + "/agent", data=raw,
        headers={"Content-Type": "application/json", "x-agent-games-signature": "sha256=" + sig},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()), r.headers.get("x-agent-games-signature")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), e.headers.get("x-agent-games-signature")


def main():
    with urllib.request.urlopen(BASE + "/health", timeout=5) as r:
        print("health:", json.loads(r.read()))

    cases = [
        ("preflight", {"type": "agent-games.preflight.v1", "agent_id": "agt_1",
                       "issued_at": iso(), "nonce": "abc123"}, "ok", None),
        ("valid condition", task(), "APPROVE", "VALID_CONDITION"),
        ("vk substitution", task(**inp(proof_vk="0xdeadbeef")), "REJECT", "VK_SUBSTITUTION"),
        ("threshold mismatch", task(**inp(public_balance="500")), "REJECT", "THRESHOLD_MISMATCH"),
        ("recipient mismatch", task(**inp(recipient="0x7a01c4b2")), "REJECT", "RECIPIENT_MISMATCH"),
        ("expired condition", task(**inp(current_block=8430000)), "REJECT", "EXPIRED_CONDITION"),
        ("amount over max", task(**inp(amount="5000", max_transfer="1000")), "REJECT", "AMOUNT_EXCEEDS_MAX"),
        ("stale task", task(issued_at=iso(-3600)), "REJECT", "STALE_TASK"),
    ]
    ok = True
    for name, payload, expect, reason in cases:
        status, body, sig = post(payload)
        got = body.get("decision") if expect != "ok" else ("ok" if body.get("ok") else "not-ok")
        reasons_ok = True if reason is None else body.get("reason_code") == reason
        verdict = "PASS" if got == expect and reasons_ok and bool(sig) else "FAIL"
        ok = ok and verdict == "PASS"
        print(f"{verdict} | {name:20s} | {status} | {got:7s} | {body.get('reason_code') or body.get('protocolVersion')} | signed={bool(sig)}")

    status, body, sig = post(task(), tamper=True)
    good = status == 401 and bool(sig)
    ok = ok and good
    print(f"{'PASS' if good else 'FAIL'} | {'bad signature':20s} | {status} | {body.get('error')} | signed={bool(sig)}")

    print("ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
