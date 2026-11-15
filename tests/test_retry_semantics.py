#!/usr/bin/env python3
"""Retry/idempotency semantics: platform redelivery must not look like a replay."""
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
RECIP = "0xDe42000000000000000000000000000000009f01"


def iso(delta=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")


def task(task_id, proof_tx):
    return {
        "type": "agent-games.proof-gatekeeper.v1",
        "task_id": task_id,
        "mode": "competition",
        "issued_at": iso(),
        "deadline_at": iso(60),
        "input": {
            "registered_vk": VK, "proof_vk": VK,
            "minimum": "1000", "public_balance": "1460",
            "expiry_block": 8430000, "current_block": 8420000,
            "recipient": RECIP, "condition_recipient": RECIP,
            "amount": "500", "max_transfer": "1000",
            "proof_tx": proof_tx,
        },
    }


def post(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    req = urllib.request.Request(BASE + "/agent", data=raw,
                                 headers={"Content-Type": "application/json",
                                          "x-agent-games-signature": sig}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    tx = "0xretry" + str(time.time_ns())
    tid = "gk_retry_" + str(int(time.time()))
    rows = []

    st1, first = post(task(tid, tx))
    st2, second = post(task(tid, tx))
    rows.append(("redelivery returns same verdict",
                 first.get("decision") == "APPROVE" and second.get("decision") == "APPROVE"
                 and second.get("reason_code") == "VALID_CONDITION"))

    st3, third = post(task(tid + "_other", tx))
    rows.append(("same proof_tx under new task is a replay",
                 third.get("reason_code") == "REPLAYED_PROOF"))

    st4, fourth = post(task(tid + "_fresh", "0xfresh" + str(time.time_ns())))
    rows.append(("fresh task still approves", fourth.get("decision") == "APPROVE"))

    failed = 0
    for name, ok in rows:
        failed += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} | {name}")
    print("ALL PASS" if not failed else f"{failed} FAILED")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
