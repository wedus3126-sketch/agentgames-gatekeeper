#!/usr/bin/env python3
"""Local end-to-end test: signed task in, signed decision out."""
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.environ.get("TEST_BASE", "http://127.0.0.1:8099")
SECRET = os.environ["AGENT_HMAC_SECRET"].encode()

VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"


def envelope(**overrides):
    task = {
        "taskId": "GK_TEST_1",
        "issuedAt": int(time.time()),
        "verification": {
            "vkHash": VK,
            "proofSystem": "groth16",
            "curve": "bn128",
            "circuit": "gatekeeper",
            "status": "finalized",
            "proofReference": "0xref-" + str(time.time_ns()),
        },
        "publicInputs": {"amount": "1500", "recipient": "0xDe42Abc9f01", "action": "transfer"},
        "condition": {"vkHash": VK, "circuit": "gatekeeper", "minAmount": "1000"},
        "request": {"recipient": "0xDe42Abc9f01", "action": "transfer"},
    }
    task.update(overrides)
    return task


def post(task, secret=SECRET, tamper=False):
    raw = json.dumps(task, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(secret, raw, hashlib.sha256).hexdigest()
    if tamper:
        raw = raw.replace(b"transfer", b"withdraw")
    req = urllib.request.Request(
        BASE + "/agent", data=raw,
        headers={"Content-Type": "application/json",
                 "x-agent-games-signature": "sha256=" + sig},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read()), resp.headers.get("x-agent-games-signature")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read()), exc.headers.get("x-agent-games-signature")


def main():
    with urllib.request.urlopen(BASE + "/health", timeout=5) as r:
        print("health:", json.loads(r.read()))

    cases = [
        ("valid condition", envelope(), False),
        ("recipient mismatch", envelope(request={"recipient": "0x7a01C4b2", "action": "transfer"}), False),
        ("threshold mismatch", envelope(publicInputs={"amount": "500", "recipient": "0xDe42Abc9f01", "action": "transfer"}), False),
        ("vk substitution", envelope(verification={**envelope()["verification"], "vkHash": "0xdeadbeef"}), False),
        ("not finalized", envelope(verification={**envelope()["verification"], "status": "included"}), False),
        ("stale task", envelope(issuedAt=int(time.time()) - 3600), False),
        ("bad signature", envelope(), True),
    ]
    ok = True
    for name, task, tamper in cases:
        status, body, resp_sig = post(task, tamper=tamper)
        decision = body.get("decision")
        reasons = body.get("reasons")
        signed = bool(resp_sig)
        expect = "APPROVE" if name == "valid condition" else "REJECT"
        verdict = "PASS" if decision == expect and signed else "FAIL"
        ok = ok and verdict == "PASS"
        print(f"{verdict} | {name:22s} | {status} | {decision:7s} | {','.join(reasons)} | signed={signed}")
    print("ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
