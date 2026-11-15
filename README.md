# Agent Games — Proof Gatekeeper agent (protocol v1)

Deterministic gatekeeper agent for the zkVerify **Agent Games** Proof Gatekeeper event.
The platform POSTs HMAC-signed task envelopes; this agent decides `APPROVE` / `REJECT`
and signs its answer.

Spec followed: <https://agentgames.zkverify.io/build>

## Contract

`POST /agent` — signed JSON, `x-agent-games-signature: <lowercase hex hmac-sha256>` over the
**raw** request body, using `AGENT_GAMES_HMAC_SECRET` (issued once by the dashboard's
*Rotate Secret*). Every response carries the same header, computed over the raw response body.

`GET /health` — liveness probe.

### Preflight handshake

```
in : {"type":"agent-games.preflight.v1","agent_id":"agt_...","issued_at":"...","nonce":"..."}
out: {"ok":true,"protocolVersion":"v1"}          # signed
```

Preflight must pass before the platform marks the agent active.

### Task envelope (Proof Gatekeeper)

```
{"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_...","mode":"competition",
 "issued_at":"...","deadline_at":"...",
 "input":{"registered_vk":"0x..","proof_vk":"0x..","minimum":"1000","public_balance":"1460",
          "expiry_block":8430000,"current_block":8420000,"recipient":"0x..",
          "condition_recipient":"0x..","amount":"500","max_transfer":"1000","proof_tx":"0x.."}}
```

### Response

```
{"decision":"APPROVE","reason_code":"VALID_CONDITION","proof_tx":"0x.."}
```

## Decision rules (deterministic, fail-closed)

Checks run in order; the first failure wins and the answer is `REJECT`.

| # | Check | reason_code |
|---|---|---|
| 1 | inbound HMAC matches raw body | `401 invalid_signature` |
| 2 | `issued_at` within `AGENT_CLOCK_SKEW` (default 180s) | `STALE_TASK` |
| 3 | `registered_vk == proof_vk` | `VK_SUBSTITUTION` |
| 4 | `current_block < expiry_block` | `EXPIRED_CONDITION` |
| 5 | `public_balance >= minimum` | `THRESHOLD_MISMATCH` |
| 6 | `recipient == condition_recipient` | `RECIPIENT_MISMATCH` |
| 7 | `0 < amount <= max_transfer` | `INVALID_AMOUNT`, `AMOUNT_EXCEEDS_MAX` |
| 8 | `amount <= public_balance` | `INSUFFICIENT_BALANCE` |
| 9 | `proof_tx` present and never seen before | `MISSING_PROOF_TX`, `REPLAYED_PROOF` |
| 10 | all of the above | `APPROVE` / `VALID_CONDITION` |

Any timeout or ambiguity rejects — the agent never approves by default.

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export AGENT_GAMES_HMAC_SECRET='<from Rotate Secret>'
uvicorn agent:app --host 0.0.0.0 --port 8080
```

Deployment used in this entry: Amazon Linux 2023 EC2 (ap-southeast-2), systemd unit
`agentgames-gatekeeper` on `127.0.0.1:8080`, Caddy terminating TLS in front of it.

## Tests

```bash
AGENT_GAMES_HMAC_SECRET=test-secret .venv/bin/python tests/test_protocol_v1.py
```

Covers preflight, a valid approval, and each rejection path (VK substitution, threshold,
recipient, expiry, amount cap, stale task, bad signature). All responses are verified signed.

## Not yet implemented

Groth16 proof generation (`snarkjs` + `gatekeeper.wasm` / `gatekeeper_final.zkey`) and Kurier
submission. The spec deducts −2 when a provable task returns no valid proof; decisions are
still scored independently.

## Circuit reference (zkVerify mainnet)

| circuit | vk_hash |
|---|---|
| gatekeeper | `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` |
| vfy-policy | `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047` |

## Secrets

Never commit `.env`; only `.env.example` ships. A placeholder secret makes preflight fail
with a signature error.
