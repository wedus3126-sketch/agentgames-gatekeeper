# Agent Games — Proof Gatekeeper agent

Deterministic gatekeeper agent for the zkVerify **Agent Games** Proof Gatekeeper event.
It receives HMAC-signed task envelopes, decides `APPROVE` / `REJECT`, and signs its answer.

## Why this design

A valid proof is not the same as a valid authorization. This agent approves only when
every field agrees — key, circuit, proof system, public inputs, replay state and
finalization — and rejects on any uncertainty, missing evidence, timeout or stale task.

## Endpoint contract

`POST /agent` — JSON body, `x-agent-games-signature: sha256=<hex hmac>` over the **raw**
body using `AGENT_HMAC_SECRET`. The response is signed the same way over the response
body using `AGENT_RESPONSE_SECRET`.

`GET /health` — liveness probe used by the platform health check.

## Decision rules

| Rule | Reject reason |
|---|---|
| Task HMAC valid | `INVALID_TASK_SIGNATURE` (401) |
| Timestamp within `AGENT_CLOCK_SKEW` | `STALE_TIMESTAMP` / `MISSING_TIMESTAMP` |
| vk_hash equals registered condition key | `VK_MISMATCH` |
| Proof system `groth16`, curve `bn128`, expected circuit | `PROOF_SYSTEM_MISMATCH`, `CURVE_MISMATCH`, `CIRCUIT_MISMATCH` |
| Public input amount >= threshold | `THRESHOLD_MISMATCH` |
| Public input recipient equals requested recipient | `RECIPIENT_MISMATCH` |
| Public input action equals requested action | `ACTION_MISMATCH` |
| Proof reference unused | `REPLAYED_PROOF` |
| Verification `finalized` | `NOT_FINALIZED` |
| Answer inside the 55s budget | `DEADLINE_EXCEEDED` |

Approve only when no reason fired: `{"decision":"APPROVE","reasons":["VALID_CONDITION"]}`.

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export AGENT_HMAC_SECRET='<platform-issued secret>'
export AGENT_RESPONSE_SECRET='<platform-issued secret>'
uvicorn agent:app --host 0.0.0.0 --port 8080
```

Then register the public HTTPS URL (for example `https://<host>/agent`) as the agent
endpoint and run the unscored practice tasks before entering the scored round.

## Circuit artifacts (zkVerify mainnet)

- gatekeeper — `vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  - `https://agentgames.zkverify.io/circuits/gatekeeper.wasm`
  - `https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey`
- vfy-policy — `vkHash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`

## Secrets

Never commit `.env`. The HMAC secrets come from the platform (Rotate Secret) — a local
placeholder means every task is rejected as `INVALID_TASK_SIGNATURE`.
