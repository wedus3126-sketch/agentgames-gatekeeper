# Agent Games — Proof Gatekeeper agent (protocol v1, with Groth16 proofs)

Deterministic gatekeeper agent for the zkVerify **Agent Games** Proof Gatekeeper event.
The platform POSTs HMAC-signed task envelopes; this agent decides `APPROVE` / `REJECT`,
proves the decision with the official Groth16 circuit, and signs its answer.

Spec: <https://agentgames.zkverify.io/build>

## Contract

`POST /agent` — signed JSON. `x-agent-games-signature` carries the **lowercase hex**
HMAC-SHA256 of the raw body (the platform sends it without a `sha256=` prefix; responses
use the same format). Secret: `AGENT_GAMES_HMAC_SECRET`, issued once by *Rotate Secret*.

`GET /health` — liveness plus `proverEnabled`.

### Preflight

```
in : {"type":"agent-games.preflight.v1","agent_id":"agt_...","issued_at":"...","nonce":"..."}
out: {"ok":true,"protocolVersion":"v1"}      # signed
```

### Task → response

```
in : {"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_...","issued_at":"...",
      "input":{"registered_vk","proof_vk","minimum","public_balance","expiry_block",
               "current_block","recipient","condition_recipient","amount",
               "max_transfer","proof_tx"}}
out: {"decision","reason_code","proof_tx","proof","public_signals","task_id"}
```

## Decision rules (deterministic, fail-closed)

Order matters; the first failure wins.

| # | Check | reason_code | proof |
|---|---|---|---|
| 1 | inbound HMAC over raw body | `401 invalid_signature` | — |
| 2 | `issued_at` within `AGENT_CLOCK_SKEW` (180s) | `STALE_TASK` | no |
| 3 | `proof_tx` present | `MISSING_PROOF_TX` | no |
| 4 | `proof_tx` never seen before | `REPLAYED_PROOF` | no |
| 5 | `registered_vk == proof_vk` | `VK_SUBSTITUTION` | yes |
| 6 | `public_balance >= minimum` | `THRESHOLD_MISMATCH` | yes |
| 7 | `current_block < expiry_block` | `EXPIRED_CONDITION` | yes |
| 8 | `recipient == condition_recipient` | `RECIPIENT_MISMATCH` | yes |
| 9 | `0 < amount <= max_transfer` | `INVALID_AMOUNT`, `AMOUNT_EXCEEDS_MAX` | yes |
| 10 | all of the above | `APPROVE` / `VALID_CONDITION` | yes |

Replay and staleness are rejected *outside* the circuit, so those responses carry no proof —
the circuit constrains `decision` to equal the conjunction of the payment conditions and
would reject a witness that approves a replay.

## Groth16 proofs

The published circuit is `GatekeeperEvaluation` (Circom 2.x, Groth16/BN254). Its input
signals are not documented; they were recovered by probing the published WASM
(`tools/probe_sizes.js`) — `getInputSignalSize` returns ≥ 1 only for real inputs:

| signal | source |
|---|---|
| `decision` | 1 = approve, 0 = reject |
| `minimum`, `publicBalance`, `amount`, `maxTransfer` | task input, decimal → field element |
| `expiryBlock`, `currentBlock` | task input |
| `recipient`, `conditionRecipient` | 20-byte address → integer mod p |
| `registeredVkHash`, `proofVkHash` | 32-byte vk hash → integer mod p |
| `taskId` | `sha256("taskId:" + task_id) mod p` |
| `salt` (private) | `HMAC(secret, "gatekeeper-salt:" + task_id) mod p` |

`salt` and `taskId` are derived deterministically, so a redelivered task reproduces the
same witness instead of a fresh one.

Proving runs through the **snarkjs CLI** (`wtns calculate` → `groth16 prove`); the JS API
path stalls in this environment. Measured: ~0.25s witness, ~0.55s prove, ~2.6–3.2s
round-trip end to end on a t3.micro, well inside the 60s deadline.

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
npm install                      # snarkjs
curl -O https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -O https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
export AGENT_GAMES_HMAC_SECRET='<from Rotate Secret>'
export GK_WASM=$PWD/gatekeeper.wasm GK_ZKEY=$PWD/gatekeeper_final.zkey
export AGENT_SNARKJS=$PWD/node_modules/.bin/snarkjs
uvicorn agent:app --host 0.0.0.0 --port 8080
```

Deployed entry: Amazon Linux 2023 EC2 (ap-southeast-2), systemd unit
`agentgames-gatekeeper` on `127.0.0.1:8080`, Caddy terminating TLS in front.

## Tests

```bash
# decision paths, each proof re-verified with snarkjs against the extracted vk
AGENT_GAMES_HMAC_SECRET=test-secret .venv/bin/python tests/test_with_proofs.py
```

Covers preflight, approve, every trap class, replay, stale task and a tampered signature,
and asserts every attached proof verifies.

## Circuit reference (zkVerify mainnet)

| circuit | vk_hash |
|---|---|
| gatekeeper | `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` |
| vfy-policy | `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047` |

## Secrets

`.env` is git-ignored; only `.env.example` ships. A placeholder secret fails preflight
with a signature error.
