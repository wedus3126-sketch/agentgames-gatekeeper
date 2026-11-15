#!/usr/bin/env node
/**
 * Groth16 prover for the Agent Games gatekeeper circuit.
 *
 * Reads a JSON job on stdin:
 *   { "task_id": "gk_1", "decision": 0|1, "minimum": "...", "public_balance": "...",
 *     "amount": "...", "max_transfer": "...", "expiry_block": n, "current_block": n,
 *     "recipient": "0x..", "condition_recipient": "0x..",
 *     "registered_vk": "0x..", "proof_vk": "0x..", "salt_seed": "<hex>" }
 *
 * Writes {"proof": {...}, "public_signals": [...], "inputs": {...}} on stdout.
 * Field mapping: 32-byte hex -> integer mod BN254 p; taskId/salt derived
 * deterministically so a redelivered task reproduces the same proof.
 */
const fs = require("fs");
const crypto = require("crypto");
const snarkjs = require("snarkjs");

const WASM = process.env.GK_WASM || "/opt/agentgames/circuits/gatekeeper.wasm";
const ZKEY = process.env.GK_ZKEY || "/opt/agentgames/circuits/gatekeeper_final.zkey";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const modP = (v) => {
  let x;
  if (typeof v === "bigint") x = v;
  else if (typeof v === "number") x = BigInt(Math.trunc(v));
  else {
    const s = String(v ?? "0").trim();
    x = s.startsWith("0x") || s.startsWith("0X") ? BigInt(s) : BigInt(s === "" ? 0 : /^-?\d+$/.test(s) ? s : "0");
  }
  const r = x % P;
  return (r < 0n ? r + P : r).toString();
};

const shaInt = (text) => modP(BigInt("0x" + crypto.createHash("sha256").update(text).digest("hex")));

function readStdin() {
  return new Promise((resolve, reject) => {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => (buf += d));
    process.stdin.on("end", () => resolve(buf));
    process.stdin.on("error", reject);
  });
}

(async () => {
  const job = JSON.parse(await readStdin());
  const taskId = job.task_id ?? "";

  const input = {
    decision: job.decision ? "1" : "0",
    minimum: modP(job.minimum),
    publicBalance: modP(job.public_balance),
    amount: modP(job.amount),
    maxTransfer: modP(job.max_transfer),
    expiryBlock: modP(job.expiry_block),
    currentBlock: modP(job.current_block),
    recipient: modP(job.recipient),
    conditionRecipient: modP(job.condition_recipient),
    registeredVkHash: modP(job.registered_vk),
    proofVkHash: modP(job.proof_vk),
    taskId: shaInt("taskId:" + taskId),
    salt: modP(BigInt("0x" + (job.salt_seed || crypto.createHash("sha256").update("salt:" + taskId).digest("hex")))),
  };

  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ms = Date.now() - t0;
  process.stdout.write(JSON.stringify({ proof, public_signals: publicSignals, inputs: input, proveMs: ms }));
})().catch((err) => {
  process.stderr.write("PROVE_FAILED " + String(err && err.message ? err.message : err).slice(0, 300));
  process.exit(2);
});
