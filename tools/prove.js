#!/usr/bin/env node
/**
 * Generate a Groth16 proof for the gatekeeper circuit and print the public signals.
 * Usage: node tools/prove.js '<json inputs>' [outdir]
 */
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { WitnessCalculatorBuilder } = require("circom_runtime");

const WASM = process.env.GK_WASM || "/home/user9/agentgames/circuits/gatekeeper.wasm";
const ZKEY = process.env.GK_ZKEY || "/home/user9/agentgames/circuits/gatekeeper_final.zkey";

const DEFAULTS = {
  minimum: 1000,
  publicBalance: 1460,
  amount: 500,
  maxTransfer: 1000,
  expiryBlock: 8430000,
  currentBlock: 8420000,
  recipient: 1,
  conditionRecipient: 1,
  registeredVkHash: 9,
  proofVkHash: 9,
  decision: 1,
  taskId: 7,
  salt: 12345,
};

(async () => {
  const overrides = process.argv[2] ? JSON.parse(process.argv[2]) : {};
  const input = { ...DEFAULTS, ...overrides };
  const outDir = process.argv[3] || "/tmp/gk-proof";
  fs.mkdirSync(outDir, { recursive: true });

  const t0 = Date.now();
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(WASM));
  const witness = await wc.calculateWitness(input, true);
  const tWitness = Date.now();

  const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY, witness);
  const tProve = Date.now();

  const vKey = await snarkjs.zKey.exportVerificationKey(ZKEY);
  const ok = await snarkjs.groth16.verify(vKey, publicSignals, proof);

  fs.writeFileSync(path.join(outDir, "proof.json"), JSON.stringify(proof, null, 1));
  fs.writeFileSync(path.join(outDir, "public.json"), JSON.stringify(publicSignals, null, 1));
  fs.writeFileSync(path.join(outDir, "input.json"), JSON.stringify(input, null, 1));

  console.log(JSON.stringify({
    verified: ok,
    nPublic: vKey.nPublic,
    publicSignals,
    witnessMs: tWitness - t0,
    proveMs: tProve - tWitness,
    totalMs: Date.now() - t0,
    outDir,
  }));
  process.exit(ok ? 0 : 3);
})().catch((err) => {
  console.error("PROVE FAILED:", String(err.message || err).slice(0, 400));
  process.exit(2);
});
