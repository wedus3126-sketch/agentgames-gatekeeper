#!/usr/bin/env node
/**
 * Enumerate circuit inputs by signal-size probe: getInputSignalSize() returns
 * >= 1 only for real inputs, so this is value-independent (no assertions run).
 */
const fs = require("fs");
const { WitnessCalculatorBuilder } = require("circom_runtime");

const WASM = process.argv[2] || "/home/user9/agentgames/circuits/gatekeeper.wasm";
const WORDS = process.argv[3] ? fs.readFileSync(process.argv[3], "utf8").split(/\s+/).filter(Boolean) : [];

function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str[i].charCodeAt(0));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  return ("0".repeat(16) + hash.toString(16)).slice(-16);
}

(async () => {
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(WASM));
  const ex = wc.instance.exports;
  const found = [];
  for (const name of WORDS) {
    const h = fnvHash(name);
    const hMSB = parseInt(h.slice(0, 8), 16);
    const hLSB = parseInt(h.slice(8, 16), 16);
    let size = 0;
    try { size = ex.getInputSignalSize(hMSB, hLSB); } catch (_) { size = 0; }
    if (size >= 1) found.push(`${name}:${size}`);
  }
  console.log("INPUTS FOUND:", found.join(", ") || "none");
  console.log("count:", found.length, "| witnessSize:", ex.getWitnessSize());
})();
