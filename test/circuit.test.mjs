import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import * as snarkjs from "snarkjs";

const wasmPath = "build/circuit/kyc_claims_js/kyc_claims.wasm";
const r1csPath = "build/circuit/kyc_claims.r1cs";

async function calculateWitness(input) {
  const witnessPath = "build/circuit/test.wtns";
  await snarkjs.wtns.calculate(input, wasmPath, witnessPath);
  return snarkjs.wtns.exportJson(witnessPath);
}

test("builds and accepts a valid in-range witness", async () => {
  const witness = await calculateWitness({ age: 21, kycVerified: 1 });
  assert.equal(witness[1], 1n);
  assert.equal(witness[2], 1n);
  assert.equal(await readFile(r1csPath).then((contents) => contents.length > 0), true);
});

test("reports false for an underage witness", async () => {
  const witness = await calculateWitness({ age: 17, kycVerified: 1 });
  assert.equal(witness[1], 0n);
  assert.equal(witness[2], 1n);
});

test("rejects an age outside the circuit's 8-bit range", async () => {
  await assert.rejects(calculateWitness({ age: 256, kycVerified: 1 }));
});

test("rejects a KYC flag that is not boolean", async () => {
  await assert.rejects(calculateWitness({ age: 21, kycVerified: 2 }));
});