import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { after, test } from "node:test";
import { ArtifactIntegrityError, assertArtifact } from "../src/prover/artifacts.js";
import { buildStarterInput, ProverInputError } from "../src/prover/inputs.js";
import { proofSize, prove, verify } from "../src/prover/prove.js";
import { circuitPaths, groth16RequiredPower, setupCircuit, terminateCurves, writeManifest } from "../src/prover/setup.js";
import { VerifierEngine } from "../src/verifier/index.js";

const workDir = resolve("build/test-prover");
const paths = circuitPaths("kyc_claims", resolve("build/circuit"));
const zkeyPath = resolve(workDir, "kyc_claims.zkey");
const verificationKeyPath = resolve(workDir, "verification_key.json");
let manifest;
let verificationKey;

await rm(workDir, { recursive: true, force: true });
const setup = await setupCircuit({ r1csPath: paths.r1csPath, zkeyPath, verificationKeyPath });
manifest = await writeManifest({
  manifestPath: resolve(workDir, "manifest.json"),
  circuit: "kyc_claims",
  protocol: "groth16",
  ...setup,
  ...paths,
  zkeyPath,
  verificationKeyPath,
});
verificationKey = JSON.parse(await readFile(verificationKeyPath, "utf8"));

after(async () => {
  await terminateCurves();
});

test("sizes the Powers of Tau like snarkjs newZKey", () => {
  assert.equal(groth16RequiredPower({ nConstraints: 18, nPubInputs: 0, nOutputs: 2 }), 12);
  assert.equal(groth16RequiredPower({ nConstraints: 4096, nPubInputs: 0, nOutputs: 0 }), 13);
  assert.equal(groth16RequiredPower({ nConstraints: 14000, nPubInputs: 8, nOutputs: 1 }), 14);
});

test("manifest records constraints, public signal order and artifact hashes", () => {
  assert.equal(manifest.constraints, 18);
  assert.deepEqual(manifest.publicSignals, ["isAdult", "isVerified"]);
  for (const name of ["r1cs", "wasm", "zkey", "verificationKey"]) {
    assert.match(manifest.artifacts[name].sha256, /^[0-9a-f]{64}$/);
    assert.ok(manifest.artifacts[name].bytes > 0);
  }
});

test("proves from file paths and the proof verifies", async () => {
  const result = await prove({ age: 30, kycVerified: 1 }, { wasm: paths.wasmPath, zkey: zkeyPath });
  assert.deepEqual(result.publicSignals, ["1", "1"]);
  assert.ok(result.timings.witnessMs >= 0 && result.timings.provingMs > 0);
  assert.equal(result.proofBytes.raw, 256);
  assert.equal((await verify(verificationKey, result.publicSignals, result.proof)).valid, true);
});

test("proves from in-memory artifacts, as the browser worker does", async () => {
  const wasm = new Uint8Array(await readFile(paths.wasmPath));
  const zkey = new Uint8Array(await readFile(zkeyPath));
  await assertArtifact("wasm", wasm, manifest.artifacts.wasm);
  await assertArtifact("zkey", zkey, manifest.artifacts.zkey);

  const first = await prove({ age: 17, kycVerified: 1 }, { wasm, zkey });
  const second = await prove({ age: 40, kycVerified: 0 }, { wasm, zkey });
  assert.deepEqual(first.publicSignals, ["0", "1"]);
  assert.deepEqual(second.publicSignals, ["1", "0"]);
  assert.equal((await verify(verificationKey, second.publicSignals, second.proof)).valid, true);
});

test("a proof does not verify against altered public signals", async () => {
  const { proof } = await prove({ age: 16, kycVerified: 1 }, { wasm: paths.wasmPath, zkey: zkeyPath });
  assert.equal((await verify(verificationKey, ["1", "1"], proof)).valid, false);
});

test("rejects artifacts whose hash differs from the manifest", async () => {
  const zkey = new Uint8Array(await readFile(zkeyPath));
  zkey[zkey.length - 1] ^= 0xff;
  await assert.rejects(assertArtifact("zkey", zkey, manifest.artifacts.zkey), ArtifactIntegrityError);
});

test("verifier start-up accepts the setup manifest and refuses a swapped key", async () => {
  const loaded = VerifierEngine.loadArtifacts({ verificationKeyPath, manifestPath: resolve(workDir, "manifest.json") });
  assert.equal(loaded.vkHash, manifest.artifacts.verificationKey.sha256);

  const swappedKeyPath = resolve(workDir, "swapped_verification_key.json");
  await writeFile(swappedKeyPath, JSON.stringify({ ...verificationKey, nPublic: verificationKey.nPublic + 1 }));
  assert.throws(
    () => VerifierEngine.loadArtifacts({ verificationKeyPath: swappedKeyPath, manifestPath: resolve(workDir, "manifest.json") }),
    /hash mismatch/,
  );
});

test("measures proof size in raw and JSON form", () => {
  const groth16 = {
    pi_a: ["1", "2", "1"],
    pi_b: [["1", "2"], ["3", "4"], ["1", "0"]],
    pi_c: ["5", "6", "1"],
    protocol: "groth16",
    curve: "bn128",
  };
  assert.equal(proofSize(groth16).raw, 256);
  assert.ok(proofSize(groth16).json > 0);
});

test("starter input builder gives readable errors", () => {
  assert.deepEqual(buildStarterInput({ age: "21", kycVerified: true }), { age: 21, kycVerified: 1 });
  assert.throws(() => buildStarterInput({ age: 300, kycVerified: 1 }), (error) => error instanceof ProverInputError && error.code === "AGE_OUT_OF_RANGE");
  assert.throws(() => buildStarterInput({ age: 20.5, kycVerified: 1 }), { code: "AGE_OUT_OF_RANGE" });
  assert.throws(() => buildStarterInput({ age: 20, kycVerified: "yes" }), { code: "INVALID_KYC_FLAG" });
});
