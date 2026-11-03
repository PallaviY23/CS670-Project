// End-to-end: issue -> wallet -> buildPresentationInput -> Groth16 proof ->
// VerifierEngine with the real verification key. Unlike verifier_attacks
// (dummy key), every case here goes through real Groth16 verification.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { after, before, test } from "node:test";
import { runCircom } from "../scripts/circom.mjs";
import {
  createHolderCommitment,
  generateIssuerKeyPair,
  issueCredential,
} from "../src/credential/presentation-credential.mjs";
import { buildPresentationInput, toDateInt } from "../src/prover/inputs.js";
import { prove } from "../src/prover/prove.js";
import { circuitPaths, setupCircuit, terminateCurves } from "../src/prover/setup.js";
import { AuditLog, ChallengeStore, VerifierEngine } from "../src/verifier/index.js";
import { RevocationRegistry } from "../src/verifier/revocation.js";
import { createWallet, generateHolderSecret } from "../src/wallet/wallet.js";
import { memoryStorage } from "../src/wallet/storage.js";
import { verifyCredential } from "../src/credential/presentation-credential.mjs";

const SP_ID = "123456789";
const DOB = 20000615;
const workDir = resolve("build/test-e2e");
const paths = circuitPaths("kyc_presentation", workDir);
const today = toDateInt(new Date());

let issuer;
let wallet;
let credential;
let holderSecret;
let registry;
let challengeStore;
let engine;
let verificationKey;
let zkeyPath;

const mtime = (file) => (existsSync(file) ? statSync(file).mtimeMs : 0);
const newestCircuitSource = () => Math.max(
  ...["circuits", "circuits/lib"].flatMap((dir) => readdirSync(dir)
    .filter((name) => name.endsWith(".circom"))
    .map((name) => mtime(resolve(dir, name)))),
);

// Reuses the compiled circuit and keys while they are newer than their inputs.
// A rebuild starts from an empty folder: circom2 (WASI) on Windows can hang
// when overwriting a previous build.
async function ensureKeys(dir) {
  const zkey = resolve(dir, "kyc_presentation.zkey");
  const vkey = resolve(dir, "verification_key.json");
  if (mtime(zkey) <= mtime(paths.r1csPath) || !existsSync(vkey)) {
    await setupCircuit({ r1csPath: paths.r1csPath, zkeyPath: zkey, verificationKeyPath: vkey });
  }
  return { zkey, vkey };
}

before(async () => {
  if (mtime(paths.wasmPath) <= newestCircuitSource() || mtime(paths.r1csPath) <= newestCircuitSource()) {
    rmSync(workDir, { recursive: true, force: true });
    mkdirSync(workDir, { recursive: true });
    runCircom("kyc_presentation.circom --r1cs --wasm --O2 -l ../node_modules -l . -o ../build/test-e2e", {
      cwd: resolve("circuits"),
    });
  }
  const keys = await ensureKeys(workDir);
  zkeyPath = keys.zkey;
  const verificationKeyPath = keys.vkey;
  verificationKey = JSON.parse(readFileSync(verificationKeyPath, "utf8"));

  issuer = await generateIssuerKeyPair();
  wallet = createWallet({
    storage: memoryStorage(),
    verifyCredential: (candidate) => verifyCredential(candidate, issuer.publicKey),
    iterations: 1000,
  });
  await wallet.initialise("correct horse battery");
  holderSecret = (await wallet.unlock("correct horse battery")).toString();

  credential = await issueCredential({
    credentialId: "4242",
    dob: DOB,
    expiry: today + 50000,
    holderCommitment: await createHolderCommitment(holderSecret),
    issuedAt: today,
    issuerPrivateKey: issuer.privateKey,
  });
  await wallet.importCredential(credential);

  registry = await new RevocationRegistry(16).init();
  for (const id of ["1001", "1002", "1003"]) registry.register(id);
  registry.register(credential.attributes.credentialId);

  challengeStore = new ChallengeStore();
  engine = new VerifierEngine({
    verificationKey,
    spId: SP_ID,
    trustedIssuerKey: { ax: issuer.publicKey.Ax, ay: issuer.publicKey.Ay },
    challengeStore,
    auditLog: new AuditLog(),
    revocationRegistry: registry,
  });
});

after(async () => {
  await terminateCurves();
});

function newRequest() {
  return challengeStore.issue({
    spId: SP_ID,
    currentDate: today,
    minAgeOffset: 180000,
    trustedIssuer: engine.trustedIssuerKey,
    acceptedRevocationRoots: [registry.getRoot()],
  });
}

async function present(request, { secret = holderSecret } = {}) {
  const stored = await wallet.getCredential((await wallet.listCredentials())[0].id);
  const input = buildPresentationInput(stored, {
    holderSecret: secret,
    request,
    revocationPath: registry.getMembershipPath(stored.attributes.credentialId),
  });
  const { proof, publicSignals } = await prove(input, { wasm: paths.wasmPath, zkey: zkeyPath });
  // Exactly what the browser POSTs to /api/sp/verify.
  return { requestId: request.requestId, proof, publicSignals };
}

const verifyAt = (presentation) => engine.verifyPresentation(presentation, { requestId: presentation.requestId });

test("valid presentation is accepted and reveals no private attribute", async () => {
  const presentation = await present(newRequest());
  const result = await verifyAt(presentation);
  assert.equal(result.accepted, true, result.reason);
  assert.match(result.nullifier, /^\d+$/);

  const sent = JSON.stringify(presentation);
  const privateValues = [
    String(DOB), "2000-06-15", holderSecret,
    String(credential.attributes.credentialId),
    String(credential.attributes.holderCommitment),
    ...Object.values(credential.salts).map(String),
    credential.root,
  ];
  for (const value of privateValues) {
    assert.equal(sent.includes(value), false, `presentation leaks ${value}`);
  }
  assert.equal(presentation.publicSignals.length, 8);
});

test("replaying an accepted presentation is rejected", async () => {
  const presentation = await present(newRequest());
  assert.equal((await verifyAt(presentation)).accepted, true);
  const replay = await verifyAt(presentation);
  assert.equal(replay.accepted, false);
  assert.equal(replay.code, "CHALLENGE_ALREADY_USED");
});

test("nullifier is stable for the same service provider", async () => {
  const first = await verifyAt(await present(newRequest()));
  const second = await verifyAt(await present(newRequest()));
  assert.equal(first.nullifier, second.nullifier);
});

test("tampered public signal or proof fails Groth16 verification and keeps the challenge", async () => {
  const request = newRequest();
  const presentation = await present(request);

  const otherNullifier = { ...presentation, publicSignals: ["1", ...presentation.publicSignals.slice(1)] };
  const tamperedSignal = await verifyAt(otherNullifier);
  assert.equal(tamperedSignal.accepted, false);
  assert.equal(tamperedSignal.code, "INVALID_PROOF");

  const swappedProof = { ...presentation, proof: { ...presentation.proof, pi_a: presentation.proof.pi_c, pi_c: presentation.proof.pi_a } };
  assert.equal((await verifyAt(swappedProof)).accepted, false);

  // A rejected attempt must not burn the user's challenge.
  assert.equal((await verifyAt(presentation)).accepted, true);
});

test("proof is rejected under a verification key from a different setup", async () => {
  const otherDir = resolve(workDir, "other-setup");
  mkdirSync(otherDir, { recursive: true });
  const { vkey: otherVkPath } = await ensureKeys(otherDir);

  const otherEngine = new VerifierEngine({
    ...engine,
    verificationKey: JSON.parse(readFileSync(otherVkPath, "utf8")),
  });
  const presentation = await present(newRequest());
  const result = await otherEngine.verifyPresentation(presentation, { requestId: presentation.requestId });
  assert.equal(result.accepted, false);
  assert.equal(result.code, "INVALID_PROOF");
});

test("wrong holder secret cannot produce a proof", async () => {
  await assert.rejects(present(newRequest(), { secret: generateHolderSecret().toString() }));
});

test("revoked credential: old-root proof rejected, no new proof possible", async () => {
  const before = newRequest();
  const stalePresentation = await present(before);
  registry.revoke(credential.attributes.credentialId);

  const stale = await verifyAt(stalePresentation);
  assert.equal(stale.accepted, false);
  assert.equal(stale.code, "REVOCATION_ROOT_REJECTED");

  assert.throws(() => registry.getMembershipPath(credential.attributes.credentialId), /revoked/);
});
