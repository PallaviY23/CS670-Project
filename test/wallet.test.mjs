import assert from "node:assert/strict";
import { test } from "node:test";
import { BN254_SCALAR_FIELD } from "../src/prover/inputs.js";
import { open, seal, WalletLockedError } from "../src/wallet/secret-box.js";
import { memoryStorage } from "../src/wallet/storage.js";
import { createWallet, generateHolderSecret, WalletError } from "../src/wallet/wallet.js";

const iterations = 1_000; // production default is 600k; kept low so tests stay fast
const credential = {
  issuer: { Ax: "1", Ay: "2" },
  attributes: { credentialId: "42", dob: 20000615, kycStatus: 1, expiry: 20301231 },
  salts: {},
  root: "3",
  signature: { R8x: "4", R8y: "5", S: "6" },
};

test("secret box round-trips and rejects a wrong passphrase", async () => {
  const box = await seal("top secret", "correct horse battery", { iterations });
  assert.equal(box.kdf, "PBKDF2-SHA256");
  assert.ok(!JSON.stringify(box).includes("top secret"));
  assert.equal(await open(box, "correct horse battery"), "top secret");
  await assert.rejects(open(box, "wrong passphrase"), WalletLockedError);
});

test("secret box detects tampered ciphertext", async () => {
  const box = await seal("top secret", "correct horse battery", { iterations });
  const bytes = Uint8Array.from(atob(box.ciphertext), (char) => char.charCodeAt(0));
  bytes[0] ^= 1;
  await assert.rejects(open({ ...box, ciphertext: btoa(String.fromCharCode(...bytes)) }, "correct horse battery"), WalletLockedError);
});

test("holder secrets are distinct non-zero field elements", () => {
  const secrets = new Set();
  for (let i = 0; i < 200; i += 1) {
    const secret = generateHolderSecret();
    assert.ok(secret > 0n && secret < BN254_SCALAR_FIELD);
    secrets.add(secret);
  }
  assert.equal(secrets.size, 200);
});

test("wallet stores the holder secret only in encrypted form", async () => {
  const storage = memoryStorage();
  const wallet = createWallet({ storage, verifyCredential: async () => true, iterations });
  await assert.rejects(wallet.initialise("short"), { code: "WEAK_PASSPHRASE" });
  await wallet.initialise("a long passphrase");
  await assert.rejects(wallet.initialise("a long passphrase"), { code: "ALREADY_INITIALISED" });

  const secret = await wallet.unlock("a long passphrase");
  assert.ok(secret > 0n && secret < BN254_SCALAR_FIELD);
  assert.ok(!JSON.stringify(await storage.get("holder-secret")).includes(secret.toString()));
  await assert.rejects(wallet.unlock("not the passphrase"), WalletLockedError);

  await wallet.changePassphrase("a long passphrase", "another long passphrase");
  assert.equal(await wallet.unlock("another long passphrase"), secret);
});

test("wallet imports only credentials that pass the issuer check", async () => {
  const unverified = createWallet({ storage: memoryStorage(), iterations });
  await assert.rejects(unverified.importCredential(credential), { code: "NO_VERIFIER" });

  const rejecting = createWallet({ storage: memoryStorage(), verifyCredential: async () => false, iterations });
  await assert.rejects(rejecting.importCredential(credential), (error) => error instanceof WalletError && error.code === "INVALID_CREDENTIAL");
  await assert.rejects(rejecting.importCredential("{not json"), { code: "INVALID_CREDENTIAL" });

  const wallet = createWallet({ storage: memoryStorage(), verifyCredential: async (c) => c.root === "3", iterations });
  const id = await wallet.importCredential(JSON.stringify(credential));
  assert.equal(id, "42");

  const [summary] = await wallet.listCredentials();
  assert.equal(summary.id, "42");
  assert.equal(summary.dob, undefined);
  assert.deepEqual(JSON.parse(await wallet.exportCredential("42")), credential);

  await wallet.removeCredential("42");
  assert.deepEqual(await wallet.listCredentials(), []);
  await assert.rejects(wallet.getCredential("42"), { code: "NOT_FOUND" });
});
