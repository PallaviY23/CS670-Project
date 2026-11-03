import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createPresentation,
  generateIssuerKeyPair,
  issueCredential,
  verifyPresentation,
} from "../src/credential/credential.mjs";

const issuedAt = 1_800_000_000;
const issuer = await generateIssuerKeyPair();
const otherIssuer = await generateIssuerKeyPair();
const credential = await issueCredential({
  claims: { age: 27, kycVerified: true },
  issuerId: "cs670-kyc-authority",
  issuerPrivateKey: issuer.privateKey,
  issuedAt,
  expiresAt: issuedAt + 3_600,
});

test("creates a selective KYC presentation without disclosing age", async () => {
  const presentation = await createPresentation(credential, ["kycVerified"]);
  const result = await verifyPresentation(presentation, issuer.publicKey, { now: issuedAt + 1 });

  assert.equal(result.valid, true);
  assert.deepEqual(result.claims, { kycVerified: true });
  assert.equal(Object.hasOwn(presentation.disclosed, "age"), false);
  assert.equal(Object.hasOwn(presentation, "privateAttributes"), false);
});

test("verifies selectively disclosed age against the issuer commitment", async () => {
  const presentation = await createPresentation(credential, ["age"]);
  const result = await verifyPresentation(presentation, issuer.publicKey, { now: issuedAt + 1 });

  assert.deepEqual(result, {
    valid: true,
    issuerId: "cs670-kyc-authority",
    claims: { age: 27 },
  });
  assert.equal(Object.hasOwn(presentation.disclosed, "kycVerified"), false);
});

test("rejects a modified disclosed value", async () => {
  const presentation = await createPresentation(credential, ["age"]);
  presentation.disclosed.age.value = 28;

  const result = await verifyPresentation(presentation, issuer.publicKey, { now: issuedAt + 1 });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "attribute-not-in-credential");
});

test("rejects a different trusted issuer key", async () => {
  const presentation = await createPresentation(credential, ["kycVerified"]);
  const result = await verifyPresentation(presentation, otherIssuer.publicKey, { now: issuedAt + 1 });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "untrusted-issuer");
});

test("rejects an expired credential", async () => {
  const presentation = await createPresentation(credential, ["kycVerified"]);
  const result = await verifyPresentation(presentation, issuer.publicKey, { now: issuedAt + 3_600 });

  assert.equal(result.valid, false);
  assert.equal(result.reason, "credential-expired");
});

test("rejects a modified issuer signature", async () => {
  const presentation = await createPresentation(credential, ["kycVerified"]);
  presentation.signature.S = "0";

  const result = await verifyPresentation(presentation, issuer.publicKey, { now: issuedAt + 1 });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "invalid-issuer-signature");
});