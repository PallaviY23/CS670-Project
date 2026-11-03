import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  createHolderCommitment,
  generateIssuerKeyPair,
  issueCredential,
  openCredentialSlot,
  verifyCredential,
} from "../src/credential/presentation-credential.mjs";
import { buildPresentationInput } from "../src/prover/inputs.js";
import { terminateCurves } from "../src/prover/setup.js";
import { RevocationRegistry } from "../src/verifier/revocation.js";
import { loadCircuit } from "./helpers/circuit.mjs";

after(async () => {
  await terminateCurves();
});

test("issued credentials verify under their issuer and reject tampering", async () => {
  const issuer = await generateIssuerKeyPair();
  const holderCommitment = await createHolderCommitment("31337");
  const credential = await issueCredential({
    credentialId: "42",
    dob: 20000615,
    expiry: 20301231,
    holderCommitment,
    issuedAt: 20261103,
    issuerPrivateKey: issuer.privateKey,
  });

  assert.equal(await verifyCredential(credential, issuer.publicKey), true);
  assert.equal(await verifyCredential(credential, (await generateIssuerKeyPair()).publicKey), false);
  assert.equal(await verifyCredential({
    ...credential,
    attributes: { ...credential.attributes, dob: "20000616" },
  }, issuer.publicKey), false);

  const opening = await openCredentialSlot(credential, "dob");
  assert.equal(opening.siblings.length, 3);
  assert.equal(opening.pathIndices.length, 3);
});

test("issued credential and revocation path satisfy the presentation circuit", async () => {
  const issuer = await generateIssuerKeyPair();
  const holderSecret = "31337";
  const credential = await issueCredential({
    credentialId: "42",
    dob: 20000615,
    expiry: 20301231,
    holderCommitment: await createHolderCommitment(holderSecret),
    issuedAt: 20261103,
    issuerPrivateKey: issuer.privateKey,
  });
  const registry = await new RevocationRegistry(16).init();
  registry.register(credential.attributes.credentialId);
  const request = {
    spId: "7",
    challenge: "123456789",
    currentDate: 20261103,
    minAgeOffset: 180000,
    trustedIssuer: issuer.publicKey,
    acceptedRevocationRoots: [registry.getRoot()],
  };
  const input = buildPresentationInput(credential, {
    holderSecret,
    request,
    revocationPath: registry.getMembershipPath(credential.attributes.credentialId),
  });

  assert.equal(input.otherLeaves.length, 3);
  assert.equal(input.revSiblings.length, 16);
  assert.deepEqual(Object.keys(input).sort(), [
    "challenge", "currentDate", "credentialId", "dob", "expiry", "holderSecret",
    "issuerAx", "issuerAy", "kycStatus", "minAgeOffset", "otherLeaves",
    "revPathIndices", "revSiblings", "revocationRoot", "salts", "sigR8x",
    "sigR8y", "sigS", "spId",
  ].sort());

  const circuit = await loadCircuit("circuits/kyc_presentation.circom");
  await assert.doesNotReject(circuit.witness(input));
});
