// Builds a valid kyc_presentation witness input from the real credential,
// revocation and input-builder modules, so benchmarks measure the circuit the
// demo actually proves.
import {
  createHolderCommitment,
  generateIssuerKeyPair,
  issueCredential,
} from "../../src/credential/presentation-credential.mjs";
import { buildPresentationInput, toDateInt } from "../../src/prover/inputs.js";
import { RevocationRegistry } from "../../src/verifier/revocation.js";

export async function samplePresentationInput({ revocationDepth = 16, activeCredentials = 100 } = {}) {
  const issuer = await generateIssuerKeyPair();
  const holderSecret = "31337";
  const currentDate = toDateInt(new Date());
  const credential = await issueCredential({
    credentialId: "42",
    dob: 20000615,
    expiry: currentDate + 100000,
    holderCommitment: await createHolderCommitment(holderSecret),
    issuedAt: currentDate,
    issuerPrivateKey: issuer.privateKey,
  });

  const registry = await new RevocationRegistry(revocationDepth).init();
  for (let i = 1; i < activeCredentials; i += 1) registry.register(String(1000 + i));
  registry.register(credential.attributes.credentialId);

  return buildPresentationInput(credential, {
    holderSecret,
    revocationPath: registry.getMembershipPath(credential.attributes.credentialId),
    request: {
      spId: "123456789",
      challenge: "987654321",
      currentDate,
      minAgeOffset: 180000,
      trustedIssuer: issuer.publicKey,
      acceptedRevocationRoots: [registry.getRoot()],
    },
  });
}

export async function defaultBenchInput(circuit) {
  if (circuit === "kyc_claims") return { age: 21, kycVerified: 1 };
  if (circuit === "kyc_presentation") return samplePresentationInput();
  return undefined;
}
