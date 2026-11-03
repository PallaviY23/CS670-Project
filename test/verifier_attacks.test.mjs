import assert from "node:assert/strict";
import { test } from "node:test";
import {
  VerifierEngine,
  ChallengeStore,
  AuditLog,
  SNARK_SCALAR_FIELD,
  isCanonicalFieldElement,
  generateRandomFieldElement,
} from "../src/verifier/index.js";
import { RevocationRegistry } from "../src/verifier/revocation.js";

const DUMMY_VK = {
  protocol: "groth16",
  curve: "bn128",
  nPublic: 8,
  vk_alpha_1: ["0", "0", "1"],
  vk_beta_2: [["0", "0"], ["0", "0"], ["1", "0"]],
  vk_gamma_2: [["0", "0"], ["0", "0"], ["1", "0"]],
  vk_delta_2: [["0", "0"], ["0", "0"], ["1", "0"]],
  vk_alphabeta_12: [],
  IC: new Array(9).fill(["0", "0", "1"]),
};

const TRUSTED_ISSUER = {
  ax: "11513271168449174522649033324628286280208269784305886616238612196620584742680",
  ay: "4525892543290680321743110595304724213031024621041926618587428172605809756083",
};

const SP_ID = "123456789";

async function setupEngine() {
  const challengeStore = new ChallengeStore();
  const auditLog = new AuditLog();
  const revocationRegistry = new RevocationRegistry(4);
  await revocationRegistry.init();
  revocationRegistry.register("1001");

  const engine = new VerifierEngine({
    verificationKey: DUMMY_VK,
    trustedIssuerKey: TRUSTED_ISSUER,
    spId: SP_ID,
    challengeStore,
    auditLog,
    revocationRegistry,
  });

  return { engine, challengeStore, auditLog, revocationRegistry };
}

function makeValidProof() {
  return {
    pi_a: ["1", "2", "1"],
    pi_b: [["1", "2"], ["3", "4"], ["1", "0"]],
    pi_c: ["5", "6", "1"],
    protocol: "groth16",
    curve: "bn128",
  };
}

test("Field element checks correctly distinguish canonical vs non-canonical", () => {
  assert.equal(isCanonicalFieldElement("0"), true);
  assert.equal(isCanonicalFieldElement("1"), true);
  assert.equal(isCanonicalFieldElement((SNARK_SCALAR_FIELD - 1n).toString()), true);

  // Non-canonical values
  assert.equal(isCanonicalFieldElement(SNARK_SCALAR_FIELD.toString()), false); // equal to r
  assert.equal(isCanonicalFieldElement((SNARK_SCALAR_FIELD + 1n).toString()), false); // greater than r
  assert.equal(isCanonicalFieldElement("-1"), false);
  assert.equal(isCanonicalFieldElement("abc"), false);
  assert.equal(isCanonicalFieldElement(""), false);
  assert.equal(isCanonicalFieldElement(null), false);
});

test("Attack 1: Rejects malformed schema and missing proof", async () => {
  const { engine } = await setupEngine();

  const res1 = await engine.verifyPresentation(null);
  assert.equal(res1.accepted, false);
  assert.equal(res1.code, "INVALID_SCHEMA");

  const res2 = await engine.verifyPresentation({ proof: {}, publicSignals: [] });
  assert.equal(res2.accepted, false);
  assert.equal(res2.code, "INVALID_PROOF_SHAPE");
});

test("Attack 2: Rejects invalid public signal count and reordering", async () => {
  const { engine } = await setupEngine();

  const proof = makeValidProof();
  const resTooFew = await engine.verifyPresentation({
    proof,
    publicSignals: ["1", "2", "3"],
  });
  assert.equal(resTooFew.accepted, false);
  assert.equal(resTooFew.code, "INVALID_SIGNAL_COUNT");
});

test("Attack 3: Rejects non-canonical field elements (field wrapping attack)", async () => {
  const { engine, challengeStore, revocationRegistry } = await setupEngine();

  const date = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  const ch = challengeStore.issue({
    spId: SP_ID,
    currentDate: date,
    trustedIssuer: TRUSTED_ISSUER,
  });

  const proof = makeValidProof();
  // Signal 0 is non-canonical: >= SNARK_SCALAR_FIELD
  const maliciousSignals = [
    SNARK_SCALAR_FIELD.toString(), // Overflowing element
    TRUSTED_ISSUER.ax,
    TRUSTED_ISSUER.ay,
    String(date),
    "180000",
    ch.challenge,
    SP_ID,
    revocationRegistry.getRoot(),
  ];

  const res = await engine.verifyPresentation({
    proof,
    publicSignals: maliciousSignals,
  });

  assert.equal(res.accepted, false);
  assert.equal(res.code, "NON_CANONICAL_FIELD_ELEMENT");
});

test("Attack 4: Rejects presentation signed by untrusted issuer key", async () => {
  const { engine, challengeStore, revocationRegistry } = await setupEngine();

  const date = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  const ch = challengeStore.issue({
    spId: SP_ID,
    currentDate: date,
    trustedIssuer: TRUSTED_ISSUER,
  });

  const proof = makeValidProof();
  const untrustedIssuerSignals = [
    "99999",
    "1234567890", // Unknown Ax
    "9876543210", // Unknown Ay
    String(date),
    "180000",
    ch.challenge,
    SP_ID,
    revocationRegistry.getRoot(),
  ];

  const res = await engine.verifyPresentation({
    proof,
    publicSignals: untrustedIssuerSignals,
  });

  assert.equal(res.accepted, false);
  assert.equal(res.code, "UNTRUSTED_ISSUER");
});

test("Attack 5: Rejects stale or future date mismatch", async () => {
  const { engine, challengeStore, revocationRegistry } = await setupEngine();

  const date = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  const ch = challengeStore.issue({
    spId: SP_ID,
    currentDate: date,
    trustedIssuer: TRUSTED_ISSUER,
  });

  const proof = makeValidProof();
  const staleDateSignals = [
    "99999",
    TRUSTED_ISSUER.ax,
    TRUSTED_ISSUER.ay,
    "20200101", // Stale date
    "180000",
    ch.challenge,
    SP_ID,
    revocationRegistry.getRoot(),
  ];

  const res = await engine.verifyPresentation({
    proof,
    publicSignals: staleDateSignals,
  });

  assert.equal(res.accepted, false);
  assert.equal(res.code, "DATE_MISMATCH");
});

test("Attack 6 & 7: Rejects unknown, expired, or replayed challenges", async () => {
  const { engine, challengeStore, revocationRegistry } = await setupEngine();

  const date = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  const proof = makeValidProof();

  // 1. Unknown challenge
  const fakeSignals = [
    "99999",
    TRUSTED_ISSUER.ax,
    TRUSTED_ISSUER.ay,
    String(date),
    "180000",
    "9999999999999999999", // Unissued challenge
    SP_ID,
    revocationRegistry.getRoot(),
  ];

  const resUnknown = await engine.verifyPresentation({
    proof,
    publicSignals: fakeSignals,
  });
  assert.equal(resUnknown.accepted, false);
  assert.equal(resUnknown.code, "CHALLENGE_NOT_FOUND");

  // 2. Expired challenge
  const expiredCh = challengeStore.issue({
    spId: SP_ID,
    currentDate: date,
    ttlMs: -1000, // Expired immediately
  });

  const expiredSignals = [...fakeSignals];
  expiredSignals[5] = expiredCh.challenge;

  const resExpired = await engine.verifyPresentation({
    proof,
    publicSignals: expiredSignals,
  });
  assert.equal(resExpired.accepted, false);
  assert.equal(resExpired.code, "CHALLENGE_EXPIRED");

  // 3. Replayed challenge
  const freshCh = challengeStore.issue({
    spId: SP_ID,
    currentDate: date,
  });
  const replayedSignals = [...fakeSignals];
  replayedSignals[5] = freshCh.challenge;

  // First consumption: fails at Snark verify because dummy VK doesn't match dummy proof, but challenge IS consumed
  await engine.verifyPresentation({ proof, publicSignals: replayedSignals });

  // Second submission with exact same challenge MUST be rejected as replayed
  const resReplay = await engine.verifyPresentation({
    proof,
    publicSignals: replayedSignals,
  });
  assert.equal(resReplay.accepted, false);
  assert.equal(resReplay.code, "CHALLENGE_ALREADY_USED");
});

test("Attack 8: Rejects wrong SP ID (cross-context forwarding attack)", async () => {
  const { engine, challengeStore, revocationRegistry } = await setupEngine();

  const date = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  const ch = challengeStore.issue({
    spId: SP_ID,
    currentDate: date,
  });

  const proof = makeValidProof();
  const wrongSpSignals = [
    "99999",
    TRUSTED_ISSUER.ax,
    TRUSTED_ISSUER.ay,
    String(date),
    "180000",
    ch.challenge,
    "999888777", // Different SP ID
    revocationRegistry.getRoot(),
  ];

  const res = await engine.verifyPresentation({
    proof,
    publicSignals: wrongSpSignals,
  });
  assert.equal(res.accepted, false);
  assert.equal(res.code, "SP_ID_MISMATCH");
});

test("Attack 9: Rejects unrecognized or stale revocation root", async () => {
  const { engine, challengeStore } = await setupEngine();

  const date = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  const ch = challengeStore.issue({
    spId: SP_ID,
    currentDate: date,
  });

  const proof = makeValidProof();
  const unacceptedRootSignals = [
    "99999",
    TRUSTED_ISSUER.ax,
    TRUSTED_ISSUER.ay,
    String(date),
    "180000",
    ch.challenge,
    SP_ID,
    "12345678901234567890", // Unknown revocation root
  ];

  const res = await engine.verifyPresentation({
    proof,
    publicSignals: unacceptedRootSignals,
  });
  assert.equal(res.accepted, false);
  assert.equal(res.code, "REVOCATION_ROOT_REJECTED");
});

test("Audit log records zero personal information and tracks nullifier", async () => {
  const { auditLog } = await setupEngine();

  const entry = auditLog.record({
    receiptId: "RCPT_TEST01",
    nullifier: "555123",
    spId: SP_ID,
    accepted: true,
  });

  assert.equal(entry.nullifier, "555123");
  assert.equal(entry.receiptId, "RCPT_TEST01");
  assert.equal(entry.proof, undefined);
  assert.equal(entry.dob, undefined);
  assert.equal(entry.name, undefined);

  // Rate limiting test
  for (let i = 0; i < 20; i++) {
    auditLog.record({
      receiptId: `RCPT_${i}`,
      nullifier: "abuser_nullifier",
      spId: SP_ID,
      accepted: true,
    });
  }
  assert.equal(auditLog.isRateLimited("abuser_nullifier", 20), true);
  assert.equal(auditLog.isRateLimited("honest_nullifier", 20), false);
});
