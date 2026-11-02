import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildPresentationInput,
  CREDENTIAL_TREE_DEPTH,
  isValidDateInt,
  meetsMinimumAge,
  OPENED_SLOTS,
  toDateInt,
} from "../src/prover/inputs.js";

const issuer = { Ax: "111", Ay: "222" };
const credential = {
  issuer,
  attributes: { credentialId: "42", dob: 20000615, kycStatus: 1, expiry: 20301231, holderCommitment: "999", nationality: 356, issuedAt: 20250101 },
  salts: { credentialId: "1", dob: "2", kycStatus: "3", expiry: "4", holderCommitment: "5" },
  root: "777",
  signature: { R8x: "10", R8y: "11", S: "12" },
};
const request = {
  spId: "7",
  challenge: "123456789",
  currentDate: 20261102,
  issuer,
  acceptedRevocationRoots: ["555"],
  expiresAt: "2026-11-02T18:00:00Z",
};
const openSlot = () => ({ siblings: ["1", "2", "3"], pathIndices: [0, 1, 0] });
const revocationPath = { root: "555", siblings: ["8", "9"], pathIndices: [1, 0] };
const now = Date.parse("2026-11-02T17:00:00Z");

function build(overrides = {}) {
  return buildPresentationInput(overrides.credential ?? credential, {
    holderSecret: 31337n,
    request,
    openSlot,
    revocationPath,
    now,
    ...overrides,
  });
}

const expectCode = (code, overrides) => assert.throws(() => build(overrides), { code });

test("date arithmetic: exact birthday, day before, leap day", () => {
  assert.equal(meetsMinimumAge(20081102, 20261102, 18), true);
  assert.equal(meetsMinimumAge(20081103, 20261102, 18), false);
  // Born 29 Feb: counted as adult from 1 Mar in non-leap years.
  assert.equal(meetsMinimumAge(20080229, 20260228, 18), false);
  assert.equal(meetsMinimumAge(20080229, 20260301, 18), true);
  assert.equal(isValidDateInt(20240229), true);
  assert.equal(isValidDateInt(20230229), false);
  assert.equal(isValidDateInt(20231301), false);
  assert.equal(toDateInt(new Date(Date.UTC(2026, 10, 2))), 20261102);
});

test("builds the presentation circuit input with public and private signals", () => {
  const input = build();
  assert.equal(input.dob, "20000615");
  assert.equal(input.minAgeOffset, "180000");
  assert.equal(input.holderSecret, "31337");
  assert.equal(input.revocationRoot, "555");
  assert.equal(input.salts.length, OPENED_SLOTS.length);
  assert.ok(input.siblings.every((path) => path.length === CREDENTIAL_TREE_DEPTH));
  assert.deepEqual(input.revocationPathIndices, [1, 0]);
  assert.ok(Object.values(input).flat(2).every((value) => typeof value === "string" || typeof value === "number"));
});

test("pre-checks give a readable reason for each failure", () => {
  expectCode("UNDERAGE", { credential: { ...credential, attributes: { ...credential.attributes, dob: 20081103 } } });
  expectCode("KYC_NOT_VERIFIED", { credential: { ...credential, attributes: { ...credential.attributes, kycStatus: 0 } } });
  expectCode("CREDENTIAL_EXPIRED", { credential: { ...credential, attributes: { ...credential.attributes, expiry: 20261101 } } });
  expectCode("INVALID_DATE", { credential: { ...credential, attributes: { ...credential.attributes, dob: 20001340 } } });
  expectCode("ISSUER_MISMATCH", { request: { ...request, issuer: { Ax: "1", Ay: "2" } } });
  expectCode("REQUEST_EXPIRED", { now: Date.parse("2026-11-03T00:00:00Z") });
  expectCode("STALE_REVOCATION_ROOT", { revocationPath: { ...revocationPath, root: "556" } });
  expectCode("MISSING_REVOCATION_PATH", { revocationPath: undefined });
  expectCode("MISSING_HOLDER_SECRET", { holderSecret: undefined });
  expectCode("INVALID_FIELD_ELEMENT", { holderSecret: -1n });
  expectCode("INVALID_MERKLE_PATH", { openSlot: () => ({ siblings: ["1"], pathIndices: [0] }) });
  expectCode("INVALID_MERKLE_PATH", { openSlot: () => ({ siblings: ["1", "2", "3"], pathIndices: [0, 2, 0] }) });
  expectCode("MALFORMED_CREDENTIAL", { credential: { ...credential, signature: { R8x: "1" } } });
  expectCode("MALFORMED_REQUEST", { request: { ...request, challenge: undefined } });
});

test("a stricter age policy is honoured", () => {
  assert.throws(() => build({ request: { ...request, minAgeYears: 30 } }), { code: "UNDERAGE" });
  assert.equal(build({ request: { ...request, minAgeYears: 21 } }).minAgeOffset, "210000");
});
