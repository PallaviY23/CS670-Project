// V2: each sub-template with valid and invalid witnesses.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { loadCircuit } from "./helpers/circuit.mjs";
import { init, H, randField, buildTree, pathOf, newIssuer, MIN_AGE_OFFSET } from "./helpers/fixtures.mjs";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ok = (c, i) => assert.doesNotReject(c.witness(i));
const bad = (c, i) => assert.rejects(c.witness(i));
let F, eddsa;
before(async () => ({ F, eddsa } = await init()));

test("AgeAtLeast: exactly 18 today passes, one day short fails", async () => {
  const c = await loadCircuit("test/circuits/age_test.circom");
  await ok (c, { dob: 20081103n, currentDate: 20261103n, minAgeOffset: MIN_AGE_OFFSET });
  await bad(c, { dob: 20081104n, currentDate: 20261103n, minAgeOffset: MIN_AGE_OFFSET });
  await ok (c, { dob: 19700101n, currentDate: 20261103n, minAgeOffset: MIN_AGE_OFFSET });
});

test("AgeAtLeast: 29 Feb birthday becomes 18 on 1 March in a non-leap year", async () => {
  const c = await loadCircuit("test/circuits/age_test.circom");
  await bad(c, { dob: 20080229n, currentDate: 20260228n, minAgeOffset: MIN_AGE_OFFSET });
  await ok (c, { dob: 20080229n, currentDate: 20260301n, minAgeOffset: MIN_AGE_OFFSET });
});

test("AgeAtLeast: month/day boundaries compare correctly", async () => {
  const c = await loadCircuit("test/circuits/age_test.circom");
  await bad(c, { dob: 20081231n, currentDate: 20261230n, minAgeOffset: MIN_AGE_OFFSET });
  await ok (c, { dob: 20081231n, currentDate: 20270101n, minAgeOffset: MIN_AGE_OFFSET });
  await bad(c, { dob: 20090101n, currentDate: 20261231n, minAgeOffset: MIN_AGE_OFFSET });
});

test("DateRange: field-wrapping and oversized dates are rejected", async () => {
  const c = await loadCircuit("test/circuits/age_test.circom");
  await bad(c, { dob: P - 100000n, currentDate: 20261103n, minAgeOffset: MIN_AGE_OFFSET }); // "negative" dob
  await bad(c, { dob: 20000101n, currentDate: 1n << 32n, minAgeOffset: MIN_AGE_OFFSET });
  await bad(c, { dob: 20000101n, currentDate: 20261103n, minAgeOffset: P - 1n });
});

test("Without DateRange the wrap-around attack succeeds (why the check exists)", async () => {
  const c = await loadCircuit("test/circuits/age_unchecked_test.circom");
  // dob + 180000 wraps to 80000 mod p, which is <= today: a fake "adult"
  ok(c, { dob: P - 100000n, currentDate: 20261103n, minAgeOffset: MIN_AGE_OFFSET });
});

test("NotExpired: expiry today passes, yesterday fails", async () => {
  const c = await loadCircuit("test/circuits/expiry_test.circom");
  await ok (c, { expiry: 20261103n, currentDate: 20261103n });
  await ok (c, { expiry: 20301231n, currentDate: 20261103n });
  await bad(c, { expiry: 20261102n, currentDate: 20261103n });
});

test("AttributeLeaf + MerkleInclusionFixed: matches JS tree; tampering changes root", async () => {
  const c = await loadCircuit("test/circuits/leaf_path_test.circom");
  const vals = [7n, 20000615n, 1n, 20301231n, 5n, 356n, 20260101n, 0n];
  const salts = vals.map(() => randField());
  const levels = buildTree(vals.map((v, i) => H(i, v, salts[i])));
  const root = levels.at(-1)[0];
  const sib = pathOf(levels, 1);
  const w = await c.witness({ value: vals[1], salt: salts[1], siblings: sib });
  assert.equal(w[1], H(1, vals[1], salts[1]));   // leaf
  assert.equal(w[2], root);                       // root
  const w2 = await c.witness({ value: 19990101n, salt: salts[1], siblings: sib });
  assert.notEqual(w2[2], root);
  // the same value/salt hashed under another slot gives a different leaf
  assert.notEqual(H(1, vals[1], salts[1]), H(2, vals[1], salts[1]));
});

test("MerkleInclusion: correct root for every position; non-boolean path bit fails", async () => {
  const c = await loadCircuit("test/circuits/merkle_test.circom");
  const leaves = Array.from({ length: 16 }, (_, i) => H(i + 100));
  const levels = buildTree(leaves);
  for (const idx of [0, 5, 10, 15]) {
    const bits = [0, 1, 2, 3].map((d) => BigInt((idx >> d) & 1));
    const w = await c.witness({ leaf: leaves[idx], siblings: pathOf(levels, idx), pathIndices: bits });
    assert.equal(w[1], levels.at(-1)[0]);
  }
  await bad(c, { leaf: leaves[0], siblings: pathOf(levels, 0), pathIndices: [2n, 0n, 0n, 0n] });
});

test("HolderBinding + Nullifier: match JS; nullifier differs per service provider", async () => {
  const c = await loadCircuit("test/circuits/holder_test.circom");
  const s = randField();
  const a = await c.witness({ holderSecret: s, spId: 1n });
  const b = await c.witness({ holderSecret: s, spId: 2n });
  assert.equal(a[1], H(s));
  assert.equal(a[2], H(s, 1n));
  assert.notEqual(a[2], b[2]);
});

test("IssuerSignature: valid passes; wrong key, wrong message, bad S fail", async () => {
  const c = await loadCircuit("test/circuits/signature_test.circom");
  const iss = newIssuer(), other = newIssuer("someone-else");
  const root = H(1n, 2n);
  const sig = eddsa.signPoseidon(iss.prv, F.e(root));
  const base = { Ax: iss.Ax, Ay: iss.Ay, R8x: F.toObject(sig.R8[0]), R8y: F.toObject(sig.R8[1]), S: sig.S, root };
  await ok (c, base);
  await bad(c, { ...base, Ax: other.Ax, Ay: other.Ay });
  await bad(c, { ...base, root: root + 1n });
  await bad(c, { ...base, S: sig.S + 1n });
});
