// V5: witness tests for the full KycPresentation circuit.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { loadCircuit } from "./helpers/circuit.mjs";
import { init, H, randField, newIssuer, scenario, presentationInput, ActiveSet } from "./helpers/fixtures.mjs";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let c;
before(async () => { await init(); c = await loadCircuit("circuits/kyc_presentation.circom"); });

const input = (sc, over = {}) => ({ ...presentationInput(sc), ...over });
const ok  = (i) => assert.doesNotReject(c.witness(i));
const bad = (i) => assert.rejects(c.witness(i));

test("valid presentation; public signals in spec order", async () => {
  const sc = await scenario();
  const i = input(sc);
  const w = await c.witness(i);
  // witness[1..8] = publicSignals = [nullifier, issuerAx, issuerAy, currentDate,
  //                                  minAgeOffset, challenge, spId, revocationRoot]
  assert.deepEqual(w.slice(1, 9), [H(sc.holderSecret, sc.spId), i.issuerAx, i.issuerAy,
    i.currentDate, i.minAgeOffset, i.challenge, i.spId, i.revocationRoot]);
});

test("age: exactly 18 today accepted, one day short rejected", async () => {
  await ok (input(await scenario({ values: { dob: 20081103n } })));
  await bad(input(await scenario({ values: { dob: 20081104n } })));
});

test("age: 29 Feb birthday — rejected on 28 Feb, accepted on 1 Mar", async () => {
  await bad(input(await scenario({ values: { dob: 20080229n }, currentDate: 20260228n })));
  await ok (input(await scenario({ values: { dob: 20080229n }, currentDate: 20260301n })));
});

test("kycStatus = 0 (validly signed) is rejected", async () => {
  await bad(input(await scenario({ values: { kycStatus: 0n } })));
});

test("expired credential rejected; expiring today accepted", async () => {
  await bad(input(await scenario({ values: { expiry: 20261102n } })));
  await ok (input(await scenario({ values: { expiry: 20261103n } })));
});

test("credential signed by a different key is rejected", async () => {
  const sc = await scenario({ signer: newIssuer("rogue-issuer") });
  await bad(input(sc));                       // trusted key in public input, rogue signature
});

test("claiming a different issuer key than the signer is rejected", async () => {
  const sc = await scenario();
  const rogue = newIssuer("rogue-issuer");
  await bad(input(sc, { issuerAx: rogue.Ax, issuerAy: rogue.Ay }));
});

test("tampered DOB, salt or other-slot leaf is rejected", async () => {
  const sc = await scenario({ values: { dob: 20100101n } });          // a 16-year-old
  await bad(input(sc, { dob: 20000101n }));                          // lies about DOB
  const i = input(sc);
  await bad({ ...i, salts: i.salts.map((s, k) => (k === 1 ? s + 1n : s)) });
  await bad({ ...i, otherLeaves: [i.otherLeaves[0] + 1n, ...i.otherLeaves.slice(1)] });
});

test("wrong holder secret is rejected", async () => {
  const sc = await scenario();
  await bad(input(sc, { holderSecret: randField() }));
});

test("revoked credential cannot prove against the current root", async () => {
  const sc = await scenario();
  await ok(input(sc));
  sc.active.revoke(1001n);
  await bad(input(sc));
  // NOTE: a proof against an OLD root still passes the circuit — rejecting
  // stale roots is the verifier's job (Someshwar, S5 / S10).
});

test("credential never added to the active set is rejected", async () => {
  const sc = await scenario();
  sc.active = new ActiveSet(); sc.active.add(1001n);   // build a set where it exists...
  const i = input(sc);
  const other = new ActiveSet(); other.add(555n);      // ...but verifier's root is a different set
  await bad({ ...i, revocationRoot: other.root() });
});

test("field-wrapping and out-of-range dates are rejected", async () => {
  // issuer (maliciously or by bug) signs a "negative" DOB
  await bad(input(await scenario({ values: { dob: P - 100000n } })));
  const sc = await scenario();
  await bad(input(sc, { currentDate: 1n << 32n }));
  await bad(input(sc, { minAgeOffset: P - 1n }));
});

test("swapping two slots' values is rejected (positions are fixed)", async () => {
  // credential where dob slot holds a "young" date; attacker swaps dob and expiry values
  const sc = await scenario({ values: { dob: 20100101n, expiry: 20000101n } });
  const i = input(sc);
  await bad({ ...i, dob: i.expiry, expiry: i.dob, salts: [i.salts[0], i.salts[3], i.salts[2], i.salts[1], i.salts[4]] });
});

test("nullifier: stable for same SP, different across SPs", async () => {
  const sc = await scenario();
  const a = await c.witness(input(sc, { spId: 1n }));
  const b = await c.witness(input(sc, { spId: 1n, challenge: randField() }));
  const d = await c.witness(input(sc, { spId: 2n }));
  assert.equal(a[1], b[1]);
  assert.notEqual(a[1], d[1]);
});
