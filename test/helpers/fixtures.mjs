// Test fixtures: builds real signed credentials and full circuit inputs.
// Hashing rules here MUST equal the circuit (and Pallavi's src/common):
//   leaf = Poseidon(slot, value, salt);  node = Poseidon(left, right)
//   holderCommitment = Poseidon(holderSecret)
//   revocation leaf = Poseidon(credentialId)
// When src/common lands, switch these helpers to import from it (task V8).
import { buildPoseidon, buildEddsa } from "circomlibjs";
import crypto from "node:crypto";

export const DEPTH = 3;        // 8 credential slots
export const REV_DEPTH = 16;
export const MIN_AGE_OFFSET = 180000n;

let P, E, F;
export async function init() {
  if (!P) { P = await buildPoseidon(); E = await buildEddsa(); F = P.F; }
  return { poseidon: P, eddsa: E, F };
}
export const H = (...xs) => F.toObject(P(xs.map(BigInt)));
export const randField = () =>
  BigInt("0x" + crypto.randomBytes(31).toString("hex")); // 248 bits < p

// ---------- credential tree ----------
export function buildTree(leaves) {           // leaves.length = 2^depth
  const levels = [leaves];
  while (levels.at(-1).length > 1) {
    const prev = levels.at(-1), next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(H(prev[i], prev[i + 1]));
    levels.push(next);
  }
  return levels;
}
export function pathOf(levels, index) {
  const sib = [];
  for (let d = 0; d < levels.length - 1; d++) {
    sib.push(levels[d][index ^ 1]);
    index >>= 1;
  }
  return sib;
}

export function newIssuer(seed = "kyc-authority-test-key") {
  const prv = crypto.createHash("sha256").update(seed).digest();
  const pub = E.prv2pub(prv);
  return { prv, Ax: F.toObject(pub[0]), Ay: F.toObject(pub[1]) };
}

// values: { credentialId, dob, kycStatus, expiry, nationality, issuedAt }
export function issueCredential(issuer, values, holderCommitment) {
  const slotValues = [
    values.credentialId, values.dob, values.kycStatus, values.expiry,
    holderCommitment, values.nationality ?? 356n, values.issuedAt ?? 20260101n, 0n,
  ].map(BigInt);
  const salts = slotValues.map(() => randField());
  const leaves = slotValues.map((v, i) => H(i, v, salts[i]));
  const levels = buildTree(leaves);
  const root = levels.at(-1)[0];
  const sig = E.signPoseidon(issuer.prv, F.e(root));
  return {
    slotValues, salts, levels, root,
    sig: { R8x: F.toObject(sig.R8[0]), R8y: F.toObject(sig.R8[1]), S: sig.S },
  };
}

// ---------- revocation (active-credential) tree, sparse ----------
export class ActiveSet {
  constructor(depth = REV_DEPTH) {
    this.depth = depth; this.nodes = new Map(); this.zeros = [0n];
    for (let i = 1; i <= depth; i++) this.zeros.push(H(this.zeros[i - 1], this.zeros[i - 1]));
    this.next = 0; this.index = new Map();
  }
  node(d, i) { return this.nodes.get(`${d}:${i}`) ?? this.zeros[d]; }
  set(i, leaf) {
    this.nodes.set(`0:${i}`, leaf);
    for (let d = 1; d <= this.depth; d++) {
      i >>= 1;
      this.nodes.set(`${d}:${i}`, H(this.node(d - 1, 2 * i), this.node(d - 1, 2 * i + 1)));
    }
  }
  add(credentialId) { const i = this.next++; this.index.set(BigInt(credentialId), i); this.set(i, H(credentialId)); }
  revoke(credentialId) { this.set(this.index.get(BigInt(credentialId)), 0n); }
  root() { return this.node(this.depth, 0); }
  path(credentialId) {
    let i = this.index.get(BigInt(credentialId));
    const siblings = [], bits = [];
    for (let d = 0; d < this.depth; d++) { siblings.push(this.node(d, i ^ 1)); bits.push(BigInt(i & 1)); i >>= 1; }
    return { siblings, bits };
  }
}

// ---------- full circuit input ----------
export function presentationInput({ issuer, cred, holderSecret, active, currentDate, challenge, spId }) {
  const { siblings, bits } = active.path(cred.slotValues[0]);
  return {
    issuerAx: issuer.Ax, issuerAy: issuer.Ay,
    currentDate: BigInt(currentDate), minAgeOffset: MIN_AGE_OFFSET,
    challenge, spId, revocationRoot: active.root(),
    credentialId: cred.slotValues[0], dob: cred.slotValues[1],
    kycStatus: cred.slotValues[2], expiry: cred.slotValues[3],
    holderSecret,
    salts: cred.salts.slice(0, 5),
    otherLeaves: cred.levels[0].slice(5, 8),
    sigR8x: cred.sig.R8x, sigR8y: cred.sig.R8y, sigS: cred.sig.S,
    revSiblings: siblings, revPathIndices: bits,
  };
}

// Convenience: a complete valid scenario, overridable.
export async function scenario(o = {}) {
  await init();
  const issuer = o.issuer ?? newIssuer();
  const holderSecret = o.holderSecret ?? randField();
  const values = { credentialId: 1001n, dob: 20000615n, kycStatus: 1n, expiry: 20301231n, ...o.values };
  const cred = issueCredential(o.signer ?? issuer, values, H(holderSecret));
  const active = new ActiveSet();
  active.add(999n); active.add(values.credentialId); active.add(1002n);
  return { issuer, holderSecret, cred, active, currentDate: o.currentDate ?? 20261103n,
           challenge: o.challenge ?? randField(), spId: o.spId ?? 42n };
}
