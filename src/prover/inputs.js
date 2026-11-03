// Turns wallet data and a Service Provider request into circuit input.
// Every claim is pre-checked here so the user gets a readable reason instead
// of an opaque "Assert Failed" from witness generation.

export const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export class ProverInputError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ProverInputError";
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new ProverInputError(code, message);
};

export function toFieldElement(value, label) {
  let parsed;
  try {
    if (typeof value === "bigint") parsed = value;
    else if (typeof value === "number" && Number.isSafeInteger(value)) parsed = BigInt(value);
    else if (typeof value === "string" && /^\d+$/.test(value.trim())) parsed = BigInt(value.trim());
  } catch {
    parsed = undefined;
  }
  if (parsed === undefined || parsed < 0n || parsed >= BN254_SCALAR_FIELD) {
    fail("INVALID_FIELD_ELEMENT", `${label} must be a non-negative integer below the BN254 field modulus.`);
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Dates are encoded as YYYYMMDD integers. Adding N years adds exactly N*10000,
// so "age >= N" is `currentDate - dob >= N * 10000`.

export function toDateInt(date) {
  return date.getUTCFullYear() * 10000 + (date.getUTCMonth() + 1) * 100 + date.getUTCDate();
}

export function isValidDateInt(value) {
  if (!Number.isSafeInteger(value)) return false;
  const year = Math.floor(value / 10000);
  const month = Math.floor(value / 100) % 100;
  const day = value % 100;
  if (year < 1900 || year > 2199 || month < 1 || month > 12 || day < 1) return false;
  const check = new Date(Date.UTC(year, month - 1, day));
  return check.getUTCMonth() === month - 1 && check.getUTCDate() === day;
}

export function meetsMinimumAge(dob, currentDate, years) {
  return currentDate - dob >= years * 10000;
}

function dateField(value, label) {
  const number = typeof value === "string" ? Number(value) : value;
  if (!isValidDateInt(number)) fail("INVALID_DATE", `${label} must be a calendar date in YYYYMMDD form.`);
  return number;
}

// ---------------------------------------------------------------------------
// Starter circuit (circuits/kyc_claims.circom).

export function buildStarterInput({ age, kycVerified }) {
  const ageNumber = typeof age === "string" && age.trim() !== "" ? Number(age) : age;
  if (!Number.isInteger(ageNumber) || ageNumber < 0 || ageNumber > 255) {
    fail("AGE_OUT_OF_RANGE", "Age must be a whole number between 0 and 255.");
  }
  if (![true, false, 0, 1].includes(kycVerified)) {
    fail("INVALID_KYC_FLAG", "KYC status must be true/false or 1/0.");
  }
  return { age: ageNumber, kycVerified: kycVerified === true || kycVerified === 1 ? 1 : 0 };
}

// ---------------------------------------------------------------------------
// Presentation circuit (credential-bound, see docs/prover-pipeline.md).
// The credential layout and signal names follow the draft in the task
// allocation plan; they must be kept in sync with spec/credential-format.md
// and spec/claim-interface.md once those are frozen.

export const CREDENTIAL_TREE_DEPTH = 3;
export const CREDENTIAL_SLOTS = Object.freeze({
  credentialId: 0,
  dob: 1,
  kycStatus: 2,
  expiry: 3,
  holderCommitment: 4,
  nationality: 5,
  issuedAt: 6,
  reserved: 7,
});
// Slots opened by the presentation circuit. holderCommitment is recomputed
// in-circuit from holderSecret, so only its salt and path are needed.
export const OPENED_SLOTS = Object.freeze(["credentialId", "dob", "kycStatus", "expiry", "holderCommitment"]);

function requireFields(object, fields, code, label) {
  for (const field of fields) {
    if (object?.[field] === undefined || object[field] === null) fail(code, `${label} is missing "${field}".`);
  }
}

function merklePath(path, depth, label) {
  if (!Array.isArray(path?.siblings) || !Array.isArray(path?.pathIndices)
    || path.siblings.length !== depth || path.pathIndices.length !== depth) {
    fail("INVALID_MERKLE_PATH", `${label} must have ${depth} siblings and path indices.`);
  }
  return {
    siblings: path.siblings.map((value, i) => toFieldElement(value, `${label} sibling ${i}`).toString()),
    pathIndices: path.pathIndices.map((bit, i) => {
      if (bit !== 0 && bit !== 1 && bit !== "0" && bit !== "1") {
        fail("INVALID_MERKLE_PATH", `${label} path index ${i} must be 0 or 1.`);
      }
      return Number(bit);
    }),
  };
}

function sameKey(a, b) {
  return toFieldElement(a.Ax, "issuer Ax") === toFieldElement(b.Ax, "issuer Ax")
    && toFieldElement(a.Ay, "issuer Ay") === toFieldElement(b.Ay, "issuer Ay");
}

/**
 * @param credential   Stored credential: { issuer:{Ax,Ay}, attributes, salts, root, signature:{R8x,R8y,S} }
 * @param options.holderSecret   Unlocked wallet secret.
 * @param options.request        Service Provider request: { spId, challenge, currentDate, issuer:{Ax,Ay},
 *                               minAgeYears?, acceptedRevocationRoots, expiresAt? }
 * @param options.openSlot       (credential, slotName) => { siblings, pathIndices } from the credential library.
 * @param options.revocationPath { root, siblings, pathIndices } for credentialId, from the revocation registry.
 * @param options.now            Clock override for tests.
 */
export function buildPresentationInput(credential, { holderSecret, request, openSlot, revocationPath, now = Date.now() }) {
  requireFields(credential, ["issuer", "attributes", "salts", "root", "signature"], "MALFORMED_CREDENTIAL", "Credential");
  requireFields(credential.attributes, OPENED_SLOTS.filter((slot) => slot !== "holderCommitment"), "MALFORMED_CREDENTIAL", "Credential attributes");
  requireFields(credential.salts, OPENED_SLOTS, "MALFORMED_CREDENTIAL", "Credential salts");
  requireFields(credential.signature, ["R8x", "R8y", "S"], "MALFORMED_CREDENTIAL", "Credential signature");
  requireFields(request, ["spId", "challenge", "currentDate", "issuer", "acceptedRevocationRoots"], "MALFORMED_REQUEST", "Proof request");
  if (typeof openSlot !== "function") fail("MISSING_MERKLE_PROVIDER", "A credential Merkle path provider is required.");

  if (request.expiresAt !== undefined && new Date(request.expiresAt).getTime() < now) {
    fail("REQUEST_EXPIRED", "This proof request has expired. Ask the service for a new one.");
  }
  if (!sameKey(credential.issuer, request.issuer)) {
    fail("ISSUER_MISMATCH", "This credential was not issued by the authority the service trusts.");
  }

  const currentDate = dateField(request.currentDate, "Request date");
  const dob = dateField(credential.attributes.dob, "Date of birth");
  const expiry = dateField(credential.attributes.expiry, "Credential expiry");
  const minAgeYears = request.minAgeYears ?? 18;
  if (!Number.isInteger(minAgeYears) || minAgeYears < 0 || minAgeYears > 150) {
    fail("MALFORMED_REQUEST", "Requested minimum age is not valid.");
  }

  if (expiry < currentDate) fail("CREDENTIAL_EXPIRED", "This credential has expired.");
  if (!meetsMinimumAge(dob, currentDate, minAgeYears)) {
    fail("UNDERAGE", `The credential does not satisfy age >= ${minAgeYears}.`);
  }
  if (String(credential.attributes.kycStatus) !== "1") fail("KYC_NOT_VERIFIED", "The credential's KYC status is not verified.");

  if (holderSecret === undefined || holderSecret === null) fail("MISSING_HOLDER_SECRET", "Unlock the wallet first.");
  const secret = toFieldElement(holderSecret, "Holder secret");
  if (secret === 0n) fail("MISSING_HOLDER_SECRET", "Holder secret must be non-zero.");

  if (!revocationPath) fail("MISSING_REVOCATION_PATH", "Fetch a revocation membership path from the issuer first.");
  const revocationRoot = toFieldElement(revocationPath.root, "Revocation root");
  const acceptedRoots = request.acceptedRevocationRoots.map((root) => toFieldElement(root, "Accepted revocation root"));
  if (!acceptedRoots.includes(revocationRoot)) {
    fail("STALE_REVOCATION_ROOT", "The revocation path is not against a root this service accepts; refresh it.");
  }
  if (!Array.isArray(revocationPath.siblings) || revocationPath.siblings.length === 0) {
    fail("INVALID_MERKLE_PATH", "Revocation path has no siblings.");
  }
  const revocation = merklePath(revocationPath, revocationPath.siblings.length, "Revocation path");

  const openings = OPENED_SLOTS.map((slot) => merklePath(openSlot(credential, slot), CREDENTIAL_TREE_DEPTH, `Credential ${slot} path`));

  return {
    // Private
    credentialId: toFieldElement(credential.attributes.credentialId, "credentialId").toString(),
    dob: String(dob),
    kycStatus: "1",
    expiry: String(expiry),
    holderSecret: secret.toString(),
    salts: OPENED_SLOTS.map((slot) => toFieldElement(credential.salts[slot], `${slot} salt`).toString()),
    siblings: openings.map((opening) => opening.siblings),
    pathIndices: openings.map((opening) => opening.pathIndices),
    credentialRoot: toFieldElement(credential.root, "Credential root").toString(),
    sigR8x: toFieldElement(credential.signature.R8x, "Signature R8x").toString(),
    sigR8y: toFieldElement(credential.signature.R8y, "Signature R8y").toString(),
    sigS: toFieldElement(credential.signature.S, "Signature S").toString(),
    revocationSiblings: revocation.siblings,
    revocationPathIndices: revocation.pathIndices,
    // Public
    issuerAx: toFieldElement(request.issuer.Ax, "issuer Ax").toString(),
    issuerAy: toFieldElement(request.issuer.Ay, "issuer Ay").toString(),
    currentDate: String(currentDate),
    minAgeOffset: String(minAgeYears * 10000),
    challenge: toFieldElement(request.challenge, "Challenge").toString(),
    spId: toFieldElement(request.spId, "spId").toString(),
    revocationRoot: revocationRoot.toString(),
  };
}
