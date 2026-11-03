import { buildEddsa, buildPoseidon } from "circomlibjs";

export const CREDENTIAL_SLOTS = Object.freeze([
  "credentialId",
  "dob",
  "kycStatus",
  "expiry",
  "holderCommitment",
  "nationality",
  "issuedAt",
  "reserved",
]);

const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let primitivesPromise;

function primitives() {
  primitivesPromise ??= Promise.all([buildPoseidon(), buildEddsa()]);
  return primitivesPromise;
}

function field(value, name) {
  let parsed;
  try {
    if (typeof value === "bigint") parsed = value;
    else if (typeof value === "number" && Number.isSafeInteger(value)) parsed = BigInt(value);
    else if (typeof value === "string" && /^(0|[1-9]\d*)$/.test(value)) parsed = BigInt(value);
  } catch {
    parsed = undefined;
  }
  if (parsed === undefined || parsed < 0n || parsed >= FIELD) {
    throw new TypeError(`${name} must be a canonical BN254 field element.`);
  }
  return parsed;
}

function dateField(value, name) {
  const parsed = field(value, name);
  const number = Number(parsed);
  const year = Math.floor(number / 10000);
  const month = Math.floor(number / 100) % 100;
  const day = number % 100;
  const date = new Date(Date.UTC(year, month - 1, day));
  if (!Number.isSafeInteger(number) || year < 1900 || year > 2199 || month < 1 || month > 12
    || day < 1 || date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day) {
    throw new TypeError(`${name} must be a valid calendar date in YYYYMMDD form.`);
  }
  return parsed;
}

function serialized(fieldApi, value) {
  return typeof value === "bigint" ? value.toString() : fieldApi.toObject(value).toString();
}

function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesFromHex(value) {
  return Uint8Array.from(value.match(/.{2}/g), (byte) => Number.parseInt(byte, 16));
}

function randomSalt() {
  return BigInt(`0x${bytesToHex(randomBytes(31))}`).toString();
}

function keyCoordinates(issuer) {
  return {
    Ax: field(issuer?.Ax ?? issuer?.ax, "issuer Ax").toString(),
    Ay: field(issuer?.Ay ?? issuer?.ay, "issuer Ay").toString(),
  };
}

function buildLevels(poseidon, leaves) {
  const levels = [leaves];
  while (levels.at(-1).length > 1) {
    const previous = levels.at(-1);
    const next = [];
    for (let index = 0; index < previous.length; index += 2) {
      next.push(poseidon([previous[index], previous[index + 1]]));
    }
    levels.push(next);
  }
  return levels;
}

export async function generateIssuerKeyPair() {
  return issuerKeyPairFromPrivateKey(bytesToHex(randomBytes(32)));
}

export async function issuerKeyPairFromPrivateKey(privateKey) {
  if (typeof privateKey !== "string" || !/^[0-9a-f]{64}$/i.test(privateKey)) {
    throw new TypeError("issuerPrivateKey must be a 32-byte hexadecimal seed.");
  }
  const [, eddsa] = await primitives();
  const privateBytes = bytesFromHex(privateKey);
  const publicKey = eddsa.prv2pub(privateBytes);
  return {
    privateKey: privateKey.toLowerCase(),
    publicKey: {
      Ax: serialized(eddsa.F, publicKey[0]),
      Ay: serialized(eddsa.F, publicKey[1]),
    },
  };
}

export async function createHolderCommitment(holderSecret) {
  const secret = field(holderSecret, "holder secret");
  if (secret === 0n) throw new RangeError("holder secret must be non-zero.");
  const [poseidon] = await primitives();
  return serialized(poseidon.F, poseidon([secret]));
}

export async function issueCredential({
  credentialId,
  dob,
  kycStatus = 1,
  expiry,
  holderCommitment,
  nationality = 840,
  issuedAt,
  issuerId = "local-demo-issuer",
  issuerPrivateKey,
}) {
  if (typeof issuerId !== "string" || !/^[A-Za-z0-9._:-]{1,31}$/.test(issuerId)) {
    throw new TypeError("issuerId must be 1 to 31 ASCII letters, digits, or . _ : - characters.");
  }
  if (typeof issuerPrivateKey !== "string" || !/^[0-9a-f]{64}$/i.test(issuerPrivateKey)) {
    throw new TypeError("issuerPrivateKey must be a 32-byte hexadecimal seed.");
  }
  const attrs = {
    credentialId: field(credentialId, "credentialId"),
    dob: dateField(dob, "dob"),
    kycStatus: field(kycStatus, "kycStatus"),
    expiry: dateField(expiry, "expiry"),
    holderCommitment: field(holderCommitment, "holderCommitment"),
    nationality: field(nationality, "nationality"),
    issuedAt: dateField(issuedAt, "issuedAt"),
    reserved: 0n,
  };
  if (attrs.kycStatus !== 1n) throw new RangeError("Demo credentials must have verified KYC status.");
  if (attrs.expiry <= attrs.issuedAt) throw new RangeError("Credential expiry must be after its issue date.");

  const [poseidon, eddsa] = await primitives();
  const salts = Object.fromEntries(CREDENTIAL_SLOTS.map((slot) => [slot, randomSalt()]));
  const values = CREDENTIAL_SLOTS.map((slot) => attrs[slot]);
  const saltValues = CREDENTIAL_SLOTS.map((slot) => BigInt(salts[slot]));
  const leaves = values.map((value, index) => poseidon([BigInt(index), value, saltValues[index]]));
  const levels = buildLevels(poseidon, leaves);
  const root = levels.at(-1)[0];
  const privateKey = bytesFromHex(issuerPrivateKey);
  const publicKey = eddsa.prv2pub(privateKey);
  const signature = eddsa.signPoseidon(privateKey, poseidon.F.e(root));

  return {
    version: 2,
    issuerId,
    issuer: {
      Ax: serialized(eddsa.F, publicKey[0]),
      Ay: serialized(eddsa.F, publicKey[1]),
    },
    attributes: Object.fromEntries(CREDENTIAL_SLOTS.map((slot) => [slot, attrs[slot].toString()])),
    salts,
    leaves: leaves.map((leaf) => serialized(eddsa.F, leaf)),
    root: serialized(eddsa.F, root),
    signature: {
      R8x: serialized(eddsa.F, signature.R8[0]),
      R8y: serialized(eddsa.F, signature.R8[1]),
      S: signature.S.toString(),
    },
  };
}

export async function verifyCredential(credential, trustedIssuer) {
  try {
    if (credential?.version !== 2 || !credential.attributes || !credential.salts
      || !Array.isArray(credential.leaves) || credential.leaves.length !== CREDENTIAL_SLOTS.length
      || !credential.signature) return false;

    const issuer = keyCoordinates(credential.issuer);
    const trusted = trustedIssuer ? keyCoordinates(trustedIssuer) : issuer;
    if (issuer.Ax !== trusted.Ax || issuer.Ay !== trusted.Ay) return false;

    const [poseidon, eddsa] = await primitives();
    const values = CREDENTIAL_SLOTS.map((slot) => {
      const value = slot === "dob" || slot === "expiry" || slot === "issuedAt"
        ? dateField(credential.attributes[slot], `${slot} attribute`)
        : field(credential.attributes[slot], `${slot} attribute`);
      return value;
    });
    if (values[2] !== 1n || values[3] <= values[6] || values[7] !== 0n) return false;
    const leaves = CREDENTIAL_SLOTS.map((slot, index) =>
      poseidon([BigInt(index), values[index], field(credential.salts[slot], `${slot} salt`)]));
    const serializedLeaves = leaves.map((leaf) => serialized(eddsa.F, leaf));
    if (serializedLeaves.some((leaf, index) => leaf !== credential.leaves[index])) return false;

    const levels = buildLevels(poseidon, leaves);
    const root = serialized(eddsa.F, levels.at(-1)[0]);
    if (root !== field(credential.root, "credential root").toString()) return false;

    const signature = {
      R8: [
        eddsa.F.e(field(credential.signature.R8x, "signature R8x")),
        eddsa.F.e(field(credential.signature.R8y, "signature R8y")),
      ],
      S: field(credential.signature.S, "signature S"),
    };
    const publicKey = [eddsa.F.e(trusted.Ax), eddsa.F.e(trusted.Ay)];
    return eddsa.verifyPoseidon(eddsa.F.e(BigInt(root)), signature, publicKey);
  } catch {
    return false;
  }
}

export async function openCredentialSlot(credential, slotName) {
  const index = CREDENTIAL_SLOTS.indexOf(slotName);
  if (index < 0 || !Array.isArray(credential?.leaves) || credential.leaves.length !== 8) {
    throw new TypeError(`Invalid credential slot "${slotName}".`);
  }
  const [poseidon] = await primitives();
  const levels = buildLevels(poseidon, credential.leaves.map((leaf) => field(leaf, "credential leaf")));
  const siblings = [];
  const pathIndices = [];
  let current = index;
  for (let depth = 0; depth < levels.length - 1; depth += 1) {
    siblings.push(serialized(poseidon.F, levels[depth][current ^ 1]));
    pathIndices.push(current & 1);
    current >>= 1;
  }
  return { siblings, pathIndices };
}
