import { randomBytes } from "node:crypto";
import { buildEddsa, buildPoseidon } from "circomlibjs";

const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ATTRIBUTE_IDS = Object.freeze({ age: 1n, kycVerified: 2n });
const ATTRIBUTE_NAMES = Object.keys(ATTRIBUTE_IDS);
let primitivesPromise;

function getPrimitives() {
  primitivesPromise ??= Promise.all([buildPoseidon(), buildEddsa()]);
  return primitivesPromise;
}

function toInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer.`);
  }
  return BigInt(value);
}

function parseField(value, name) {
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
    throw new TypeError(`${name} must be a canonical decimal field string.`);
  }

  const parsed = BigInt(value);
  if (parsed >= FIELD_MODULUS) {
    throw new RangeError(`${name} is outside the BN128 scalar field.`);
  }
  return parsed;
}

function parseIssuerId(issuerId) {
  if (typeof issuerId !== "string" || !/^[A-Za-z0-9._:-]{1,31}$/.test(issuerId)) {
    throw new TypeError("issuerId must be 1 to 31 ASCII letters, digits, or . _ : - characters.");
  }
  return BigInt(`0x${Buffer.from(issuerId, "ascii").toString("hex")}`);
}

function fieldString(field, value) {
  return field.toObject(value).toString();
}

function asFieldElement(field, value, name) {
  return field.e(parseField(value, name));
}

function parsePublicKey(publicKey, field) {
  if (!Array.isArray(publicKey) || publicKey.length !== 2) {
    throw new TypeError("issuerPublicKey must contain two field elements.");
  }
  return publicKey.map((value, index) => asFieldElement(field, value, `issuerPublicKey[${index}]`));
}

function parseSignature(signature, field) {
  if (!signature || !Array.isArray(signature.R8) || signature.R8.length !== 2) {
    throw new TypeError("signature.R8 must contain two field elements.");
  }
  const R8 = signature.R8.map((value, index) => asFieldElement(field, value, `signature.R8[${index}]`));
  const S = parseField(signature.S, "signature.S");
  return { R8, S };
}

function validateClaims(claims) {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    throw new TypeError("claims must be an object.");
  }
  if (!Number.isInteger(claims.age) || claims.age < 0 || claims.age > 255) {
    throw new RangeError("claims.age must be an integer from 0 to 255.");
  }
  if (typeof claims.kycVerified !== "boolean") {
    throw new TypeError("claims.kycVerified must be a Boolean.");
  }
}

function validatePrivateAttributes(attributes) {
  if (!attributes || typeof attributes !== "object") {
    throw new TypeError("Credential privateAttributes are missing.");
  }
  if (!Number.isInteger(attributes.age?.value) || attributes.age.value < 0 || attributes.age.value > 255) {
    throw new RangeError("Credential age must be an integer from 0 to 255.");
  }
  if (typeof attributes.kycVerified?.value !== "boolean") {
    throw new TypeError("Credential kycVerified must be a Boolean.");
  }
  parseField(attributes.age.salt, "age salt");
  parseField(attributes.kycVerified.salt, "kycVerified salt");
}

function valueAsField(name, value) {
  if (name === "age") {
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new RangeError("Disclosed age must be an integer from 0 to 255.");
    }
    return BigInt(value);
  }
  if (name === "kycVerified" && typeof value === "boolean") {
    return value ? 1n : 0n;
  }
  throw new TypeError(`Invalid value for disclosed attribute ${name}.`);
}

async function hashFields(values) {
  const [poseidon] = await getPrimitives();
  return poseidon(values);
}

async function attributeLeaf(name, value, salt) {
  return hashFields([ATTRIBUTE_IDS[name], valueAsField(name, value), parseField(salt, `${name} salt`)]);
}

async function commitmentFor(attributes) {
  validatePrivateAttributes(attributes);
  const ageLeaf = await attributeLeaf("age", attributes.age.value, attributes.age.salt);
  const kycLeaf = await attributeLeaf("kycVerified", attributes.kycVerified.value, attributes.kycVerified.salt);
  return hashFields([ageLeaf, kycLeaf]);
}

async function signedMessage({ commitment, issuerId, issuedAt, expiresAt }) {
  return hashFields([
    parseField(commitment, "commitment"),
    toInteger(issuedAt, "issuedAt"),
    toInteger(expiresAt, "expiresAt"),
    parseIssuerId(issuerId),
  ]);
}

function randomSalt() {
  return BigInt(`0x${randomBytes(31).toString("hex")}`).toString();
}

function serializePublicKey(publicKey, field) {
  return publicKey.map((coordinate) => fieldString(field, coordinate));
}

function equalPublicKeys(left, right) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length === 2
    && right.length === 2
    && left.every((coordinate, index) => coordinate === right[index]);
}

export async function generateIssuerKeyPair() {
  const [, eddsa] = await getPrimitives();
  const privateKey = randomBytes(32);
  const publicKey = eddsa.prv2pub(privateKey);

  return {
    privateKey: privateKey.toString("hex"),
    publicKey: serializePublicKey(publicKey, eddsa.F),
  };
}

export async function issueCredential({
  claims,
  issuerId,
  issuerPrivateKey,
  issuedAt = Math.floor(Date.now() / 1000),
  expiresAt = 0,
}) {
  validateClaims(claims);
  parseIssuerId(issuerId);
  toInteger(issuedAt, "issuedAt");
  toInteger(expiresAt, "expiresAt");
  if (expiresAt !== 0 && expiresAt <= issuedAt) {
    throw new RangeError("expiresAt must be later than issuedAt, or 0 for no expiry.");
  }
  if (typeof issuerPrivateKey !== "string" || !/^[0-9a-fA-F]{64}$/.test(issuerPrivateKey)) {
    throw new TypeError("issuerPrivateKey must be a 32-byte hexadecimal seed.");
  }

  const [, eddsa] = await getPrimitives();
  const privateKey = Buffer.from(issuerPrivateKey, "hex");
  const issuerPublicKey = eddsa.prv2pub(privateKey);
  const privateAttributes = {
    age: { value: claims.age, salt: randomSalt() },
    kycVerified: { value: claims.kycVerified, salt: randomSalt() },
  };
  const commitment = fieldString(eddsa.F, await commitmentFor(privateAttributes));
  const message = await signedMessage({ commitment, issuerId, issuedAt, expiresAt });
  const signature = eddsa.signPoseidon(privateKey, message);

  return {
    version: 1,
    issuerId,
    issuedAt,
    expiresAt,
    commitment,
    issuerPublicKey: serializePublicKey(issuerPublicKey, eddsa.F),
    signature: {
      R8: serializePublicKey(signature.R8, eddsa.F),
      S: signature.S.toString(),
    },
    privateAttributes,
  };
}

export async function createPresentation(credential, disclose) {
  if (!Array.isArray(disclose) || disclose.length === 0 || disclose.some((name) => !ATTRIBUTE_NAMES.includes(name))) {
    throw new TypeError("disclose must select age and/or kycVerified.");
  }
  if (new Set(disclose).size !== disclose.length) {
    throw new TypeError("disclose cannot contain duplicate attributes.");
  }

  const attributes = credential?.privateAttributes;
  const calculatedCommitment = fieldString(
    (await getPrimitives())[0].F,
    await commitmentFor(attributes),
  );
  if (calculatedCommitment !== credential.commitment) {
    throw new Error("Credential attributes do not match the signed commitment.");
  }

  const [poseidon, eddsa] = await getPrimitives();
  const ageLeaf = await attributeLeaf("age", attributes.age.value, attributes.age.salt);
  const kycLeaf = await attributeLeaf("kycVerified", attributes.kycVerified.value, attributes.kycVerified.salt);
  const privateValues = { age: ageLeaf, kycVerified: kycLeaf };
  const presentation = {
    version: credential.version,
    issuerId: credential.issuerId,
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
    commitment: credential.commitment,
    issuerPublicKey: credential.issuerPublicKey,
    signature: credential.signature,
    disclosed: {},
  };

  for (const name of disclose) {
    const siblingName = name === "age" ? "kycVerified" : "age";
    const attribute = attributes[name];
    presentation.disclosed[name] = {
      value: attribute.value,
      salt: attribute.salt,
      index: name === "age" ? 0 : 1,
      sibling: fieldString(eddsa.F, privateValues[siblingName]),
    };
  }

  return presentation;
}

export async function verifyPresentation(presentation, trustedIssuerPublicKey, { now = Math.floor(Date.now() / 1000) } = {}) {
  const invalid = (reason) => ({ valid: false, reason });

  try {
    if (!presentation || presentation.version !== 1) return invalid("unsupported-credential-version");
    parseIssuerId(presentation.issuerId);
    toInteger(presentation.issuedAt, "issuedAt");
    toInteger(presentation.expiresAt, "expiresAt");
    toInteger(now, "now");
    if (presentation.expiresAt !== 0 && now >= presentation.expiresAt) return invalid("credential-expired");
    if (!equalPublicKeys(presentation.issuerPublicKey, trustedIssuerPublicKey)) return invalid("untrusted-issuer");
    if (!presentation.disclosed || typeof presentation.disclosed !== "object") return invalid("missing-disclosures");

    const disclosedNames = Object.keys(presentation.disclosed);
    if (disclosedNames.length === 0 || disclosedNames.some((name) => !ATTRIBUTE_NAMES.includes(name))) {
      return invalid("invalid-disclosures");
    }

    const [, eddsa] = await getPrimitives();
    const publicKey = parsePublicKey(trustedIssuerPublicKey, eddsa.F);
    const signature = parseSignature(presentation.signature, eddsa.F);
    const message = await signedMessage(presentation);
    if (!eddsa.verifyPoseidon(message, signature, publicKey)) return invalid("invalid-issuer-signature");

    const commitment = parseField(presentation.commitment, "commitment");
    const claims = {};
    for (const name of disclosedNames) {
      const disclosure = presentation.disclosed[name];
      const expectedIndex = name === "age" ? 0 : 1;
      if (!disclosure || disclosure.index !== expectedIndex) return invalid("invalid-merkle-path");
      const leaf = await attributeLeaf(name, disclosure.value, disclosure.salt);
      const sibling = parseField(disclosure.sibling, `${name} sibling`);
      const root = expectedIndex === 0
        ? await hashFields([leaf, sibling])
        : await hashFields([sibling, leaf]);
      if (eddsa.F.toObject(root) !== commitment) return invalid("attribute-not-in-credential");
      claims[name] = disclosure.value;
    }

    return { valid: true, issuerId: presentation.issuerId, claims };
  } catch {
    return invalid("malformed-presentation");
  }
}