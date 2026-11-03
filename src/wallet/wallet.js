// User wallet: holds the encrypted holder secret and issued credentials.
// The holder secret is generated here and never leaves the device in plain
// text; the KYC Authority only ever sees Poseidon(holderSecret).
import { BN254_SCALAR_FIELD } from "../prover/inputs.js";
import { DEFAULT_PBKDF2_ITERATIONS, open, seal } from "./secret-box.js";

const SECRET_KEY = "holder-secret";
const CREDENTIAL_PREFIX = "credential:";
const MIN_PASSPHRASE_LENGTH = 8;

export class WalletError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "WalletError";
    this.code = code;
  }
}

// Uniform random non-zero element of the BN254 scalar field (rejection sampling).
export function generateHolderSecret() {
  for (;;) {
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
    bytes[0] &= 0x3f; // 254 bits; the modulus is just below 2^254
    const value = BigInt(`0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`);
    if (value > 0n && value < BN254_SCALAR_FIELD) return value;
  }
}

function checkPassphrase(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new WalletError("WEAK_PASSPHRASE", `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
}

/**
 * @param storage           memoryStorage() or indexedDbStorage() from ./storage.js
 * @param verifyCredential  Issuer-signature/integrity check from the credential module. Required:
 *                          the wallet refuses to store anything it cannot verify.
 * @param iterations        PBKDF2 iterations (lower only in tests).
 */
export function createWallet({ storage, verifyCredential, iterations = DEFAULT_PBKDF2_ITERATIONS }) {
  if (!storage) throw new Error("createWallet needs a storage backend.");

  async function readSecretBox() {
    const box = await storage.get(SECRET_KEY);
    if (!box) throw new WalletError("NOT_INITIALISED", "Create the wallet first.");
    return box;
  }

  return {
    async isInitialised() {
      return (await storage.get(SECRET_KEY)) !== undefined;
    },

    async initialise(passphrase) {
      checkPassphrase(passphrase);
      if (await this.isInitialised()) throw new WalletError("ALREADY_INITIALISED", "The wallet already has a holder secret.");
      await storage.set(SECRET_KEY, await seal(generateHolderSecret().toString(), passphrase, { iterations }));
    },

    async unlock(passphrase) {
      return BigInt(await open(await readSecretBox(), passphrase));
    },

    async changePassphrase(oldPassphrase, newPassphrase) {
      checkPassphrase(newPassphrase);
      const secret = await open(await readSecretBox(), oldPassphrase);
      await storage.set(SECRET_KEY, await seal(secret, newPassphrase, { iterations }));
    },

    async importCredential(credentialOrJson) {
      if (typeof verifyCredential !== "function") {
        throw new WalletError("NO_VERIFIER", "No credential verifier is configured; refusing to import.");
      }
      let credential;
      try {
        credential = typeof credentialOrJson === "string" ? JSON.parse(credentialOrJson) : structuredClone(credentialOrJson);
      } catch {
        throw new WalletError("INVALID_CREDENTIAL", "The credential file is not valid JSON.");
      }
      const id = credential?.attributes?.credentialId;
      if (id === undefined || id === null) throw new WalletError("INVALID_CREDENTIAL", "The credential has no credentialId.");
      if (!(await verifyCredential(credential))) {
        throw new WalletError("INVALID_CREDENTIAL", "The credential failed its issuer signature check.");
      }
      await storage.set(`${CREDENTIAL_PREFIX}${id}`, { credential, importedAt: new Date().toISOString() });
      return String(id);
    },

    // Summary only: private attributes such as date of birth are not listed.
    async listCredentials() {
      const keys = (await storage.keys()).filter((key) => String(key).startsWith(CREDENTIAL_PREFIX));
      const records = await Promise.all(keys.map((key) => storage.get(key)));
      return records.map(({ credential, importedAt }) => ({
        id: String(credential.attributes.credentialId),
        issuer: credential.issuer,
        expiry: credential.attributes.expiry,
        importedAt,
      }));
    },

    async getCredential(id) {
      const record = await storage.get(`${CREDENTIAL_PREFIX}${id}`);
      if (!record) throw new WalletError("NOT_FOUND", `No credential with id ${id}.`);
      return record.credential;
    },

    async exportCredential(id) {
      return JSON.stringify(await this.getCredential(id), null, 2);
    },

    async removeCredential(id) {
      await storage.delete(`${CREDENTIAL_PREFIX}${id}`);
    },
  };
}
