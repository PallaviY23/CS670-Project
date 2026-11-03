// Passphrase-based encryption for wallet secrets (PBKDF2-SHA256 + AES-256-GCM).
// Uses WebCrypto, so it runs unchanged in browsers and Node 20+.

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const BOX_VERSION = 1;
const ADDITIONAL_DATA = new TextEncoder().encode("cs670-kyc-wallet/secret-box/v1");

export class WalletLockedError extends Error {
  constructor() {
    super("Incorrect passphrase, or the stored secret has been modified.");
    this.name = "WalletLockedError";
    this.code = "WALLET_LOCKED";
  }
}

const subtle = () => globalThis.crypto.subtle;
const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
const fromBase64 = (text) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));

async function deriveKey(passphrase, salt, iterations) {
  const material = await subtle().importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function seal(plaintext, passphrase, { iterations = DEFAULT_PBKDF2_ITERATIONS } = {}) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, iterations);
  const ciphertext = await subtle().encrypt(
    { name: "AES-GCM", iv, additionalData: ADDITIONAL_DATA },
    key,
    new TextEncoder().encode(plaintext),
  );
  return {
    version: BOX_VERSION,
    kdf: "PBKDF2-SHA256",
    iterations,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };
}

export async function open(box, passphrase) {
  if (box?.version !== BOX_VERSION || box.kdf !== "PBKDF2-SHA256") throw new Error("Unsupported secret format.");
  try {
    const key = await deriveKey(passphrase, fromBase64(box.salt), box.iterations);
    const plaintext = await subtle().decrypt(
      { name: "AES-GCM", iv: fromBase64(box.iv), additionalData: ADDITIONAL_DATA },
      key,
      fromBase64(box.ciphertext),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new WalletLockedError();
  }
}
