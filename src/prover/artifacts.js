// Artifact integrity helpers. Runs in Node 20+ and browsers (WebCrypto).

export class ArtifactIntegrityError extends Error {
  constructor(name, expected, actual) {
    super(`Prover artifact "${name}" does not match the build manifest.`);
    this.name = "ArtifactIntegrityError";
    this.code = "ARTIFACT_HASH_MISMATCH";
    this.artifact = name;
    this.expected = expected;
    this.actual = actual;
  }
}

export async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function assertArtifact(name, bytes, manifestEntry) {
  if (!manifestEntry?.sha256) throw new Error(`The build manifest has no entry for "${name}".`);
  const actual = await sha256Hex(bytes);
  if (actual !== manifestEntry.sha256) throw new ArtifactIntegrityError(name, manifestEntry.sha256, actual);
  return bytes;
}
