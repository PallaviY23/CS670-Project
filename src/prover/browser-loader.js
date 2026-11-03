// Browser-side loading of prover artifacts. Downloads happen once: artifacts
// are kept in the Cache API keyed by their manifest hash, and every copy
// (fresh or cached) is checked against the manifest before use.
import { ArtifactIntegrityError, assertArtifact } from "./artifacts.js";

const CACHE_NAME = "kyc-prover-artifacts-v1";

export const DEFAULT_ARTIFACT_URLS = Object.freeze({
  manifest: "/api/prover/manifest",
  wasm: "/api/prover/wasm",
  zkey: "/api/prover/zkey",
});

async function openCache() {
  try {
    return typeof caches === "undefined" ? null : await caches.open(CACHE_NAME);
  } catch {
    return null;
  }
}

async function fetchBytes(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`Could not download ${url} (HTTP ${response.status}).`);
  return new Uint8Array(await response.arrayBuffer());
}

async function loadArtifact(name, url, entry, cache) {
  const cacheKey = `${new URL(url, globalThis.location?.href).href}#sha256=${entry.sha256}`;
  const cached = await cache?.match(cacheKey).catch(() => undefined);
  if (cached) {
    const bytes = new Uint8Array(await cached.arrayBuffer());
    try {
      return { bytes: await assertArtifact(name, bytes, entry), fromCache: true };
    } catch (error) {
      if (!(error instanceof ArtifactIntegrityError)) throw error;
      await cache.delete(cacheKey);
    }
  }

  const bytes = await assertArtifact(name, await fetchBytes(url), entry);
  await cache?.put(cacheKey, new Response(bytes)).catch(() => {});
  return { bytes, fromCache: false };
}

export async function loadProverArtifacts(urls = DEFAULT_ARTIFACT_URLS) {
  const startedAt = performance.now();
  const response = await fetch(urls.manifest, { cache: "no-store" });
  if (!response.ok) throw new Error("Proving artifacts are not ready. Run npm run setup:demo.");
  const manifest = await response.json();
  const cache = await openCache();
  const [wasm, zkey] = await Promise.all([
    loadArtifact("wasm", urls.wasm, manifest.artifacts.wasm, cache),
    loadArtifact("zkey", urls.zkey, manifest.artifacts.zkey, cache),
  ]);
  return {
    manifest,
    wasm: wasm.bytes,
    zkey: zkey.bytes,
    loadMs: Number((performance.now() - startedAt).toFixed(2)),
    fromCache: wasm.fromCache && zkey.fromCache,
  };
}
