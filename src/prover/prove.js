// Proof generation with separately timed witness and proving steps.
// Runs in Node and in browsers; `wasm` and `zkey` may be file paths (Node),
// URLs or Uint8Arrays.
import * as snarkjs from "snarkjs";

const PROTOCOLS = new Set(["groth16", "plonk", "fflonk"]);
const FIELD_ELEMENT_BYTES = 32;

const elapsed = (start) => Number((performance.now() - start).toFixed(2));

function backendFor(protocol) {
  if (!PROTOCOLS.has(protocol)) throw new Error(`Unsupported proof system "${protocol}".`);
  return snarkjs[protocol];
}

function countFieldElements(value) {
  if (typeof value === "string") return 1;
  // Points are serialised in projective form; the affine encoding needs
  // two coordinates for G1 and four for G2.
  if (Array.isArray(value)) return Array.isArray(value[0]) ? 4 : 2;
  return Object.entries(value)
    .filter(([key]) => key !== "protocol" && key !== "curve")
    .reduce((total, [, entry]) => total + countFieldElements(entry), 0);
}

// `raw` is the uncompressed affine encoding (256 bytes for Groth16 on BN254);
// `json` is what is actually sent to the verifier.
export function proofSize(proof) {
  return {
    raw: countFieldElements(proof) * FIELD_ELEMENT_BYTES,
    json: new TextEncoder().encode(JSON.stringify(proof)).length,
  };
}

export async function prove(input, { wasm, zkey, protocol = "groth16", onProgress } = {}) {
  const backend = backendFor(protocol);
  const witness = { type: "mem" };

  onProgress?.("witness");
  const witnessStart = performance.now();
  await snarkjs.wtns.calculate(input, wasm, witness);
  const witnessMs = elapsed(witnessStart);

  onProgress?.("proof");
  const provingStart = performance.now();
  const { proof, publicSignals } = await backend.prove(zkey, witness);
  const provingMs = elapsed(provingStart);

  return {
    proof,
    publicSignals,
    timings: { witnessMs, provingMs, totalMs: Number((witnessMs + provingMs).toFixed(2)) },
    proofBytes: proofSize(proof),
  };
}

export async function verify(verificationKey, publicSignals, proof) {
  const backend = backendFor(verificationKey.protocol);
  const start = performance.now();
  const valid = await backend.verify(verificationKey, publicSignals, proof);
  return { valid, verificationMs: elapsed(start) };
}
