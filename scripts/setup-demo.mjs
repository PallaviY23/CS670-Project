import { rm } from "node:fs/promises";
import { resolve } from "node:path";
import { circuitPaths, setupCircuit, terminateCurves, writeManifest } from "../src/prover/setup.js";

const circuit = process.env.CIRCUIT ?? "kyc_presentation";
const circuitDir = resolve("build/circuit");
const { r1csPath, wasmPath, symPath } = circuitPaths(circuit, circuitDir);
const zkeyPath = resolve(circuitDir, `${circuit}_final.zkey`);
const verificationKeyPath = resolve(circuitDir, "verification_key.json");
const manifestPath = resolve(circuitDir, "manifest.json");
const logger = { ...console, debug() {} };

for (const stale of [zkeyPath, verificationKeyPath, manifestPath]) await rm(stale, { force: true });

console.log("Creating local development-only Groth16 setup...");
const { info, ptau, setupMs } = await setupCircuit({ r1csPath, zkeyPath, verificationKeyPath, logger });
const manifest = await writeManifest({
  manifestPath,
  circuit,
  protocol: "groth16",
  info,
  ptau,
  setupMs,
  r1csPath,
  wasmPath,
  symPath,
  zkeyPath,
  verificationKeyPath,
});
await terminateCurves();

console.log(`Circuit ${circuit}: ${manifest.constraints} constraints, public signals [${manifest.publicSignals.join(", ")}].`);
console.log(`Powers of Tau: ${manifest.ptau.file} (${manifest.ptau.source}). Setup took ${setupMs} ms.`);
console.log("Proving key verified against the circuit. Artifacts and manifest are ready under build/circuit.");
