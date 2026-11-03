// Node proving benchmark and proof-system comparison.
//   node scripts/bench.mjs [--runs 30] [--warmup 3] [--protocols groth16,plonk,fflonk]
//                          [--circuit kyc_presentation] [--input input.json]
// Requires a compiled circuit in build/circuit (npm run circuit:presentation,
// or npm run circuit:build for the starter kyc_claims circuit).
import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { prove, verify } from "../src/prover/prove.js";
import { circuitPaths, setupCircuit, terminateCurves } from "../src/prover/setup.js";
import { defaultBenchInput } from "./lib/presentation-input.mjs";
import { hostInfo, parseOptions, summarizeSamples, timestamp, writeCsv, writeJson } from "./lib/bench-utils.mjs";

const options = parseOptions({
  runs: { type: "string", default: "30" },
  warmup: { type: "string", default: "3" },
  protocols: { type: "string", default: "groth16" },
  circuit: { type: "string", default: "kyc_presentation" },
  input: { type: "string" },
});
const runs = Number(options.runs);
const warmup = Number(options.warmup);
const protocols = options.protocols.split(",").map((protocol) => protocol.trim());
const { circuit } = options;

const { r1csPath, wasmPath } = circuitPaths(circuit, resolve("build/circuit"));
if (!existsSync(r1csPath) || !existsSync(wasmPath)) {
  console.error(`No compiled ${circuit} circuit in build/circuit. Run npm run circuit:presentation first.`);
  process.exit(1);
}
const input = options.input ? JSON.parse(await readFile(options.input, "utf8")) : await defaultBenchInput(circuit);
if (!input) {
  console.error("Pass --input <file.json> with a valid witness input for this circuit.");
  process.exit(1);
}
const wasm = new Uint8Array(await readFile(wasmPath));

const results = [];
const runRows = [];

for (const protocol of protocols) {
  const dir = resolve("build/bench", circuit, protocol);
  const zkeyPath = resolve(dir, `${circuit}.zkey`);
  const verificationKeyPath = resolve(dir, "verification_key.json");

  console.log(`\n[${protocol}] setup...`);
  const { info, ptau, setupMs } = await setupCircuit({ protocol, r1csPath, zkeyPath, verificationKeyPath });
  const zkey = new Uint8Array(await readFile(zkeyPath));
  const verificationKey = JSON.parse(await readFile(verificationKeyPath, "utf8"));

  console.log(`[${protocol}] ${warmup} warm-up + ${runs} measured proofs...`);
  const samples = [];
  let proofBytes;
  for (let i = 0; i < warmup + runs; i += 1) {
    const result = await prove(input, { wasm, zkey, protocol });
    const { valid, verificationMs } = await verify(verificationKey, result.publicSignals, result.proof);
    if (!valid) throw new Error(`${protocol} proof failed verification on run ${i}.`);
    proofBytes = result.proofBytes;
    if (i >= warmup) {
      const sample = { ...result.timings, verificationMs };
      samples.push(sample);
      runRows.push({ protocol, run: i - warmup + 1, ...sample });
    }
  }

  results.push({
    protocol,
    constraints: info.nConstraints,
    publicSignals: info.nOutputs + info.nPubInputs,
    ptauPower: ptau.power,
    setupMs,
    zkeyBytes: (await stat(zkeyPath)).size,
    verificationKeyBytes: (await stat(verificationKeyPath)).size,
    wasmBytes: wasm.byteLength,
    proofRawBytes: proofBytes.raw,
    proofJsonBytes: proofBytes.json,
    timings: summarizeSamples(samples, ["witnessMs", "provingMs", "totalMs", "verificationMs"]),
  });
}
await terminateCurves();

const stamp = timestamp();
const outDir = resolve("build/bench");
const report = { kind: "node-prover", circuit, runs, warmup, host: hostInfo(), generatedAt: new Date().toISOString(), results };
await writeJson(resolve(outDir, `node-${circuit}-${stamp}.json`), report);
await writeCsv(resolve(outDir, `node-${circuit}-${stamp}-runs.csv`), runRows);
await writeCsv(resolve(outDir, `node-${circuit}-${stamp}-summary.csv`), results.map((result) => ({
  protocol: result.protocol,
  constraints: result.constraints,
  ptauPower: result.ptauPower,
  setupMs: result.setupMs,
  zkeyBytes: result.zkeyBytes,
  verificationKeyBytes: result.verificationKeyBytes,
  proofRawBytes: result.proofRawBytes,
  proofJsonBytes: result.proofJsonBytes,
  witnessMeanMs: result.timings.witnessMs.mean,
  provingMeanMs: result.timings.provingMs.mean,
  provingMedianMs: result.timings.provingMs.median,
  provingP95Ms: result.timings.provingMs.p95,
  verificationMeanMs: result.timings.verificationMs.mean,
  verificationP95Ms: result.timings.verificationMs.p95,
})));

console.log(`\nHost: ${report.host.cpu} (${report.host.cores} threads), Node ${report.host.node}`);
console.table(results.map((result) => ({
  protocol: result.protocol,
  constraints: result.constraints,
  "proof B": result.proofRawBytes,
  "zkey KB": Number((result.zkeyBytes / 1024).toFixed(1)),
  "witness ms": result.timings.witnessMs.mean,
  "prove ms (mean)": result.timings.provingMs.mean,
  "prove ms (p95)": result.timings.provingMs.p95,
  "verify ms (mean)": result.timings.verificationMs.mean,
})));
console.log(`Results written to build/bench/node-${circuit}-${stamp}*.`);
process.exit(0);
