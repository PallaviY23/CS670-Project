// Cost of the building blocks the credential-bound circuit will need:
// Poseidon Merkle inclusion at several depths (credential tree, revocation
// tree) and EdDSA-Poseidon issuer signature verification.
//   node scripts/bench-components.mjs [--runs 10] [--depths 3,10,16,20]
// These are reference circuits for measurement only; the production
// templates live in circuits/ (circuit owner).
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { promisify } from "node:util";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { prove, verify } from "../src/prover/prove.js";
import { circuitPaths, setupCircuit, terminateCurves } from "../src/prover/setup.js";
import { generateHolderSecret as randomFieldElement } from "../src/wallet/wallet.js";
import { hostInfo, parseOptions, summarizeSamples, timestamp, writeCsv, writeJson } from "./lib/bench-utils.mjs";

const options = parseOptions({
  runs: { type: "string", default: "10" },
  warmup: { type: "string", default: "2" },
  depths: { type: "string", default: "3,10,16,20" },
});
const runs = Number(options.runs);
const warmup = Number(options.warmup);
const depths = options.depths.split(",").map(Number);
const root = resolve("build/bench/components");
const run = promisify(execFile);

const merkleSource = (depth) => `pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";

template MerkleInclusion(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input pathIndices[depth];
    signal input root;

    signal hashes[depth + 1];
    signal left[depth];
    signal right[depth];
    component hashers[depth];
    hashes[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        left[i] <== hashes[i] + pathIndices[i] * (siblings[i] - hashes[i]);
        right[i] <== siblings[i] + pathIndices[i] * (hashes[i] - siblings[i]);
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        hashes[i + 1] <== hashers[i].out;
    }
    root === hashes[depth];
}

component main {public [root]} = MerkleInclusion(${depth});
`;

const eddsaSource = `pragma circom 2.1.6;
include "circomlib/circuits/eddsaposeidon.circom";

component main {public [Ax, Ay]} = EdDSAPoseidonVerifier();
`;

const poseidon = await buildPoseidon();
const eddsa = await buildEddsa();
const hash2 = (a, b) => poseidon.F.toObject(poseidon([a, b]));

function merkleInput(depth) {
  const leaf = randomFieldElement();
  const siblings = Array.from({ length: depth }, () => randomFieldElement());
  const pathIndices = Array.from({ length: depth }, (_, i) => i % 2);
  let node = leaf;
  for (let i = 0; i < depth; i += 1) node = pathIndices[i] ? hash2(siblings[i], node) : hash2(node, siblings[i]);
  return { leaf, siblings, pathIndices, root: node };
}

function eddsaInput() {
  const { F } = eddsa.babyJub;
  const privateKey = randomBytes(32);
  const publicKey = eddsa.prv2pub(privateKey);
  const message = randomFieldElement();
  const signature = eddsa.signPoseidon(privateKey, F.e(message));
  if (!eddsa.verifyPoseidon(F.e(message), signature, publicKey)) throw new Error("circomlibjs produced an invalid signature.");
  return {
    enabled: 1,
    Ax: F.toObject(publicKey[0]),
    Ay: F.toObject(publicKey[1]),
    R8x: F.toObject(signature.R8[0]),
    R8y: F.toObject(signature.R8[1]),
    S: signature.S,
    M: message,
  };
}

const components = [
  ...depths.map((depth) => ({ name: `merkle_d${depth}`, label: `Poseidon Merkle inclusion, depth ${depth}`, source: merkleSource(depth), input: () => merkleInput(depth) })),
  { name: "eddsa_poseidon", label: "EdDSA-Poseidon signature check", source: eddsaSource, input: eddsaInput },
];

const toPosix = (from, to) => relative(from, to).split("\\").join("/");
const results = [];
const runRows = [];

for (const component of components) {
  const dir = resolve(root, component.name);
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  const sourcePath = resolve(dir, `${component.name}.circom`);
  await writeFile(sourcePath, component.source);

  console.log(`\n[${component.name}] compiling...`);
  // circom2 (WASI) only writes reliably into its working directory.
  const toProjectRoot = toPosix(dir, process.cwd());
  await run(process.execPath, [
    `${toProjectRoot}/node_modules/circom2/cli.js`, `${component.name}.circom`, "--r1cs", "--wasm", "--sym",
    "-l", `${toProjectRoot}/node_modules`, "-o", ".",
  ], { cwd: dir });

  const { r1csPath, wasmPath } = circuitPaths(component.name, dir);
  const zkeyPath = resolve(dir, `${component.name}.zkey`);
  const verificationKeyPath = resolve(dir, "verification_key.json");
  const { info, ptau, setupMs } = await setupCircuit({ r1csPath, zkeyPath, verificationKeyPath });
  const wasm = new Uint8Array(await readFile(wasmPath));
  const zkey = new Uint8Array(await readFile(zkeyPath));
  const verificationKey = JSON.parse(await readFile(verificationKeyPath, "utf8"));

  console.log(`[${component.name}] ${info.nConstraints} constraints; ${warmup} warm-up + ${runs} measured proofs...`);
  const samples = [];
  for (let i = 0; i < warmup + runs; i += 1) {
    const result = await prove(component.input(), { wasm, zkey });
    const { valid, verificationMs } = await verify(verificationKey, result.publicSignals, result.proof);
    if (!valid) throw new Error(`${component.name} proof failed verification.`);
    if (i >= warmup) {
      samples.push({ ...result.timings, verificationMs });
      runRows.push({ component: component.name, run: i - warmup + 1, ...result.timings, verificationMs });
    }
  }

  results.push({
    component: component.name,
    description: component.label,
    constraints: info.nConstraints,
    ptauPower: ptau.power,
    setupMs,
    zkeyBytes: (await stat(zkeyPath)).size,
    timings: summarizeSamples(samples, ["witnessMs", "provingMs", "totalMs", "verificationMs"]),
  });
}
await terminateCurves();

const stamp = timestamp();
const report = { kind: "components", runs, warmup, host: hostInfo(), generatedAt: new Date().toISOString(), results };
await writeJson(resolve("build/bench", `components-${stamp}.json`), report);
await writeCsv(resolve("build/bench", `components-${stamp}-runs.csv`), runRows);
await writeCsv(resolve("build/bench", `components-${stamp}-summary.csv`), results.map((result) => ({
  component: result.component,
  constraints: result.constraints,
  ptauPower: result.ptauPower,
  zkeyBytes: result.zkeyBytes,
  witnessMeanMs: result.timings.witnessMs.mean,
  provingMeanMs: result.timings.provingMs.mean,
  provingP95Ms: result.timings.provingMs.p95,
  verificationMeanMs: result.timings.verificationMs.mean,
})));

console.log(`\nHost: ${report.host.cpu} (${report.host.cores} threads), Node ${report.host.node}`);
console.table(results.map((result) => ({
  component: result.component,
  constraints: result.constraints,
  "zkey KB": Number((result.zkeyBytes / 1024).toFixed(1)),
  "witness ms": result.timings.witnessMs.mean,
  "prove ms (mean)": result.timings.provingMs.mean,
  "prove ms (p95)": result.timings.provingMs.p95,
  "verify ms": result.timings.verificationMs.mean,
})));
console.log(`Results written to build/bench/components-${stamp}*.`);
process.exit(0);
