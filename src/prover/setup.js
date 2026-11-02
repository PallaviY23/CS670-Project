// Node-only trusted-setup and manifest helpers shared by setup-demo, the
// benchmarks and the prover tests.
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, dirname, relative, resolve } from "node:path";
import * as snarkjs from "snarkjs";
import { sha256Hex } from "./artifacts.js";

export const MIN_PTAU_POWER = 12;
export const MAX_PTAU_POWER = 20;
export const DEFAULT_PTAU_DIR = resolve("build/ptau");

const silentLogger = { debug() {}, info() {}, warn() {}, error() {} };
const entropy = () => randomBytes(32).toString("hex");
// snarkjs does not export its package.json, so read it next to the resolved entry point.
const snarkjsVersion = JSON.parse(
  readFileSync(resolve(dirname(createRequire(import.meta.url).resolve("snarkjs")), "../package.json"), "utf8"),
).version;

export async function readCircuitInfo(r1csPath) {
  const { nConstraints, nVars, nPrvInputs, nPubInputs, nOutputs } = await snarkjs.r1cs.info(r1csPath);
  return { nConstraints, nVars, nPrvInputs, nPubInputs, nOutputs };
}

// Mirrors the domain-size rule in snarkjs zKey.newZKey.
export function groth16RequiredPower({ nConstraints, nPubInputs, nOutputs }) {
  const size = nConstraints + nPubInputs + nOutputs;
  return Math.max(MIN_PTAU_POWER, Math.floor(Math.log2(size)) + 1);
}

function ptauPathFor(dir, power) {
  return resolve(dir, `pot${power}_final.ptau`);
}

async function findCachedPtau(dir, power) {
  if (!existsSync(dir)) return null;
  const powers = (await readdir(dir))
    .map((name) => /^pot(\d+)_final\.ptau$/.exec(name)?.[1])
    .filter(Boolean)
    .map(Number)
    .filter((cached) => cached >= power)
    .sort((a, b) => a - b);
  return powers.length ? { path: ptauPathFor(dir, powers[0]), power: powers[0] } : null;
}

// Returns a prepared Powers of Tau file of at least `power`. An external file
// (for example the public Hermez ceremony) can be supplied with PTAU_FILE;
// otherwise a development-only ceremony is generated once and cached.
export async function ensurePtau(power, { dir = DEFAULT_PTAU_DIR, logger = silentLogger } = {}) {
  if (process.env.PTAU_FILE) {
    return { path: resolve(process.env.PTAU_FILE), power: null, source: "external" };
  }

  const cached = await findCachedPtau(dir, power);
  if (cached) return { ...cached, source: "cache" };

  await mkdir(dir, { recursive: true });
  const finalPath = ptauPathFor(dir, power);
  const initial = `${finalPath}.0000.tmp`;
  const contributed = `${finalPath}.0001.tmp`;
  const prepared = `${finalPath}.prepared.tmp`;

  logger.info(`Generating development-only Powers of Tau (2^${power})...`);
  const curve = await snarkjs.curves.getCurveFromName("bn128");
  await snarkjs.powersOfTau.newAccumulator(curve, power, initial, logger);
  await snarkjs.powersOfTau.contribute(initial, contributed, "Local dev contribution", entropy(), logger);
  await snarkjs.powersOfTau.preparePhase2(contributed, prepared, logger);
  // Rename last so an interrupted run never leaves a usable-looking cache file.
  await rename(prepared, finalPath);
  await rm(initial, { force: true });
  await rm(contributed, { force: true });

  return { path: finalPath, power, source: "generated" };
}

async function setupGroth16(r1csPath, ptauPath, zkeyPath, logger) {
  const initialZkey = `${zkeyPath}.0000.tmp`;
  const created = await snarkjs.zKey.newZKey(r1csPath, ptauPath, initialZkey, logger);
  if (created === -1) throw new Error("Groth16 key generation failed (Powers of Tau too small?).");

  await snarkjs.zKey.contribute(initialZkey, zkeyPath, "Local dev proving key contribution", entropy(), logger);
  await rm(initialZkey, { force: true });

  const valid = await snarkjs.zKey.verifyFromR1cs(r1csPath, ptauPath, zkeyPath, logger);
  if (!valid) throw new Error("Generated proving key does not match the circuit and Powers of Tau.");
}

async function setupUniversal(protocol, r1csPath, ptauPath, zkeyPath, logger) {
  const result = await snarkjs[protocol].setup(r1csPath, ptauPath, zkeyPath, logger);
  if (result === -1) throw new Error(`${protocol} setup failed (Powers of Tau too small?).`);
}

// Creates a proving key and verification key for `protocol`. PLONK and FFLONK
// need a larger domain than Groth16 that snarkjs only reports by failing, so
// the Powers of Tau size is raised until setup succeeds.
export async function setupCircuit({
  protocol = "groth16",
  r1csPath,
  zkeyPath,
  verificationKeyPath,
  ptauDir = DEFAULT_PTAU_DIR,
  logger = silentLogger,
}) {
  const info = await readCircuitInfo(r1csPath);
  await mkdir(dirname(zkeyPath), { recursive: true });
  const startedAt = performance.now();
  let power = groth16RequiredPower(info);

  for (;;) {
    const ptau = await ensurePtau(power, { dir: ptauDir, logger });
    try {
      if (protocol === "groth16") await setupGroth16(r1csPath, ptau.path, zkeyPath, logger);
      else await setupUniversal(protocol, r1csPath, ptau.path, zkeyPath, logger);
    } catch (error) {
      await rm(zkeyPath, { force: true });
      if (ptau.source === "external" || ptau.power >= MAX_PTAU_POWER) throw error;
      power = ptau.power + 1;
      logger.info(`${protocol} setup needs a larger Powers of Tau; retrying with 2^${power}.`);
      continue;
    }

    const verificationKey = await snarkjs.zKey.exportVerificationKey(zkeyPath, logger);
    await writeFile(verificationKeyPath, `${JSON.stringify(verificationKey, null, 2)}\n`);
    return { info, ptau, setupMs: Number((performance.now() - startedAt).toFixed(2)) };
  }
}

// Public signal names in snarkjs order (outputs, then public inputs), read
// from the .sym file so the manifest follows the circuit automatically.
export async function readPublicSignalNames(symPath, { nOutputs, nPubInputs }) {
  const count = nOutputs + nPubInputs;
  const names = new Array(count).fill(null);
  for (const line of (await readFile(symPath, "utf8")).split(/\r?\n/)) {
    const [, wire, , name] = line.split(",");
    const index = Number(wire);
    if (index >= 1 && index <= count && name?.startsWith("main.") && names[index - 1] === null) {
      names[index - 1] = name.slice("main.".length);
    }
  }
  return names;
}

async function describeFile(path, baseDir) {
  const bytes = await readFile(path);
  return {
    file: relative(baseDir, path).split("\\").join("/"),
    bytes: (await stat(path)).size,
    sha256: await sha256Hex(bytes),
  };
}

export async function writeManifest({
  manifestPath,
  circuit,
  protocol,
  info,
  ptau,
  setupMs,
  r1csPath,
  wasmPath,
  symPath,
  zkeyPath,
  verificationKeyPath,
}) {
  const baseDir = dirname(manifestPath);
  const manifest = {
    manifestVersion: 1,
    circuit,
    protocol,
    curve: "bn128",
    generatedAt: new Date().toISOString(),
    snarkjsVersion,
    constraints: info.nConstraints,
    wires: info.nVars,
    privateInputs: info.nPrvInputs,
    publicInputs: info.nPubInputs,
    outputs: info.nOutputs,
    publicSignals: await readPublicSignalNames(symPath, info),
    ptau: { file: basename(ptau.path), power: ptau.power, source: ptau.source },
    setupMs,
    artifacts: {
      r1cs: await describeFile(r1csPath, baseDir),
      wasm: await describeFile(wasmPath, baseDir),
      zkey: await describeFile(zkeyPath, baseDir),
      verificationKey: await describeFile(verificationKeyPath, baseDir),
    },
  };
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

// Standard locations of a compiled circuit inside a build directory.
export function circuitPaths(circuit, dir) {
  return {
    r1csPath: resolve(dir, `${circuit}.r1cs`),
    wasmPath: resolve(dir, `${circuit}_js/${circuit}.wasm`),
    symPath: resolve(dir, `${circuit}.sym`),
  };
}

export async function terminateCurves() {
  await globalThis.curve_bn128?.terminate?.();
  delete globalThis.curve_bn128;
}
