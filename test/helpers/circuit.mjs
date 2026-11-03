// Minimal witness-test harness: compiles a circuit once (circom2, wasm)
// and runs the witness calculator. A constraint violation throws.
import { runCircom } from "../../scripts/circom.mjs";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const OUT = "build/circuit-tests";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CIRCUITS = path.join(ROOT, "circuits");
const NODE_MODULES = path.join(ROOT, "node_modules");
const compilations = new Map();

export async function loadCircuit(file) {
  const name = path.basename(file, ".circom");
  const dir = path.join(OUT, name);
  const wasm = path.join(dir, `${name}_js`, `${name}.wasm`);
  if (!fs.existsSync(wasm) || fs.statSync(wasm).mtimeMs < newestSource(file)) {
    let compilation = compilations.get(name);
    if (!compilation) {
      compilation = compileCircuit(file, name, dir);
      compilations.set(name, compilation);
    }
    try {
      await compilation;
    } finally {
      compilations.delete(name);
    }
  }
  // circom emits CommonJS; keep it CommonJS even if the repo is "type": "module"
  fs.writeFileSync(path.join(dir, `${name}_js`, "package.json"), '{"type":"commonjs"}');
  const builder = require(path.resolve(dir, `${name}_js`, "witness_calculator.js"));
  const wc = await builder(fs.readFileSync(wasm));
  return {
    // returns the witness (array of bigint); witness[1..] = outputs then public inputs
    witness: (input) => wc.calculateWitness(input, true),
  };
}

async function compileCircuit(file, name, dir) {
  fs.mkdirSync(dir, { recursive: true });
  const source = path.resolve(ROOT, file);
  const relative = (target) => path.relative(CIRCUITS, target).split(path.sep).join("/");
  const output = relative(path.resolve(dir));
  const tempSource = path.join(CIRCUITS, `${name}.circom`);
  const sourceInCircuits = source.startsWith(`${CIRCUITS}${path.sep}`);
  const input = sourceInCircuits ? relative(source) : path.basename(tempSource);

  if (!sourceInCircuits) {
    if (fs.existsSync(tempSource)) throw new Error(`Temporary circuit path already exists: ${tempSource}`);
    const contents = fs.readFileSync(source, "utf8").replaceAll("../../circuits/", "");
    fs.writeFileSync(tempSource, contents);
  }
  try {
    runCircom(`${input} --wasm -l ${relative(NODE_MODULES)} -l . -o ${output}`, { cwd: CIRCUITS });
  } finally {
    if (!sourceInCircuits) fs.rmSync(tempSource, { force: true });
  }
}

function newestSource(file) {
  let t = 0;
  const source = path.resolve(ROOT, file);
  const sourceDir = path.dirname(source);
  const dirs = source.startsWith(`${CIRCUITS}${path.sep}`)
    ? [CIRCUITS, path.join(CIRCUITS, "lib")]
    : [sourceDir, CIRCUITS, path.join(CIRCUITS, "lib")];
  for (const dir of dirs) {
    if (fs.existsSync(dir)) {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isFile() && entry.name.endsWith(".circom")) {
          t = Math.max(t, fs.statSync(path.join(dir, entry.name)).mtimeMs);
        }
      }
    }
  }
  return t;
}
