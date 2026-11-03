// Minimal witness-test harness: compiles a circuit once (circom2, wasm)
// and runs the witness calculator. A constraint violation throws.
import { runCircom } from "../../scripts/circom.mjs";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";

const require = createRequire(import.meta.url);
const OUT = "build/circuit-tests";

export async function loadCircuit(file) {
  const name = path.basename(file, ".circom");
  const dir = path.join(OUT, name);
  const wasm = path.join(dir, `${name}_js`, `${name}.wasm`);
  if (!fs.existsSync(wasm) || fs.statSync(wasm).mtimeMs < newestSource()) {
    fs.mkdirSync(dir, { recursive: true });
    // forward slashes: required by the circom2 (WASI) fallback, harmless for native circom
    const fwd = (p) => p.split(path.sep).join("/");
    runCircom(`${fwd(file)} --wasm -l node_modules -l circuits -o ${fwd(dir)}`);
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

function newestSource() {
  let t = 0;
  for (const d of ["circuits", "circuits/lib", "test/circuits"])
    if (fs.existsSync(d)) for (const f of fs.readdirSync(d))
      if (f.endsWith(".circom")) t = Math.max(t, fs.statSync(path.join(d, f)).mtimeMs);
  return t;
}
