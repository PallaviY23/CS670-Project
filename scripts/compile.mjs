// npm run compile -> build/circuit/kyc_presentation.{r1cs,sym} + wasm
import fs from "node:fs";
import path from "node:path";
import { runCircom } from "./circom.mjs";
fs.mkdirSync("build/circuit", { recursive: true });
// Remove the previous build first: circom2 (WASI) on Windows can hang when
// overwriting existing output. setup-demo.mjs regenerates the keys afterwards.
for (const output of ["kyc_presentation_js", "kyc_presentation.r1cs", "kyc_presentation.sym"]) {
  fs.rmSync(path.join("build/circuit", output), { recursive: true, force: true });
}
console.log(runCircom("kyc_presentation.circom --r1cs --wasm --sym --O2 -l ../node_modules -l . -o ../build/circuit", {
  cwd: path.resolve("circuits"),
}));
