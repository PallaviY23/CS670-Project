// npm run compile -> build/circuit/kyc_presentation.{r1cs,sym} + wasm
import fs from "node:fs";
import path from "node:path";
import { runCircom } from "./circom.mjs";
fs.mkdirSync("build/circuit", { recursive: true });
console.log(runCircom("kyc_presentation.circom --r1cs --wasm --sym --O2 -l ../node_modules -l . -o ../build/circuit", {
  cwd: path.resolve("circuits"),
}));
