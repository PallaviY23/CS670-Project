// V6: per-component constraint table (circom --O2, non-linear constraints).
// Usage: node scripts/constraints.mjs   -> prints a markdown table and writes
// build/constraints.md. Works on Windows (forward slashes only).
import { runCircom } from "./circom.mjs";
import fs from "node:fs";

const OUT = "build/constraints";
fs.mkdirSync(OUT, { recursive: true });

const pre = `pragma circom 2.1.6;\n`;
const cases = {
  "AttributeLeaf (x5)": [5, `include "circuits/lib/attribute_leaf.circom";
template T(){ signal input v; signal input s; signal output o;
 component l = AttributeLeaf(1); l.value <== v; l.salt <== s; o <== l.leaf; }
component main = T();`],
  "CredentialRoot8 (tree of 8)": [1, `include "circuits/lib/merkle.circom";
template T(){ signal input l[8]; signal output r;
 component c = CredentialRoot8(); for (var i=0;i<8;i++) c.leaves[i] <== l[i]; r <== c.root; }
component main = T();`],
  "IssuerSignature (EdDSA-Poseidon)": [1, `include "circuits/lib/signature.circom";
component main = IssuerSignature();`],
  "RevocationMembership(16)": [1, `include "circuits/RevocationMembership.circom";
component main = RevocationMembership(16);`],
  "DateRange (x4)": [4, `include "circuits/lib/dates.circom";
template T(){ signal input d; component r = DateRange(); r.in <== d; }
component main = T();`],
  "AgeAtLeast": [1, `include "circuits/lib/dates.circom";
template T(){ signal input a; signal input b; signal input c;
 component g = AgeAtLeast(); g.dob <== a; g.currentDate <== b; g.minAgeOffset <== c; }
component main = T();`],
  "NotExpired": [1, `include "circuits/lib/dates.circom";
template T(){ signal input a; signal input b;
 component g = NotExpired(); g.expiry <== a; g.currentDate <== b; }
component main = T();`],
  "HolderBinding": [1, `include "circuits/lib/holder.circom";
template T(){ signal input s; signal output o; component h = HolderBinding(); h.holderSecret <== s; o <== h.holderCommitment; }
component main = T();`],
  "Nullifier": [1, `include "circuits/lib/holder.circom";
template T(){ signal input s; signal input p; signal output o; component n = Nullifier(); n.holderSecret <== s; n.spId <== p; o <== n.nullifier; }
component main = T();`],
};

function count(name, src) {
  const f = `${OUT}/${name}.circom`;
  fs.writeFileSync(f, pre + src);
  const out = runCircom(`${f} --r1cs --O2 -l node_modules -l . -o ${OUT}`);
  return Number(out.match(/non-linear constraints: (\d+)/)[1]);
}
function countFile(f) {
  const out = runCircom(`${f} --r1cs --O2 -l node_modules -l circuits -o ${OUT}`);
  return Number(out.match(/non-linear constraints: (\d+)/)[1]);
}

const rows = [];
let i = 0, sum = 0;
for (const [label, [mult, src]] of Object.entries(cases)) {
  const each = count(`c${i++}`, src);
  rows.push([label, each * mult]); sum += each * mult;
}
const total = countFile("circuits/kyc_presentation.circom");

let md = `| Component | Constraints | Share |\n|---|---|---|\n`;
for (const [l, n] of rows) md += `| ${l} | ${n.toLocaleString("en")} | ${((100 * n) / total).toFixed(1)}% |\n`;
md += `| **Sum of components** | **${sum.toLocaleString("en")}** | |\n`;
md += `| **Whole circuit (KycPresentation(16), --O2)** | **${total.toLocaleString("en")}** | |\n`;
md += `\nSmallest Powers of Tau: 2^${Math.ceil(Math.log2(total + 8 + 1))}\n`;
fs.writeFileSync("build/constraints.md", md);
console.log(md);
