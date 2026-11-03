const fs = require("node:fs");
const path = require("node:path");

// Remove only the starter/test circuit outputs that `npm test` rebuilds, so the
// kyc_presentation proving artifacts from `npm run setup:demo` survive a test run.
const circuitDir = "build/circuit";
fs.mkdirSync(circuitDir, { recursive: true });
for (const entry of fs.readdirSync(circuitDir)) {
  if (/^(kyc_claims|test_revocation|rev_|test\.wtns)/.test(entry)) {
    fs.rmSync(path.join(circuitDir, entry), { recursive: true, force: true });
  }
}
fs.rmSync("circuits/kyc_claims_js", { recursive: true, force: true });
fs.rmSync("circuits/kyc_claims.r1cs", { force: true });
fs.rmSync("circuits/kyc_claims.sym", { force: true });
