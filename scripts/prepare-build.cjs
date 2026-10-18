const fs = require("node:fs");

fs.rmSync("build/circuit", { recursive: true, force: true });
fs.rmSync("circuits/kyc_claims_js", { recursive: true, force: true });
fs.rmSync("circuits/kyc_claims.r1cs", { force: true });
fs.rmSync("circuits/kyc_claims.sym", { force: true });
fs.mkdirSync("build/circuit", { recursive: true });