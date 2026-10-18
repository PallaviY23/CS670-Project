import { randomBytes } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import * as snarkjs from "snarkjs";

const circuitDir = resolve("build/circuit");
const ceremonyDir = resolve("build/ceremony");
const logger = console;
const entropy = () => randomBytes(32).toString("hex");

await rm(ceremonyDir, { recursive: true, force: true });
await rm(resolve(circuitDir, "kyc_claims_0000.zkey"), { force: true });
await rm(resolve(circuitDir, "kyc_claims_final.zkey"), { force: true });
await rm(resolve(circuitDir, "verification_key.json"), { force: true });
await mkdir(ceremonyDir, { recursive: true });

const ptauInitial = resolve(ceremonyDir, "pot12_0000.ptau");
const ptauContributed = resolve(ceremonyDir, "pot12_0001.ptau");
const ptauFinal = resolve(ceremonyDir, "pot12_final.ptau");
const zkeyInitial = resolve(circuitDir, "kyc_claims_0000.zkey");
const zkeyFinal = resolve(circuitDir, "kyc_claims_final.zkey");

console.log("Creating local development-only Groth16 setup...");
const curve = await snarkjs.curves.getCurveFromName("bn128");
await snarkjs.powersOfTau.newAccumulator(curve, 12, ptauInitial, logger);
await curve.terminate();
await snarkjs.powersOfTau.contribute(
  ptauInitial,
  ptauContributed,
  "Local demo contribution",
  entropy(),
  logger,
);
await snarkjs.powersOfTau.preparePhase2(ptauContributed, ptauFinal, logger);
await snarkjs.zKey.newZKey(
  resolve(circuitDir, "kyc_claims.r1cs"),
  ptauFinal,
  zkeyInitial,
  logger,
);
await snarkjs.zKey.contribute(
  zkeyInitial,
  zkeyFinal,
  "Local demo proving key contribution",
  entropy(),
  logger,
);

const verificationKey = await snarkjs.zKey.exportVerificationKey(zkeyFinal, logger);
await writeFile(
  resolve(circuitDir, "verification_key.json"),
  `${JSON.stringify(verificationKey, null, 2)}\n`,
);

console.log("Demo proving and verification artifacts are ready under build/circuit.");