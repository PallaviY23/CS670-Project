import express from "express";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const app = express();
const circuitDir = resolve("build/circuit");
const wasmPath = resolve(circuitDir, "kyc_claims_js/kyc_claims.wasm");
const zkeyPath = resolve(circuitDir, "kyc_claims_final.zkey");
const verificationKeyPath = resolve(circuitDir, "verification_key.json");

app.disable("x-powered-by");
app.use(express.json({ limit: "256kb" }));

function isProofReady() {
  return [wasmPath, zkeyPath, verificationKeyPath].every(existsSync);
}

function sendArtifact(path) {
  return (_request, response) => {
    if (!isProofReady()) {
      response.status(503).json({ error: "Run npm run setup:demo first." });
      return;
    }

    response.sendFile(path);
  };
}

app.get("/api/health", (_request, response) => {
  response.json({
    status: "ok",
    proofReady: isProofReady(),
    verifier: "Groth16 / bn128",
  });
});

app.get("/api/prover/wasm", sendArtifact(wasmPath));
app.get("/api/prover/zkey", sendArtifact(zkeyPath));

app.post("/api/verify", async (request, response) => {
  const { proof, publicSignals } = request.body ?? {};
  const validSignals = Array.isArray(publicSignals)
    && publicSignals.length === 2
    && publicSignals.every((signal) => ["0", "1"].includes(String(signal)));

  if (!proof || typeof proof !== "object" || !validSignals) {
    response.status(400).json({ error: "Expected a proof and two boolean public signals." });
    return;
  }

  if (!isProofReady()) {
    response.status(503).json({ error: "Run npm run setup:demo first." });
    return;
  }

  const startedAt = performance.now();

  try {
    const verificationKey = JSON.parse(readFileSync(verificationKeyPath, "utf8"));
    const proofValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    const claims = {
      ageAtLeast18: String(publicSignals[0]) === "1",
      kycVerified: String(publicSignals[1]) === "1",
    };

    response.json({
      proofValid,
      accepted: proofValid && claims.ageAtLeast18 && claims.kycVerified,
      claims,
      verificationMs: Number((performance.now() - startedAt).toFixed(2)),
    });
  } catch {
    response.status(400).json({ error: "The proof could not be verified." });
  }
});

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (isMain) {
  const port = Number(process.env.PORT ?? 4000);
  app.listen(port, "127.0.0.1", () => {
    console.log(`KYC verification API listening on http://127.0.0.1:${port}`);
  });
}

export { app };