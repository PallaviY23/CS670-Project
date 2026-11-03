import express from "express";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { VerifierEngine, ChallengeStore, AuditLog } from "../src/verifier/index.js";
import { getDefaultRegistry } from "../src/verifier/revocation.js";

const app = express();
const circuitDir = resolve("build/circuit");
const wasmPath = resolve(circuitDir, "kyc_claims_js/kyc_claims.wasm");
const zkeyPath = resolve(circuitDir, "kyc_claims_final.zkey");
const verificationKeyPath = resolve(circuitDir, "verification_key.json");
const manifestPath = resolve(circuitDir, "manifest.json");

// Security Hardening (Task S8)
app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'"], // required for snarkjs wasm/prover in browser
        connectSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);
app.use(cors());
app.use(express.json({ limit: "256kb" }));

// Rate limiting (Task S8)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests from this IP, please try again later." },
});
app.use("/api/", apiLimiter);

// Verifier state instances (Tasks S3, S4, S6, S7)
const challengeStore = new ChallengeStore();
const auditLog = new AuditLog();
let revocationRegistry = null;
let verifierEngine = null;

// Initialize registry and verifier engine
async function initVerifier() {
  revocationRegistry = await getDefaultRegistry(16);

  let verificationKey = null;
  if (existsSync(verificationKeyPath)) {
    try {
      const loaded = VerifierEngine.loadArtifacts({ verificationKeyPath, manifestPath });
      verificationKey = loaded.verificationKey;
    } catch (err) {
      console.warn("Warning loading verification key / manifest:", err.message);
      verificationKey = JSON.parse(readFileSync(verificationKeyPath, "utf8"));
    }
  }

  verifierEngine = new VerifierEngine({
    verificationKey,
    spId: "123456789",
    trustedIssuerKey: {
      ax: "11513271168449174522649033324628286280208269784305886616238612196620584742680",
      ay: "4525892543290680321743110595304724213031024621041926618587428172605809756083",
    },
    challengeStore,
    auditLog,
    revocationRegistry,
  });
}

await initVerifier();

function isProofReady() {
  return [wasmPath, zkeyPath, verificationKeyPath, manifestPath].every(existsSync);
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

// Health and artifact serving
app.get("/api/health", (_request, response) => {
  response.json({
    status: "ok",
    proofReady: isProofReady(),
    verifier: "Groth16 / bn128",
    revocationRoot: revocationRegistry ? revocationRegistry.getRoot() : null,
  });
});

app.get("/api/prover/manifest", sendArtifact(manifestPath));
app.get("/api/prover/wasm", sendArtifact(wasmPath));
app.get("/api/prover/zkey", sendArtifact(zkeyPath));

// Backward-compatible starter verify endpoint
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

// --- Service Provider Verifier API (Tasks S4 & S5) ---

// S4: Challenge Service
app.post("/api/sp/request", (request, response) => {
  const { spId = "123456789", minAgeOffset = 180000 } = request.body ?? {};
  const currentDate = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));

  const record = challengeStore.issue({
    spId,
    currentDate,
    minAgeOffset,
    trustedIssuer: verifierEngine.trustedIssuerKey,
    acceptedRevocationRoots: revocationRegistry ? revocationRegistry.getRootHistory() : [],
  });

  response.json({
    requestId: record.requestId,
    challenge: record.challenge,
    spId: record.spId,
    currentDate: record.currentDate,
    minAgeOffset: record.minAgeOffset,
    trustedIssuer: record.trustedIssuer,
    acceptedRevocationRoots: record.acceptedRevocationRoots,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
  });
});

// S5: Strict Fail-Closed Verification Pipeline
app.post("/api/sp/verify", async (request, response) => {
  try {
    const presentation = request.body;
    const result = await verifierEngine.verifyPresentation(presentation);

    if (!result.accepted) {
      response.status(400).json(result);
      return;
    }

    response.json(result);
  } catch (error) {
    response.status(500).json({
      accepted: false,
      code: "INTERNAL_VERIFIER_ERROR",
      reason: "An unexpected error occurred during verification.",
    });
  }
});

// S7: Audit Log endpoint
app.get("/api/sp/audit-log", (_request, response) => {
  response.json({
    entries: auditLog.getEntries(50),
  });
});

// --- Revocation Registry Endpoints (Task S6) ---

app.get("/api/revocation/root", (_request, response) => {
  response.json({
    root: revocationRegistry.getRoot(),
    treeDepth: revocationRegistry.depth,
  });
});

app.get("/api/revocation/history", (_request, response) => {
  response.json({
    currentRoot: revocationRegistry.getRoot(),
    recentRoots: revocationRegistry.getRootHistory(),
  });
});

app.get("/api/revocation/path/:credentialId", (request, response) => {
  try {
    const { credentialId } = request.params;
    const path = revocationRegistry.getMembershipPath(credentialId);
    response.json(path);
  } catch (error) {
    response.status(404).json({ error: error.message });
  }
});

// Revoke a credential (KYC Authority / Issuer action)
app.post("/api/revocation/revoke", (request, response) => {
  try {
    const { credentialId } = request.body ?? {};
    if (!credentialId) {
      response.status(400).json({ error: "credentialId is required" });
      return;
    }
    const result = revocationRegistry.revoke(credentialId);
    response.json(result);
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
});

// Register an active credential
app.post("/api/revocation/register", (request, response) => {
  try {
    const { credentialId } = request.body ?? {};
    if (!credentialId) {
      response.status(400).json({ error: "credentialId is required" });
      return;
    }
    const result = revocationRegistry.register(credentialId);
    response.json(result);
  } catch (error) {
    response.status(400).json({ error: error.message });
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

export { app, verifierEngine, challengeStore, auditLog, revocationRegistry };
