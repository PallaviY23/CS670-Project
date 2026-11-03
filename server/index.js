import express from "express";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import {
  VerifierEngine,
  ChallengeStore,
  AuditLog,
  generateRandomFieldElement,
  isCanonicalFieldElement,
} from "../src/verifier/index.js";
import { getDefaultRegistry } from "../src/verifier/revocation.js";
import {
  generateIssuerKeyPair,
  issuerKeyPairFromPrivateKey,
  issueCredential,
} from "../src/credential/presentation-credential.mjs";
import { isValidDateInt } from "../src/prover/inputs.js";

const app = express();
const circuitDir = resolve("build/circuit");
const wasmPath = resolve(circuitDir, "kyc_presentation_js/kyc_presentation.wasm");
const zkeyPath = resolve(circuitDir, "kyc_presentation_final.zkey");
const verificationKeyPath = resolve(circuitDir, "verification_key.json");
const manifestPath = resolve(circuitDir, "manifest.json");
const serviceProviderId = "123456789";
const minimumAgeOffset = 180000;

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
const issuerKeyPath = resolve("build/demo-issuer-key.json");

async function loadDemoIssuerKeyPair() {
  mkdirSync(resolve("build"), { recursive: true });
  if (existsSync(issuerKeyPath)) {
    const stored = JSON.parse(readFileSync(issuerKeyPath, "utf8"));
    return issuerKeyPairFromPrivateKey(stored.privateKey);
  }
  const generated = await generateIssuerKeyPair();
  try {
    writeFileSync(issuerKeyPath, JSON.stringify({ privateKey: generated.privateKey }), { flag: "wx", mode: 0o600 });
    return generated;
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const stored = JSON.parse(readFileSync(issuerKeyPath, "utf8"));
    return issuerKeyPairFromPrivateKey(stored.privateKey);
  }
}

const demoIssuerKeyPair = await loadDemoIssuerKeyPair();

// Initialize registry and verifier engine
async function initVerifier() {
  revocationRegistry = await getDefaultRegistry(16);

  let verificationKey = null;
  if (existsSync(verificationKeyPath) && existsSync(manifestPath)) {
    const loaded = VerifierEngine.loadArtifacts({ verificationKeyPath, manifestPath });
    if (loaded.manifest?.circuit !== "kyc_presentation") {
      throw new Error("Verifier artifacts were not generated for the credential-bound presentation circuit.");
    }
    const expectedSignals = [
      "nullifier",
      "issuerAx",
      "issuerAy",
      "currentDate",
      "minAgeOffset",
      "challenge",
      "spId",
      "revocationRoot",
    ];
    if (JSON.stringify(loaded.manifest.publicSignals) !== JSON.stringify(expectedSignals)) {
      throw new Error("Verifier public-signal order does not match the presentation interface.");
    }
    verificationKey = loaded.verificationKey;
  }

  verifierEngine = new VerifierEngine({
    verificationKey,
    spId: serviceProviderId,
    trustedIssuerKey: {
      ax: demoIssuerKeyPair.publicKey.Ax,
      ay: demoIssuerKeyPair.publicKey.Ay,
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
    trustedIssuer: demoIssuerKeyPair.publicKey,
    serviceProviderId,
    minimumAgeOffset,
  });
});

app.get("/api/prover/manifest", sendArtifact(manifestPath));
app.get("/api/prover/wasm", sendArtifact(wasmPath));
app.get("/api/prover/zkey", sendArtifact(zkeyPath));

app.post("/api/verify", (_request, response) => {
  response.status(410).json({
    error: "The starter age/KYC circuit is retired. Request a presentation with POST /api/sp/request.",
  });
});

// --- Service Provider Verifier API (Tasks S4 & S5) ---

app.post("/api/demo/issue", async (request, response) => {
  if (process.env.NODE_ENV === "production") {
    response.sendStatus(404);
    return;
  }
  const dob = Number(request.body?.dob);
  const holderCommitment = request.body?.holderCommitment;
  const currentDate = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  if (!isValidDateInt(dob) || dob > currentDate) {
    response.status(400).json({ error: "dob must be a valid past date in YYYYMMDD form." });
    return;
  }
  if (!isCanonicalFieldElement(holderCommitment) || String(holderCommitment) === "0") {
    response.status(400).json({ error: "holderCommitment must be a non-zero canonical field element." });
    return;
  }

  try {
    const issuedAt = currentDate;
    const year = Math.floor(currentDate / 10000) + 10;
    const month = Math.floor(currentDate / 100) % 100;
    const day = currentDate % 100;
    const expiry = year * 10000 + month * 100 + Math.min(day, month === 2 ? 28 : 31);
    const credentialId = generateRandomFieldElement();
    const credential = await issueCredential({
      credentialId,
      dob,
      kycStatus: 1,
      expiry,
      holderCommitment,
      nationality: 840,
      issuedAt,
      issuerPrivateKey: demoIssuerKeyPair.privateKey,
    });
    const registration = revocationRegistry.register(credentialId);
    response.status(201).json({ credential, revocationRoot: registration.root });
  } catch (error) {
    response.status(400).json({ error: error.message });
  }
});

// S4: Challenge Service
app.post("/api/sp/request", (request, response) => {
  const { spId = serviceProviderId, minAgeOffset = minimumAgeOffset } = request.body ?? {};
  if (String(spId) !== serviceProviderId || Number(minAgeOffset) !== minimumAgeOffset) {
    response.status(400).json({ error: "This demo issues requests for its fixed service provider and age policy." });
    return;
  }
  const currentDate = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));

  const record = challengeStore.issue({
    spId,
    currentDate,
    minAgeOffset,
    trustedIssuer: verifierEngine.trustedIssuerKey,
    acceptedRevocationRoots: [revocationRegistry.getRoot()],
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
  if (!isProofReady()) {
    response.status(503).json({ accepted: false, code: "PROVING_ARTIFACTS_MISSING", reason: "Run npm run setup:demo first." });
    return;
  }
  if (typeof request.body?.requestId !== "string") {
    response.status(400).json({ accepted: false, code: "INVALID_SCHEMA", reason: "requestId is required." });
    return;
  }
  try {
    const presentation = request.body;
    const result = await verifierEngine.verifyPresentation(presentation, {
      requestId: presentation?.requestId,
    });

    if (!result.accepted) {
      response.status(400).json(result);
      return;
    }

    response.json(result);
  } catch (error) {
    console.error("Presentation verification failed:", error);
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
  if (process.env.NODE_ENV === "production") {
    response.sendStatus(404);
    return;
  }
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
  if (process.env.NODE_ENV === "production") {
    response.sendStatus(404);
    return;
  }
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
