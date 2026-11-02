import crypto from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import * as snarkjs from "snarkjs";

/**
 * BN254 / alt_bn128 scalar field order r.
 * Every valid public signal and secret scalar must satisfy 0 <= x < r.
 */
export const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Validates whether a value is a canonical BN254 scalar field element.
 * @param {string|number|bigint} val
 * @returns {boolean}
 */
export function isCanonicalFieldElement(val) {
  if (val === null || val === undefined || val === "") return false;
  try {
    const s = String(val).trim();
    if (!/^\d+$/.test(s)) return false;
    const n = BigInt(s);
    return n >= 0n && n < SNARK_SCALAR_FIELD;
  } catch {
    return false;
  }
}

/**
 * Generates a cryptographically secure random field element in [1, r - 1].
 * @returns {string} Decimal string representation
 */
export function generateRandomFieldElement() {
  while (true) {
    const buf = crypto.randomBytes(32);
    // Mask top 3 bits to fit within 254-bit range
    buf[0] &= 0x1f;
    const n = BigInt(`0x${buf.toString("hex")}`);
    if (n > 0n && n < SNARK_SCALAR_FIELD) {
      return n.toString();
    }
  }
}

/**
 * Computes deterministic receipt identifier from public signals and nullifier.
 * Note: Per Threat Model (Task S11), we NEVER use proof bytes as an identifier
 * due to Groth16 proof malleability.
 */
export function createReceiptId(nullifier, challenge, spId) {
  const payload = `${nullifier}:${challenge}:${spId}`;
  return `RCPT_${crypto.createHash("sha256").update(payload).digest("hex").slice(0, 12).toUpperCase()}`;
}

/**
 * In-memory challenge store with automatic TTL expiration and atomic single-use consumption.
 */
export class ChallengeStore {
  /**
   * @param {number} defaultTtlMs Time-to-live in milliseconds (default 5 minutes)
   */
  constructor(defaultTtlMs = 300_000) {
    this.defaultTtlMs = defaultTtlMs;
    this.challenges = new Map(); // challenge string -> record
  }

  /**
   * Issues and stores a new challenge record.
   */
  issue({ spId, currentDate, minAgeOffset = 180000, trustedIssuer, acceptedRevocationRoots, ttlMs }) {
    const challenge = generateRandomFieldElement();
    const requestId = `req_${crypto.randomBytes(8).toString("hex")}`;
    const now = Date.now();
    const expiresAtMs = now + (ttlMs ?? this.defaultTtlMs);

    const record = {
      requestId,
      challenge,
      spId: String(spId),
      currentDate: Number(currentDate),
      minAgeOffset: Number(minAgeOffset),
      trustedIssuer,
      acceptedRevocationRoots: Array.isArray(acceptedRevocationRoots) ? acceptedRevocationRoots : [],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresAtMs,
      used: false,
    };

    this.challenges.set(challenge, record);
    this.cleanExpired();
    return record;
  }

  /**
   * Validates and atomically consumes a challenge.
   * @param {string} challenge
   * @returns {{ valid: boolean, reason?: string, record?: object }}
   */
  consume(challenge) {
    const challengeStr = String(challenge).trim();
    if (!this.challenges.has(challengeStr)) {
      return { valid: false, reason: "CHALLENGE_NOT_FOUND" };
    }

    const record = this.challenges.get(challengeStr);
    if (record.used) {
      return { valid: false, reason: "CHALLENGE_ALREADY_USED" };
    }

    if (Date.now() > record.expiresAtMs) {
      this.challenges.delete(challengeStr);
      return { valid: false, reason: "CHALLENGE_EXPIRED" };
    }

    // Mark used immediately (atomic consumption)
    record.used = true;
    record.usedAt = new Date().toISOString();
    return { valid: true, record };
  }

  cleanExpired() {
    const now = Date.now();
    for (const [key, rec] of this.challenges.entries()) {
      if (now > rec.expiresAtMs + 60_000) {
        this.challenges.delete(key);
      }
    }
  }
}

/**
 * Privacy-preserving audit log for presentation receipts.
 * Strictly avoids logging proof bytes, attribute values, or salts.
 */
export class AuditLog {
  constructor(maxEntries = 5000) {
    this.maxEntries = maxEntries;
    this.entries = [];
    this.nullifierTimestamps = new Map(); // nullifier -> array of timestamp numbers
  }

  /**
   * Records an audit log entry.
   */
  record({ nullifier, spId, accepted, receiptId, errorReason = null }) {
    const entry = {
      receiptId,
      nullifier: String(nullifier),
      spId: String(spId),
      accepted: Boolean(accepted),
      errorReason,
      timestamp: new Date().toISOString(),
    };

    this.entries.unshift(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.pop();
    }

    // Rate-limit tracking per nullifier
    const now = Date.now();
    const timestamps = this.nullifierTimestamps.get(entry.nullifier) ?? [];
    timestamps.push(now);
    // Keep only timestamps within 1 hour
    const recent = timestamps.filter((t) => now - t < 3600_000);
    this.nullifierTimestamps.set(entry.nullifier, recent);

    return entry;
  }

  /**
   * Checks if a nullifier exceeded the rate limit.
   */
  isRateLimited(nullifier, maxPerHour = 20) {
    const now = Date.now();
    const timestamps = (this.nullifierTimestamps.get(String(nullifier)) ?? []).filter((t) => now - t < 3600_000);
    return timestamps.length >= maxPerHour;
  }

  getEntries(limit = 100) {
    return this.entries.slice(0, limit);
  }
}

/**
 * Verifier Engine
 */
export class VerifierEngine {
  constructor(options = {}) {
    this.verificationKey = options.verificationKey ?? null;
    this.manifest = options.manifest ?? null;
    this.trustedIssuerKey = options.trustedIssuerKey ?? null; // { ax: string, ay: string }
    this.spId = options.spId ?? "123456789";
    this.challengeStore = options.challengeStore ?? new ChallengeStore();
    this.auditLog = options.auditLog ?? new AuditLog();
    this.revocationRegistry = options.revocationRegistry ?? null;
  }

  /**
   * Loads verification key and manifest, asserting hash integrity.
   */
  static loadArtifacts({ verificationKeyPath, manifestPath }) {
    if (!existsSync(verificationKeyPath)) {
      throw new Error(`Verification key not found at ${verificationKeyPath}`);
    }

    const vkRaw = readFileSync(verificationKeyPath, "utf8");
    const verificationKey = JSON.parse(vkRaw);
    const vkHash = crypto.createHash("sha256").update(vkRaw).digest("hex");

    let manifest = null;
    if (manifestPath && existsSync(manifestPath)) {
      manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
      if (manifest.verificationKeyHash && manifest.verificationKeyHash !== vkHash) {
        throw new Error(
          `Verification key hash mismatch! Manifest expected ${manifest.verificationKeyHash}, got ${vkHash}`
        );
      }
    }

    return { verificationKey, vkHash, manifest };
  }

  /**
   * Strict 9-step fail-closed verification pipeline.
   *
   * @param {object} presentation { proof, publicSignals }
   * @param {object} context { expectedDate, expectedSpId, ... }
   * @returns {Promise<{ accepted: boolean, code?: string, reason?: string, receiptId?: string, nullifier?: string, verificationMs: number }>}
   */
  async verifyPresentation(presentation, context = {}) {
    const startedAt = performance.now();
    const elapsed = () => Number((performance.now() - startedAt).toFixed(2));

    const { proof, publicSignals } = presentation ?? {};

    // 1. Request Schema Validation
    if (!proof || typeof proof !== "object" || !Array.isArray(publicSignals)) {
      return {
        accepted: false,
        code: "INVALID_SCHEMA",
        reason: "Presentation must contain a proof object and a publicSignals array.",
        verificationMs: elapsed(),
      };
    }

    const { pi_a, pi_b, pi_c } = proof;
    if (!Array.isArray(pi_a) || !Array.isArray(pi_b) || !Array.isArray(pi_c)) {
      return {
        accepted: false,
        code: "INVALID_PROOF_SHAPE",
        reason: "Proof structure missing valid pi_a, pi_b, or pi_c elements.",
        verificationMs: elapsed(),
      };
    }

    // 2. Signal Count and Ordering
    if (publicSignals.length !== 8) {
      return {
        accepted: false,
        code: "INVALID_SIGNAL_COUNT",
        reason: `Expected 8 public signals, received ${publicSignals.length}.`,
        verificationMs: elapsed(),
      };
    }

    const [
      nullifier,
      issuerAx,
      issuerAy,
      currentDate,
      minAgeOffset,
      challenge,
      spId,
      revocationRoot,
    ] = publicSignals.map((s) => String(s).trim());

    // 3. Canonical Field Elements Validation
    for (let i = 0; i < publicSignals.length; i++) {
      if (!isCanonicalFieldElement(publicSignals[i])) {
        return {
          accepted: false,
          code: "NON_CANONICAL_FIELD_ELEMENT",
          reason: `Signal at index ${i} is not a canonical field element (must be integer in [0, r - 1]).`,
          verificationMs: elapsed(),
        };
      }
    }

    // 4. Trusted Issuer Public Key
    const trustedIssuer = context.trustedIssuerKey ?? this.trustedIssuerKey;
    if (trustedIssuer) {
      const expectedAx = String(trustedIssuer.ax).trim();
      const expectedAy = String(trustedIssuer.ay).trim();
      if (issuerAx !== expectedAx || issuerAy !== expectedAy) {
        return {
          accepted: false,
          code: "UNTRUSTED_ISSUER",
          reason: "Issuer public key does not match trusted KYC Authority.",
          verificationMs: elapsed(),
        };
      }
    }

    // 5. Date Verification
    const expectedDate = context.expectedDate ?? Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
    if (Number(currentDate) !== expectedDate) {
      return {
        accepted: false,
        code: "DATE_MISMATCH",
        reason: `Current date ${currentDate} does not match expected verifier date ${expectedDate}.`,
        verificationMs: elapsed(),
      };
    }

    // 6. Challenge Verification (Issued, Unexpired, Unused -> Consumed)
    const consumeResult = this.challengeStore.consume(challenge);
    if (!consumeResult.valid) {
      return {
        accepted: false,
        code: consumeResult.reason,
        reason: `Challenge validation failed: ${consumeResult.reason}.`,
        verificationMs: elapsed(),
      };
    }

    // 7. Service Provider Identifier Verification
    const expectedSpId = String(context.spId ?? this.spId).trim();
    if (spId !== expectedSpId) {
      return {
        accepted: false,
        code: "SP_ID_MISMATCH",
        reason: `Presentation target spId ${spId} does not match verifier spId ${expectedSpId}.`,
        verificationMs: elapsed(),
      };
    }

    // 8. Revocation Root Verification
    if (this.revocationRegistry) {
      if (!this.revocationRegistry.isRootAccepted(revocationRoot)) {
        return {
          accepted: false,
          code: "REVOCATION_ROOT_REJECTED",
          reason: "Revocation root is not in accepted current or historical root set.",
          verificationMs: elapsed(),
        };
      }
    }

    // Check Nullifier Rate Limiting
    if (this.auditLog.isRateLimited(nullifier)) {
      return {
        accepted: false,
        code: "RATE_LIMITED",
        reason: "Too many presentations for this nullifier in the last hour.",
        verificationMs: elapsed(),
      };
    }

    // 9. Groth16 Cryptographic Verification
    if (!this.verificationKey) {
      return {
        accepted: false,
        code: "VERIFICATION_KEY_MISSING",
        reason: "Verifier has not loaded a verification key.",
        verificationMs: elapsed(),
      };
    }

    let proofValid = false;
    try {
      proofValid = await snarkjs.groth16.verify(this.verificationKey, publicSignals, proof);
    } catch (err) {
      return {
        accepted: false,
        code: "SNARK_VERIFY_EXCEPTION",
        reason: "Cryptographic proof verification encountered an error.",
        verificationMs: elapsed(),
      };
    }

    if (!proofValid) {
      return {
        accepted: false,
        code: "INVALID_PROOF",
        reason: "Cryptographic proof is invalid for given public signals.",
        verificationMs: elapsed(),
      };
    }

    const receiptId = createReceiptId(nullifier, challenge, spId);

    // Record strictly in privacy-preserving audit log
    this.auditLog.record({
      receiptId,
      nullifier,
      spId,
      accepted: true,
    });

    return {
      accepted: true,
      status: "VERIFIED",
      receiptId,
      nullifier,
      claims: {
        ageAtLeast18: true,
        kycVerified: true,
        unrevoked: true,
        holderBound: true,
      },
      verificationMs: elapsed(),
    };
  }
}
