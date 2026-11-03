# Verifier & Security Module

**Owner**: Someshwar Singh (231020) — Verification, Security and Optimization  
**Location**: `src/verifier/` and `server/index.js`

---

## 1. Overview

This module provides the complete verification pipeline, challenge issuance service (anti-replay), revocation registry (depth 16–20 Poseidon Merkle tree), privacy-preserving audit logging, and adversarial/negative testing suite for the Privacy-Preserving Digital KYC System.

---

## 2. Implemented Components

### 2.1 Verification Engine (`src/verifier/index.js`)
- **BN254 Scalar Field Canonicalization**: Enforces $0 \le x < r$ for all 8 public signals, preventing field-overflow and wrapping attacks.
- **Fail-Closed Presentation Verification Pipeline**:
  1. `INVALID_SCHEMA`: Validates proof object and public signals array presence.
  2. `INVALID_PROOF_SHAPE`: Ensures `pi_a`, `pi_b`, `pi_c` elements exist.
  3. `INVALID_SIGNAL_COUNT`: Checks for exactly 8 public signals.
  4. `NON_CANONICAL_FIELD_ELEMENT`: Checks canonical scalar bounds.
  5. `UNTRUSTED_ISSUER`: Validates BabyJubJub coordinates against trusted KYC Authority key.
  6. `DATE_MISMATCH`: Rejects stale or altered dates.
  7. `POLICY_MISMATCH`, `REQUEST_ID_MISMATCH`, and `SP_ID_MISMATCH`: Bind context signals to the issued challenge.
  8. `CHALLENGE_EXPIRED` / `CHALLENGE_ALREADY_USED`: Check TTL and replay status without consuming an invalid request.
  9. `REVOCATION_ROOT_REJECTED`: Requires the challenge's root to remain the current active root.
  10. `INVALID_PROOF`: Groth16 cryptographic proof check via SnarkJS; the challenge is consumed only after a valid proof.
- **Malleability Defense**: Receipts are generated from $\text{SHA256}(nullifier \parallel challenge \parallel spId)$ rather than proof bytes, neutralizing Groth16 proof randomization attacks.

### 2.2 Challenge & Anti-Replay Service (`ChallengeStore`)
- Issues ephemeral 254-bit field nonces with 5-minute TTL.
- A request is atomically consumed only after successful proof verification, so malformed submissions do not burn a user's request.

### 2.3 Revocation Subsystem (`src/verifier/revocation.js` & `circuits/RevocationMembership.circom`)
- **Poseidon Merkle Tree**: Depth-16 tree supporting 65,536 active credentials; IDs are canonical BN254 field elements, matching the circuit's `Poseidon(credentialId)` leaf.
- **Dynamic Updates**:
  - `register(id)`: Adds credential ID to active tree and updates root.
  - `revoke(id)`: Clears leaf, recomputes root, and updates accepted root history.
  - `getMembershipPath(id)`: Returns sibling path and direction bits for prover.
- **Circom Sub-Template**: `circuits/RevocationMembership.circom` for inclusion in the presentation circuit.

### 2.4 Privacy-Preserving Audit Log (`AuditLog`)
- Records **only** `{ receiptId, nullifier, spId, accepted, timestamp }`.
- Never stores date of birth, name, attribute values, salts, or proof bytes.
- Includes per-nullifier rate limiting to detect and mitigate Sybil flooding.

### 2.5 API Hardening (`server/index.js`)
- `helmet`: CSP headers preventing XSS while permitting client-side WASM.
- Same-origin Vite proxy; the API does not enable broad cross-origin access.
- `express-rate-limit`: IP-level rate limiting on `/api/*`.
- Body parser limited to 256 KB.

---

## 3. Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/sp/request` | POST | Issues fresh random challenge, date, and accepted revocation roots. |
| `/api/sp/verify` | POST | Runs 9-step fail-closed verification on incoming presentation. |
| `/api/sp/audit-log` | GET | Returns privacy-safe presentation receipts. |
| `/api/revocation/root` | GET | Returns current active credential Merkle root. |
| `/api/revocation/history` | GET | Returns root history for inspection; verification accepts only the current root. |
| `/api/revocation/path/:id` | GET | Returns Merkle inclusion path for an active credential. |
| `/api/revocation/revoke` | POST | Revokes a credential ID and updates the tree root. |
| `/api/revocation/register` | POST | Registers a newly issued credential ID as active. |

---

## 4. Testing & Benchmarking

Run the full automated test suite (including all 10 attack vectors and revocation tests):
```powershell
npm test
```

Run verifier scalability benchmarks:
```powershell
node scripts/benchmark-verifier.mjs
```
