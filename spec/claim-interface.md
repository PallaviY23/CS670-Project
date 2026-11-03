# Claim Interface — `KycPresentation` circuit

**Owner:** B. Vaishnavi (V1) · **Status:** Implemented for the local demo
**Circuit:** `circuits/kyc_presentation.circom` · **Instantiation:** `KycPresentation(REV_DEPTH = 16)`, credential tree depth 3 (fixed)

This file is the contract between the circuit, the prover (Durbasmriti), the verifier (Someshwar) and the credential library (Pallavi). Any change to the public signal order, hashing rules or ranges is a coordinated spec change made through a reviewed pull request, and must be reflected in `build/circuit/manifest.json`.

## 1. What a valid proof means

A proof exists **only if all of the following hold**. Claims are assertions, not 0/1 outputs. An underage, unverified, expired or revoked holder cannot produce any proof, so a negative result is never revealed.

| # | Statement | Template |
|---|---|---|
| 1 | The credential root is signed by the issuer key `(issuerAx, issuerAy)` (EdDSA-Poseidon, BabyJubJub) | `IssuerSignature` |
| 2 | Slots 0–4 used by the prover all belong to that one signed root | `AttributeLeaf`, `CredentialRoot8` |
| 3 | `currentDate ≥ dob + minAgeOffset` | `DateRange`, `AgeAtLeast` |
| 4 | `kycStatus = 1` | inline constraint |
| 5 | `expiry ≥ currentDate` | `DateRange`, `NotExpired` |
| 6 | The prover knows `holderSecret` with `Poseidon(holderSecret) = holderCommitment` (slot 4) | `HolderBinding` |
| 7 | `Poseidon(credentialId)` is a leaf of the active-credential tree with root `revocationRoot` | `RevocationMembership` |
| — | Outputs `nullifier = Poseidon(holderSecret, spId)`; binds `challenge` | `Nullifier` |

## 2. Public signals (fixed order)

`publicSignals` as returned by SnarkJS: circuit outputs first, then public inputs **in their declaration order** in the main template.

| Index | Name | Kind | Range / type | Verifier checks it against |
|---|---|---|---|---|
| 0 | `nullifier` | output | field element | Audit log / optional rate limit. Do not treat proof bytes as an identifier |
| 1 | `issuerAx` | public input | field element | Trusted KYC Authority key |
| 2 | `issuerAy` | public input | field element | Trusted KYC Authority key |
| 3 | `currentDate` | public input | YYYYMMDD, < 2^32 | Date stored with the challenge |
| 4 | `minAgeOffset` | public input | < 2^32; 180000 for age ≥ 18 | Service policy |
| 5 | `challenge` | public input | field element | Issued, unexpired, unused |
| 6 | `spId` | public input | field element | Verifier's own identifier |
| 7 | `revocationRoot` | public input | field element | Current active-set root stored with the challenge |

**Total: 8 public signals.** The verifier must reject any proof whose signal count is not 8, and any non-canonical value (≥ p).

## 3. Private inputs

| Name | Shape | Meaning |
|---|---|---|
| `credentialId` | 1 | Slot 0 value |
| `dob` | 1 | Slot 1 value, YYYYMMDD |
| `kycStatus` | 1 | Slot 2 value (must be 1) |
| `expiry` | 1 | Slot 3 value, YYYYMMDD |
| `holderSecret` | 1 | Wallet secret. Slot 4 value is **computed** as `Poseidon(holderSecret)`, never supplied |
| `salts` | [5] | Salts of slots 0–4 |
| `otherLeaves` | [3] | Leaf hashes of slots 5, 6, 7 (nationality, issuedAt, reserved), in slot order. Their values stay hidden |
| `sigR8x`, `sigR8y`, `sigS` | 1 each | Issuer EdDSA-Poseidon signature on the root |
| `revSiblings` | [16] | Siblings in the active-credential tree, bottom level first |
| `revPathIndices` | [16] | Position bits in that tree (0 = left, 1 = right), bottom level first; must be boolean |

The credential root itself is not an input. The circuit rebuilds the whole 8-leaf tree from the five computed leaves and `otherLeaves`. Because every position is fixed by construction, a leaf cannot be moved to another slot.

**Wallet note (Durbasmriti):** `otherLeaves` = `leaves[5..7]` of the stored credential, where `leaf_s = Poseidon(s, value_s, salt_s)`.

## 4. Hashing rules (must match `src/credential/presentation-credential.mjs` exactly)

All hashes are circomlib Poseidon over the BN254 scalar field.

- **Leaf:** `leaf_s = Poseidon(s, value_s, salt_s)`, where `s` is the slot number 0–7.
- **Internal node:** `Poseidon(left, right)`.
- **Tree:** depth 3, 8 leaves, slot `s` at leaf position `s`; level 1 = `Poseidon(leaf_0, leaf_1)`, … ; root = `Poseidon(node_L, node_R)`.
- **Holder commitment:** `Poseidon(holderSecret)`.
- **Nullifier:** `Poseidon(holderSecret, spId)`.
- **Signature:** `circomlibjs` `eddsa.signPoseidon(privateKey, root)`; verified with circomlib `EdDSAPoseidonVerifier`, `M = root`.
- **Revocation leaf:** `Poseidon(credentialId)`; internal nodes `Poseidon(left, right)`; empty leaves are 0. Template: `circuits/RevocationMembership.circom` (Someshwar, S6), inputs `credentialId`, `root`, `pathElements`, `pathIndices`.

| Slot | Attribute | Used inside this circuit |
|---|---|---|
| 0 | credentialId | yes (revocation check) |
| 1 | dob | yes |
| 2 | kycStatus | yes |
| 3 | expiry | yes |
| 4 | holderCommitment | yes (computed) |
| 5 | nationality | no (only its leaf hash) |
| 6 | issuedAt | no (only its leaf hash) |
| 7 | reserved | no (only its leaf hash) |

"Used" means used privately inside the proof. No attribute value appears in the public signals.

## 5. Integer ranges and date arithmetic

- Dates are integers `YYYYMMDD`. `dob`, `expiry`, `currentDate` and `minAgeOffset` are each range-checked to `[0, 2^32)` with `Num2Bits(32)` before any comparison. All comparisons use 33-bit comparators.
- **Why the range check is mandatory.** Circuit arithmetic is modulo p. Without it, a "negative" date such as `dob = p − 100000` makes `dob + 180000` wrap to `80000`, which passes a naive comparison. A test demonstrates this attack on an unchecked variant.
- **Why 180000 means 18 years.** Adding 18 to the year adds `18 × 10000` to `YYYYMMDD` and leaves `MMDD` unchanged. The holder is an adult on their 18th birthday.
- **29 February.** The threshold for `20080229` is `20260229`, a date that does not exist, so the holder becomes an adult on **1 March** in non-leap years. This is the convention we adopt.
- Validity of the calendar date (month 01–12, day 01–31) is **not** checked in the circuit. Values are issuer-signed, and `currentDate` is verifier-checked.

## 6. Responsibilities outside the circuit

The circuit only proves internal consistency. The verifier must reject the proof unless it also checks:

- the issuer key is trusted,
- `currentDate`, `minAgeOffset`, `spId`, issuer key, and revocation root match the challenge record,
- the challenge is fresh and unused, and is consumed only after a valid proof,
- the revocation root is still the current active-set root at verification time. A proof against an old root still passes the circuit.

## 7. Sizes (measured, circom 2.2.3, `--O2`)

Regenerate with `node scripts/constraints.mjs`.

| Component | Constraints | Share |
|---|---|---|
| IssuerSignature (EdDSA-Poseidon) | 4,207 | 35.3% |
| RevocationMembership(16) | 4,101 | 34.4% |
| CredentialRoot8 (whole tree, 7 hashes) | 1,680 | 14.1% |
| AttributeLeaf ×5 | 1,290 | 10.8% |
| Nullifier | 240 | 2.0% |
| HolderBinding | 213 | 1.8% |
| DateRange ×4 | 128 | 1.1% |
| AgeAtLeast | 33 | 0.3% |
| NotExpired | 33 | 0.3% |
| **Whole circuit** | **11,923** | — |

**Smallest Powers of Tau: 2^14.**

**V6 optimisation applied.** The first version proved five separate Merkle inclusion paths (15 node hashes, 13,827 constraints). The circuit now rebuilds the 8-leaf tree once (7 node hashes): **13,827 → 11,907 constraints (−13.9%)**; 11,923 after switching to Someshwar's revocation template (+1 per tree level), with fewer private inputs (3 leaf hashes instead of 15 siblings).

**Revocation tree depth** (each level ≈ 243 constraints):

| `REV_DEPTH` | Max credentials | Constraints | Powers of Tau |
|---|---|---|---|
| 16 | 65,536 | 11,923 | 2^14 |
| 20 | ~1 million | 12,895 | 2^14 |
| 24 | ~16.7 million | 13,867 | 2^14 |

Recommendation: depth 20. It costs +8% and needs no larger setup. Final choice is Someshwar's (S6).

**Kept on purpose.** The range check on `minAgeOffset` (32 constraints) is redundant if the verifier enforces 180000, but it keeps the circuit sound on its own. The cost is negligible.

## 8. Demo choices and production limits

The merged demo uses revocation depth 16 and builds the presentation circuit with `--O2`. The demo issuer is local and synthetic: it accepts the DOB supplied by the UI and sets `kycStatus = 1`; it does not verify identity documents or perform real KYC. The key is development-only. A production deployment needs a real issuer workflow and protected key management, a durable revocation service, and an independently generated multi-party setup.

## 9. Credential-module alignment

`src/credential/presentation-credential.mjs` implements this circuit's eight-slot format, root-only EdDSA-Poseidon signature, and `Poseidon(slot, value, salt)` leaf hashing. The earlier `src/credential/credential.mjs` two-attribute selective-disclosure API remains as a standalone first prototype and is not used by the browser demo.

The website's `/api/issuer/issue` endpoint (alias `/api/demo/issue`) is only for local demonstration. The stored JSON format and disclosure policy are in [credential-format.md](credential-format.md). It is not a trusted external issuer service and must be disabled/replaced for deployment.
