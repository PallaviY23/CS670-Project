# Credential Format and Selective-Disclosure Policy

**Tasks:** P1 (format), P7 (disclosure policy) · **Implementation:** `src/credential/presentation-credential.mjs` (version 2)
**Related:** [claim-interface.md](claim-interface.md) (circuit hashing rules), [protocol.md](protocol.md) (messages)

This file describes the credential a KYC Authority issues and the wallet stores. If this file and the code disagree, the code is authoritative and this file must be corrected.

## 1. JSON layout

```json
{
  "version": 2,
  "issuerId": "local-demo-issuer",
  "issuer": { "Ax": "<field>", "Ay": "<field>" },
  "attributes": {
    "credentialId": "<field>", "dob": "20000615", "kycStatus": "1", "expiry": "20361104",
    "holderCommitment": "<field>", "nationality": "840", "issuedAt": "20261104", "reserved": "0"
  },
  "salts":   { "credentialId": "<field>", "...": "one salt per slot" },
  "leaves":  ["<leaf 0>", "...", "<leaf 7>"],
  "root":    "<field>",
  "signature": { "R8x": "<field>", "R8y": "<field>", "S": "<integer>" }
}
```

Every number is a decimal string holding a canonical BN254 scalar field element (`0 ≤ x < p`), with no sign, leading zeros or hex. `issuerId` is 1 to 31 characters from `[A-Za-z0-9._:-]`. It is a label only and is not signed.

## 2. Slots

| Slot | Attribute | Encoding | Rule checked by `issueCredential` / `verifyCredential` |
|---|---|---|---|
| 0 | `credentialId` | field element; random in the demo (`generateRandomFieldElement`) | unique per credential; also the revocation-registry key |
| 1 | `dob` | integer `YYYYMMDD` | valid calendar date, 1900–2199 |
| 2 | `kycStatus` | `1` = verified | must be 1 (only verified credentials are issued) |
| 3 | `expiry` | integer `YYYYMMDD` | valid date, strictly after `issuedAt` |
| 4 | `holderCommitment` | `Poseidon(holderSecret)` | non-zero; computed by the wallet, never by the issuer |
| 5 | `nationality` | ISO 3166-1 numeric code (demo: 840) | field element |
| 6 | `issuedAt` | integer `YYYYMMDD` | valid date |
| 7 | `reserved` | `0` | must be 0 |

Slot positions are fixed. The circuit rebuilds the tree with slot `s` at leaf `s`, so moving a value to another slot changes the root.

**Date encoding.** Adding *N* years to a `YYYYMMDD` integer adds exactly `N × 10000`, so "age ≥ 18" is `currentDate − dob ≥ 180000`. A 29 February birthday reaches 18 on 1 March in non-leap years. See claim-interface §5.

## 3. Salts, leaves, root and signature

- **Salt:** 31 random bytes (248 bits, always `< p`) from `crypto.getRandomValues`, one for each slot, drawn fresh for every credential. Salts stop a verifier or observer from recovering a low-entropy value such as a date of birth by hashing every candidate.
- **Leaf:** `leaf_s = Poseidon(s, value_s, salt_s)`.
- **Tree:** depth 3. `node = Poseidon(left, right)`, and `root` is the single top node.
- **Signature:** EdDSA-Poseidon on BabyJubJub over `M = root`, via circomlibjs `signPoseidon`. The issuer key is a 32-byte seed. The public key `(Ax, Ay)` is published by `GET /api/issuer/key` and `GET /api/health`.

## 4. Verification on import (P5)

`verifyCredential(credential, trustedIssuer)` returns `true` only if all of the following hold:

1. `version === 2`, and the credential has all 8 attributes, all 8 salts, 8 leaves and a signature.
2. `issuer` equals `trustedIssuer` (when one is given).
3. Every attribute passes its encoding rule in §2.
4. Every recomputed leaf equals the stored leaf, and the recomputed root equals `root`.
5. The signature verifies under the trusted key.

It never throws: a malformed field returns `false`. The wallet refuses to import any credential that fails (`src/wallet/wallet.js`). Covered by `test/presentation-credential.test.mjs` and `test/wallet.test.mjs`.

## 5. Issuance flow and what the issuer learns

1. The wallet generates `holderSecret` and sends only `holderCommitment = Poseidon(holderSecret)`.
2. The KYC Authority checks identity. In this demo the check is mocked: `POST /api/issuer/issue` accepts the submitted DOB as verified.
3. The issuer assigns `credentialId`, draws the salts, signs the root, and registers `credentialId` in the active-credential (revocation) tree.
4. The wallet checks the credential (§4) and stores it encrypted in IndexedDB.

The issuer necessarily learns every attribute, `credentialId` and `holderCommitment`. It never learns `holderSecret`.

## 6. Selective-disclosure policy (P7)

The demo has one request type, "age ≥ 18 and KYC verified and credential active". The table shows what each party receives when it is answered.

| Item | Service provider (verifier) | Stays in wallet |
|---|---|---|
| `dob`, exact age | — | ✓ (used privately in the proof) |
| `kycStatus` | only the fact that it equals 1 | ✓ |
| `expiry` | only the fact that `expiry ≥ currentDate` | ✓ |
| `credentialId` | — (only that it is in the active set) | ✓ |
| `holderCommitment`, `holderSecret` | — | ✓ |
| `nationality`, `issuedAt`, `reserved` | — (only their leaf hashes enter the proof, privately) | ✓ |
| salts, leaves, root, signature | — | ✓ |
| `nullifier = Poseidon(holderSecret, spId)` | ✓ per-service pseudonym | |
| issuer key, `currentDate`, `minAgeOffset`, `challenge`, `spId`, `revocationRoot` | ✓ (all values the verifier chose or already knows) | |

A new claim type, such as a nationality check, would need a circuit that opens slot 5 and a new row in this table. That change goes through claim-interface.md.

### Consent-screen wording (used in `web/src/App.jsx`)

> **Share a proof with service ⟨spId⟩?**
> The service asks you to prove: age ≥ 18, KYC verified, credential active and not expired.
> **The service learns:** a per-service pseudonym (nullifier), which KYC Authority signed your credential, the request date and age policy, the request challenge and service ID, and the current revocation root.
> **Stays in your wallet:** date of birth and exact age; credential ID, expiry and nationality; salts, Merkle data and the issuer signature; your holder secret.

## 7. Privacy notes and limits (input to P10)

- **Issuer–verifier collusion.** The issuer knows `credentialId` and `holderCommitment`, but neither appears in a presentation. The nullifier depends on `holderSecret`, which the issuer never sees, so the issuer cannot link a nullifier to a credential by itself. If the issuer and a verifier collude, they can still use timing and the revocation-path lookup to link them (next point).
- **Revocation-path lookup.** In the demo, the wallet fetches its membership path from `GET /api/revocation/path/:credentialId`, so the registry learns which credential is about to be used. A deployment should let the wallet download the active set, or a published tree snapshot, and compute the path locally.
- **Cross-service unlinkability.** Different `spId` values give unrelated nullifiers. The same service sees the same nullifier on every visit, by design, for rate limiting and audit.
- **Exported credential files** contain every attribute in clear text. The UI warns the user when exporting.
