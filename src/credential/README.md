# Credential Module

The original `credential.mjs` contains the first two-attribute prototype and its selective-disclosure API. The browser demo now uses `presentation-credential.mjs`, whose format matches `circuits/kyc_presentation.circom`.

The presentation credential has eight ordered slots:

1. `credentialId`
2. `dob`
3. `kycStatus`
4. `expiry`
5. `holderCommitment`
6. `nationality`
7. `issuedAt`
8. `reserved`

Each leaf is `Poseidon(slot, value, salt)`, internal nodes are `Poseidon(left, right)`, and the issuer signs the root with EdDSA-Poseidon. The wallet verifies the whole credential against the configured issuer before storing it. The circuit recomputes slots 0–4 from private values, uses the stored hashes for slots 5–7, and checks the signature and active-set membership without disclosing the DOB.

`issueCredential()` is used by the local development-only issuer. Its key is stored under the ignored `build/` directory; it is not a production issuer and does not perform identity checks. `createHolderCommitment()` and `openCredentialSlot()` share the same hashing rules with the circuit.

Run credential and integration coverage with:

```powershell
node --test test/credential.test.mjs test/presentation-credential.test.mjs
```
