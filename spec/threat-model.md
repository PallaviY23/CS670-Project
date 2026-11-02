# Threat Model and Security Architecture

**Project**: Privacy-Preserving Digital KYC System Using Zero-Knowledge Proofs  
**Author**: Someshwar Singh (231020) — Verification, Security and Optimization  
**Scope**: Cryptographic threat model, trust boundaries, information-disclosure bounds, and formal security goals.

---

## 1. System Overview and Participating Parties

The system facilitates privacy-preserving verification of Identity / Know-Your-Customer (KYC) claims using Groth16 zero-knowledge proofs over the BN254 (alt_bn128) elliptic curve, Poseidon hash trees, and EdDSA-Poseidon signatures over the BabyJubJub curve.

There are three core parties and network-level adversaries:

1. **KYC Authority (Issuer)**:
   - Verifies the user's physical/official government credentials out-of-band during enrollment.
   - Formats user attributes into an 8-slot Merkle tree of depth 3.
   - Signs the Merkle tree root using an EdDSA-Poseidon private key ($k_{sk}$) over the BabyJubJub curve.
   - Publishes and rotates its public key $A = (A_x, A_y)$ and publishes updates to the active credential revocation tree.
   - **Trust Assumption**: Trusted to correctly verify real-world identities and sign accurate attribute roots. However, the system is designed to be **untrusted for surveillance**: the issuer must not be able to track user interactions with third-party service providers.

2. **Credential Holder (Prover / User Wallet)**:
   - Manages personal credentials, attribute salts, and a local secret $s_{holder} \in \mathbb{F}_r$ (`holderSecret`).
   - Generates zero-knowledge presentation proofs inside their local wallet (browser or worker).
   - **Trust Assumption**: **Untrusted**. Provers are assumed to be potentially malicious and may attempt to:
     - Forge proofs without a valid issuer signature.
     - Claim false attributes (e.g. claim age $\ge 18$ when underage, or valid KYC when unverified).
     - Present expired credentials ($currentDate > expiry$).
     - Present revoked credentials.
     - Present another user's credential (identity theft / credential sharing).
     - Replay captured proofs across services or sessions.

3. **Service Provider (Verifier / Relying Party)**:
   - Requests proof of eligibility (e.g., age $\ge 18$ and active KYC status) before granting access or opening an account.
   - Issues fresh, single-use, cryptographically secure nonces (`challenge`) and specifies its identifier (`spId`).
   - Verifies Groth16 zero-knowledge proofs and checks public signals against trusted keys, unexpired nonces, and current revocation roots.
   - **Trust Assumption**: **Untrusted with personal data**. The verifier is honest-but-curious or potentially malicious in attempting to:
     - Learn exact underlying identity data (exact date of birth, name, nationality, or raw credential ID).
     - Link transactions of the same user across multiple visits or across different service providers (profiling/collusion).

4. **Network & System Adversary**:
   - Eavesdrops on or actively manipulates network communication between Wallet, Issuer, and Verifier.
   - Injects, alters, delays, or replays API messages.

---

## 2. Information Disclosure Bounds (What Each Party Learns)

| Party | Permitted Knowledge | Cryptographically Concealed Information |
| :--- | :--- | :--- |
| **Issuer** | User's real-world identity, raw attributes, holder commitment $C_{holder} = \text{Poseidon}(s_{holder})$. | `holderSecret` ($s_{holder}$), verifier identities (`spId`), service usage timestamps, proof receipts, or nullifiers. |
| **Holder (Wallet)** | Raw attributes, leaf salts, Merkle tree inclusion paths, $s_{holder}$, issuer signature, challenge, and proof. | Issuer private key ($k_{sk}$), internal secrets of other users. |
| **Verifier (SP)** | Verification boolean (`accepted`), failure reasons, public signals (`nullifier`, `issuerAx`, `issuerAy`, `currentDate`, `minAgeOffset`, `challenge`, `spId`, `revocationRoot`), proof timings. | Date of birth, exact age, name, nationality, credential ID, attribute salts, $s_{holder}$, issuer signature $(R, S)$, Merkle paths, or activity at other SPs. |
| **Third-Party / Eavesdropper** | Only encrypted transport traffic (TLS). If intercepted: public signals and Groth16 proof. | Any private attribute or link to real-world identity. |

---

## 3. Core Security Goals

### 3.1 Computational Soundness
No computationally bounded adversary $\mathcal{A}$ without a valid, unrevoked, unexpired credential issued by a trusted KYC authority can generate a proof $\pi$ and public signals that satisfy `verifyPresentation()`, except with negligible probability:
$$\Pr[\text{Verify}(\text{vk}, x, \pi) = 1 \mid \text{Invalid}(\mathcal{A})] \le \text{negl}(\lambda)$$
Specifically, soundness covers:
1. **Issuer Signature Binding**: The attribute root must be signed under the trusted issuer public key $(A_x, A_y)$ using BabyJubJub EdDSA.
2. **Merkle Path Integrity**: Attribute leaves must belong to the signed root at designated slot indices (0 to 4).
3. **Claim Predicates**:
   - Date-of-Birth: $currentDate - dob \ge minAgeOffset$ (180000 for $\ge 18$ years under YYYYMMDD arithmetic).
   - KYC Status: $kycStatus = 1$.
   - Credential Expiry: $expiry \ge currentDate$.
4. **Revocation Membership**: The `credentialId` must be proven to reside in the published active credential tree `revocationRoot`.

### 3.2 Perfect / Computational Zero-Knowledge
The Groth16 proof $\pi = (A, B, C) \in \mathbb{G}_1 \times \mathbb{G}_2 \times \mathbb{G}_1$ leaks no computational information regarding private inputs (date of birth, credential ID, leaf salts, issuer signature scalars, or holder secret) beyond what is logically implied by the public signals. There exists a polynomial-time simulator $\mathcal{S}$ that can simulate valid-looking proofs given only the public signals.

### 3.3 Strict Holder Binding
Possession of credential data alone (even including all attribute values, salts, and the issuer signature) does not allow an adversary to generate a valid proof.
- The credential commits to $C_{holder} = \text{Poseidon}(s_{holder})$.
- The presentation circuit enforces knowledge of the preimage $s_{holder}$ such that:
  $$\text{Poseidon}(s_{holder}) == C_{holder}$$
- The nullifier is bound to this same secret:
  $$\text{nullifier} = \text{Poseidon}(s_{holder}, spId)$$
- Therefore, credential theft, leakage of credential files, or un-consented sharing fails because the recipient cannot prove knowledge of $s_{holder}$ without the user's hardware/passphrase-protected secret.

### 3.4 Replay and Cross-Context Resistance
- **Challenge Nonce**: Each verification request issues a fresh random scalar field challenge $c \xleftarrow{\$} \mathbb{F}_r$ with a finite time-to-live (TTL, e.g. 5 minutes).
- The presentation circuit enforces:
  $$\text{publicChallenge} == c$$
- Upon receipt of a presentation, the verifier consumes $c$ immediately (marking it used in an atomic transaction). Any replayed proof with the same challenge is rejected.
- **Service Provider Binding**: The circuit enforces $\text{publicSpId} == spId_{verifier}$. A proof generated for Service Provider A cannot be forwarded or replayed to Service Provider B.

### 3.5 Unlinkability Across Service Providers
The nullifier is defined as:
$$\text{nullifier}_{SP} = \text{Poseidon}(s_{holder}, spId)$$
- **Pseudorandomness**: Under the cryptographic pseudo-random function (PRF) assumption for Poseidon, $\text{nullifier}_{SP}$ is computationally indistinguishable from uniform random noise for any party that does not possess $s_{holder}$.
- **Unlinkability**: For two distinct service providers $spId_1 \ne spId_2$, the values $\text{nullifier}_{SP_1}$ and $\text{nullifier}_{SP_2}$ are independent random variables in $\mathbb{F}_r$. Neither service provider (nor a colluding coalition of service providers) can link them to the same holder.
- **Collusion Resistance**: Even if the Issuer colludes with Service Provider $i$, the Issuer knows $C_{holder} = \text{Poseidon}(s_{holder})$, but cannot invert Poseidon to recover $s_{holder}$, and thus cannot compute or correlate $\text{Poseidon}(s_{holder}, spId_i)$.

---

## 4. Specific Attack Vectors and Mitigations

| Attack Vector | Adversary Action | Architectural Mitigation |
| :--- | :--- | :--- |
| **Proof Malleability** | Adversary mutates Groth16 proof group elements $(\alpha A, \dots)$ to generate a fresh-looking proof for the same public signals. | The verifier **never** uses proof bytes as a transaction/receipt identifier or replay check. Uniqueness and replay protection rely exclusively on the single-use `challenge` state and `nullifier`. |
| **Non-Canonical Field Elements** | Adversary submits public signal integers $x \ge r$ or $x < 0$ to cause field wrapping or verification parser discrepancies. | Verifier explicitly parses and enforces $0 \le x < r$ for every public signal before invoking SnarkJS verification. |
| **Public Signal Reordering** | Adversary swaps positions of public inputs (e.g. swapping `challenge` and `nullifier`). | Fixed public signal schema in `spec/claim-interface.md` checked by length, index, and hash matching against `manifest.json`. |
| **Expired / Stale Credential** | User attempts to prove validity after $expiry < currentDate$. | Enforced inside the circuit via numeric constraint $expiry - currentDate \ge 0$. |
| **Revoked Credential** | User attempts to prove eligibility after credential revocation. | Verifier checks proof against latest known `revocationRoot`. Circuit proves membership in active tree. |
| **Expired Challenge** | Adversary intercepts a proof and replays it after the challenge expires. | Server tracks timestamped challenges and rejects any challenge whose TTL has elapsed. |
| **Verifier Impersonation** | Malicious SP attempts to reuse a proof created for a legitimate bank. | Verifier checks its own `spId` against public signal $spId$. |
| **Audit Log De-anonymization** | Attacker accesses verifier audit logs to compromise user identities. | Audit logs record **only** `(nullifier, timestamp, accepted)`. No attribute values, salts, or proof data are ever persisted. |

---

## 5. Residual Risks and System Assumptions

1. **Trusted Setup**: The Groth16 zk-SNARK requires a trusted setup ceremony (Phase 1 Powers of Tau + Phase 2 circuit-specific zKey). The final deployment relies on a publicly verified Hermez ceremony contribution for Phase 1. Local setups are strictly restricted to testing and development.
2. **Client Endpoint Security**: The user's device is assumed to safeguard `holderSecret` (e.g. encrypted in IndexedDB via PBKDF2 + AES-GCM). Device-level malware that captures `holderSecret` could impersonate the holder until the credential is revoked.
3. **Issuer Key Integrity**: If the KYC Authority's private BabyJubJub signing key is compromised, an attacker can issue forged credentials. Key rotation procedures and short-lived credential expiry mitigate this risk.
