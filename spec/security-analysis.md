# Security Analysis and Cryptographic Soundness

**Project**: Privacy-Preserving Digital KYC System Using Zero-Knowledge Proofs  
**Author**: Someshwar Singh (231020) — Verification, Security and Optimization  
**Deliverable**: Task S11 — Security Analysis for Final Project Report  

---

## 1. Soundness Analysis per Constraint Group

The target zk-SNARK presentation circuit enforces multiple independent constraint groups. Soundness guarantees that an adversary $\mathcal{A}$ cannot produce an accepted proof without satisfying all constraint groups simultaneously. Below is the formal analysis of each group and the specific attack prevented:

| Constraint Group | Circom Sub-Template / Constraints | Mathematical Relation Enforced | Attack Prevented by this Group |
| :--- | :--- | :--- | :--- |
| **1. Age Verification** | `AgeAtLeast` / `LessThan(32)` | $currentDate - dob \ge minAgeOffset$ | **Underage access**: Prover cannot claim $\ge 18$ if their date of birth yields an age under 18. |
| **2. KYC Status** | `isVerified` assertion | $kycStatus \cdot (1 - kycStatus) = 0 \land kycStatus = 1$ | **Unverified status assertion**: Prevents non-boolean or unverified (0) status from producing a proof. |
| **3. Credential Expiry** | `NotExpired` / `LessThan(32)` | $expiry - currentDate \ge 0$ | **Stale / Expired credential use**: An expired credential cannot be presented as valid. |
| **4. Issuer Signature** | `EdDSAPoseidonVerifier` | $\text{EdDSA-Verify}(A, R, S, \text{root}) = 1$ | **Forged credential**: Ensures the attribute Merkle root was authentically signed by the KYC Authority with BabyJubJub private key. |
| **5. Attribute Inclusion** | `MerkleInclusion(3)` | $\text{MerklePath}(\text{leaf}_i, \text{path}_i) = \text{root}$ | **Attribute substitution**: Prover cannot mix-and-match attributes from different credentials or inject fake leaves. |
| **6. Holder Binding** | `Poseidon(1)` | $\text{Poseidon}(s_{holder}) = C_{holder}$ | **Credential theft / Credential sharing**: Possession of credential files without knowledge of secret $s_{holder}$ yields no valid proof. |
| **7. Nullifier Output** | `Poseidon(2)` | $\text{nullifier} = \text{Poseidon}(s_{holder}, spId)$ | **Sybil attacks / Re-identification**: Enforces deterministic, per-SP pseudonymity; prevents cross-SP correlation. |
| **8. Revocation Check** | `RevocationMembership(16)` | $\text{MerklePath}(\text{credId}, \text{revPath}) = \text{revRoot}$ | **Revoked credential reuse**: Prover cannot generate a valid proof if their credential was revoked. |
| **9. Nonce Binding** | Wire equality | $challenge_{public} = challenge_{verifier}$ | **Proof replay**: Intercepted proofs cannot be presented against a new session or verifier. |

Note: since the V6 optimisation, group 5 is implemented as `AttributeLeaf` ×5 plus `CredentialRoot8`, which rebuilds the whole 8-leaf tree. It no longer uses five `MerkleInclusion(3)` paths. The challenge is a public input, so Groth16 binds it to the proof. The `challengeSquare` constraint keeps it inside the constraint system. Replay is stopped by the verifier's single-use challenge store, which `test/e2e.test.mjs` checks with real proofs.

### Ablation evidence (V7)

`test/ablation.test.mjs` compiles `test/ablation/kyc_ablation.circom` seven times: once complete as a control, and once with each constraint group removed. For each group, a forged witness is rejected by the control and accepted by the weakened circuit. A satisfying witness is all a prover needs to produce a Groth16 proof, so each group is shown to be necessary.

| Group removed | Forgery that then succeeds |
| :--- | :--- |
| Issuer signature | Self-signed credential presented under the trusted issuer key |
| Credential-tree link (signature on a supplied root) | A minor reuses a genuine signature but substitutes an adult date of birth |
| `kycStatus = 1` | Validly signed credential whose KYC status is not verified |
| Expiry check | Credential that expired the day before |
| Holder binding | Stolen credential file used without the holder secret |
| Revocation membership | Revoked credential proving against the current root |
| Date range check (`test/subtemplates.test.mjs`) | Field-wrapping "negative" date of birth passes the age check |

---

## 2. Public Signal Information Disclosure Analysis

The presentation statement exposes exactly eight public signals. We analyze the information revealed by each:

1. **`nullifier = Poseidon(s_holder, spId)`**:
   - *Information revealed*: A pseudorandom element in $\mathbb{F}_r$.
   - *Leakage*: The verifier learns only whether this same holder has visited *this specific service provider* before (for rate limiting, duplicate account prevention, or audit logging). Under the pseudo-random function (PRF) assumption for Poseidon, $\text{nullifier}$ is computationally indistinguishable from uniform random noise to any party not knowing $s_{holder}$, and is mathematically unlinkable across different service providers ($spId_A \ne spId_B$).
2. **`issuerAx, issuerAy`**:
   - *Information revealed*: The KYC Authority's public key coordinates.
   - *Leakage*: Reveals which trusted authority accredited the user. Zero user-specific data is revealed.
3. **`currentDate`**:
   - *Information revealed*: Calendar date (`YYYYMMDD`) supplied by the verifier during challenge issuance.
   - *Leakage*: Zero user attribute data revealed.
4. **`minAgeOffset`**:
   - *Information revealed*: Constant `180000` (threshold for 18 years).
   - *Leakage*: Zero user attribute data revealed.
5. **`challenge`**:
   - *Information revealed*: Verifier-generated random nonce.
   - *Leakage*: Zero user attribute data revealed.
6. **`spId`**:
   - *Information revealed*: Verifier's own identifier.
   - *Leakage*: Zero user attribute data revealed.
7. **`revocationRoot`**:
   - *Information revealed*: The Merkle root of the active credential registry.
   - *Leakage*: An accumulator of active credential count. Reveals zero individual credential IDs or indices.

**Conclusion**: The verifier and network eavesdroppers learn **strictly the boolean validity** of the predicates (age $\ge 18$, KYC status verified, valid unrevoked credential) and a per-service pseudonym. Date of birth, name, nationality, credential ID, attribute salts, and root signatures remain completely confidential.

---

## 3. Groth16 Proof Malleability Defense

### Vulnerability Mechanism:
The Groth16 proof consists of group elements:
$$\pi = (A \in \mathbb{G}_1, B \in \mathbb{G}_2, C \in \mathbb{G}_1)$$
Because the pairing check evaluates:
$$e(A, B) = e(\alpha, \beta) + e(x \cdot \gamma, \delta) + e(C, \delta)$$
for any non-zero scalar $k \in \mathbb{F}_r^*$, an attacker can randomize the proof elements (e.g. $A' = k A, B' = k^{-1} B$) such that $e(A', B') = e(A, B)$. This produces a syntactically distinct proof $(\pi' \ne \pi)$ that verifies under the exact same public signals.

### Mitigation:
If a system naively tracks "seen proofs" by hashing proof bytes:
$$\text{seenProofs}.\text{add}(\text{SHA256}(\text{proof}))$$
an attacker can bypass replay protection by submitting $\pi'$.

In our architecture:
1. **Proof bytes are NEVER used as identifiers or replay tokens.**
2. Replay resistance is strictly governed by single-use challenge consumption in `ChallengeStore`:
   - A unique nonce $c \in \mathbb{F}_r$ is generated per request.
   - The challenge is marked `used = true` immediately upon receipt of the first presentation attempt.
   - Any subsequent presentation carrying $c$ is rejected immediately with `CHALLENGE_ALREADY_USED`, regardless of whether the proof bytes were mutated.
3. Presentation receipts are identified by:
   $$\text{receiptId} = \text{SHA256}(nullifier \parallel challenge \parallel spId)$$
   which is invariant to proof malleability.

---

## 4. Trusted Setup & Cryptographic Assumptions

1. **Security Assumptions**:
   - Discrete Logarithm (DL) and Computational Diffie-Hellman (CDH) hardness over BN254 $\mathbb{G}_1$ and $\mathbb{G}_2$.
   - Symmetric / Asymmetric Pairing assumption ($e: \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_T$).
   - Collision resistance and pseudo-random function properties of the Poseidon algebraic hash function over $\mathbb{F}_r$.
   - EdDSA unforgeability under chosen message attacks (EUF-CMA) on the BabyJubJub curve.
2. **Phase 1 Powers of Tau**:
   - Production deployments rely on public multi-party computation (MPC) ceremonies (e.g. Hermez / Perpetual Powers of Tau) where soundness holds as long as at least one ceremony participant was honest.
   - For local development, `scripts/setup-demo.mjs` generates an isolated testing setup, which must never be used in production.
3. **Phase 2 Circuit-Specific Ceremony**:
   - The circuit-specific proving key $\text{zkey}$ is generated and verified using `snarkjs.zKey.verifyFromR1cs`.
   - The cryptographic verification key hash is pinned in `manifest.json` and validated by `VerifierEngine` at startup.

---

## 5. Key Compromise and Recovery

| Key / Secret | Impact of Compromise | Recovery & Mitigation Protocol |
| :--- | :--- | :--- |
| **KYC Authority Private Key ($k_{sk}$)** | Adversary could mint forged credentials for arbitrary users. | 1. Key rotation: Verifier updates `trustedIssuerKey` set.<br/>2. Revocation: The issuer revokes invalid roots.<br/>3. Short expiration: Credentials have fixed `expiry` dates, limiting window of validity. |
| **Holder Secret ($s_{holder}$)** | Adversary holding both the credential JSON and $s_{holder}$ can impersonate the user. | 1. Holder secret is encrypted at rest in IndexedDB using PBKDF2 + AES-GCM.<br/>2. User requests credential revocation from KYC Authority.<br/>3. Issuer revokes `credentialId`, invalidating all future presentations. |
| **Service Provider Identifier ($spId$)** | Malicious SP attempts to elicit proofs intended for another SP. | Proofs are strictly bound to $spId$. The verifier verifies that public signal $spId == spId_{verifier}$. |

---

## 6. Verifier Fail-Closed Architectural Pattern

The `VerifierEngine` enforces a 9-step fail-closed pipeline:
1. **Schema Check** $\to$ Reject malformed payloads immediately.
2. **Signal Count & Order** $\to$ Enforce exactly 8 public signals in deterministic order.
3. **Field Canonicalization** $\to$ Enforce $0 \le x < r$ for every signal, preventing field-wrapping attacks.
4. **Issuer Key Match** $\to$ Ensure $A = (A_x, A_y)$ belongs to the trusted authority.
5. **Date Consistency** $\to$ Reject stale or manipulated dates.
6. **Challenge Freshness** $\to$ Validate challenge existence, unexpired TTL, and atomic single-use mark.
7. **Service Provider Match** $\to$ Reject proofs targeted at other service providers.
8. **Revocation Tree Membership** $\to$ Ensure root belongs to active credential tree history.
9. **Groth16 Pairing Verification** $\to$ Verify cryptographic proof against trusted $\text{vk}$.
