# Demo Script (A9)

About 10 minutes. It covers the scenarios in the task plan: valid user, underage user, tampered credential, replayed proof, revoked credential and the network inspector. The unverified-user and expired cases are shown through the test suite (§3), because the demo issuer only issues verified credentials.

## 0. Before the presentation

```powershell
npm install
npm run setup:demo        # first run: about 4 minutes (11,923 constraints, 2^14 Powers of Tau)
npm run dev               # API on :4000, website on http://localhost:5173
```

- Open the site in a fresh browser profile (or clear site data) so the wallet starts empty.
- Keep a terminal ready for `npm run test:circuit` and `npm run test:e2e`, which back up the claims made in §3.
- `npm test` no longer deletes the demo proving keys, so running tests before the demo is safe.

## 1. Live walk-through

| # | Action in the UI | What to say / point at |
|---|---|---|
| 1 | Enter a passphrase, then **Create / unlock wallet** | The holder secret is generated in the browser and stored encrypted (PBKDF2 + AES-GCM) in IndexedDB. Only its Poseidon commitment ever leaves the browser. |
| 2 | Keep DOB `2000-06-15`, then **Issue and store demo credential** | The KYC Authority signs an 8-slot Poseidon root. The wallet re-checks the signature before storing. **Network inspector:** the issuer request is the only one flagged *CONTAINS DOB*. |
| 3 | **Generate & verify** → consent screen | It shows what the service learns (nullifier, issuer key, date and policy, challenge and service ID, revocation root) and what stays in the wallet. |
| 4 | **Approve & prove** | Progress: loading artifacts → witness → Groth16 proof, all in a Web Worker. The receipt shows *Claims verified*, the nullifier, witness and prove times, and a 256 B proof. |
| 5 | Open the **Network inspector**, expand `POST /api/sp/verify` | The body holds only `requestId`, `proof` and 8 public signals, and is flagged *NO DOB*. |
| 6 | Generate & verify again | The nullifier is the same for this service (stable pseudonym). The challenge is new, so the proof is new too. |
| 7 | **Service Provider (SP)** tab | Challenge issuance, the revocation root, and an audit log that stores only receipt ID, nullifier, SP ID and time. |
| 8 | Revoke the displayed credential ID, return to the workspace, Generate & verify | It fails: *Credential … is revoked or not found in active registry*. No membership path exists, so no proof can be built. |
| 9 | Unlock with a wrong passphrase (reload the page first) | AES-GCM authentication fails, so the wallet stays locked. |

### Underage user

In the same wallet, issue a second credential with DOB set to *today minus 17 years*. The most recently issued credential is the one used. **Generate & verify** stops before proving with the readable error *does not satisfy the requested minimum age*. The prover's pre-check catches it, and the circuit would also reject it (see §3). Issue an adult DOB again to switch back. Both credentials give the same nullifier, because it depends on the wallet's holder secret and not on the credential.

### Tampered credential

Use **Export credential**, change `"dob"` in the JSON file, then **Import credential**. The import is refused with *failed its issuer signature check*.

### Replayed proof

The UI always asks for a fresh challenge, so show replay with the end-to-end test: `npm run test:e2e`, test *replaying an accepted presentation is rejected* (`CHALLENGE_ALREADY_USED`).

## 2. Talking points

- **Proof:** 256 bytes, about 11.9k constraints. Proving and verification times are in `docs/prover-pipeline.md` §4.
- **Why Groth16:** smallest proof and fastest verification. The cost is a circuit-specific setup, which here is development-only (one local contribution). PLONK and FFLONK comparison: `docs/prover-pipeline.md`.
- **Soundness:** each constraint group is necessary. `npm run test:circuit` includes the V7 ablation tests (`spec/security-analysis.md`, "Ablation evidence").
- **Known limits:**
  - The demo issuer does no real KYC.
  - The revocation-path lookup reveals the credential ID to the registry.
  - The setup is single-party.
  - The issuer and verifier run in one local API.

## 3. Evidence for cases not shown live

| Case | Test |
|---|---|
| Unverified (`kycStatus = 0`) | `test/presentation.test.mjs`: *kycStatus = 0 (validly signed) is rejected* |
| Expired credential | `test/presentation.test.mjs`: *expired credential rejected* |
| Wrong issuer key / self-signed | `test/presentation.test.mjs`, `test/ablation.test.mjs` |
| Exactly 18 today / one day short / 29 Feb | `test/presentation.test.mjs`, `test/subtemplates.test.mjs` |
| Replay, tampered signals, wrong verification key, revoked (real Groth16 proofs) | `test/e2e.test.mjs` |
| Verifier policy attacks (wrong SP, stale date, non-canonical values, …) | `test/verifier_attacks.test.mjs` |
