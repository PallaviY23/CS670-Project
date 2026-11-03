# Groth16 Proving Pipeline

Owner: Durbasmriti Saha. This document covers the proving side of the system (trusted setup, artifacts, witness and proof generation, wallet storage) and the performance results used in the evaluation section of the report.

## 1. Pipeline overview

```
circuits/*.circom ──circom2──▶ r1cs + wasm + sym
                                   │
            build/ptau (cached) ───┼──▶ setupCircuit()  ──▶ proving key (zkey) + verification key
                                   │       └─ zKey.verifyFromR1cs check
                                   ▼
                         build/circuit/manifest.json  (constraints, public signal order, SHA-256 of every artifact)
                                   │
Browser ──────────────────────────────────────────────────────────────────────────
  wallet (IndexedDB, encrypted holder secret)
     │  credential + request
     ▼
  buildPresentationInput()  ── readable pre-checks (underage, expired, wrong issuer, stale revocation root…)
     │  witness input (never leaves the tab)
     ▼
  Web Worker: load wasm + zkey (Cache API, hash-checked against manifest) → wtns.calculate → groth16.prove
     │  { proof, publicSignals, timings }
     ▼
  Service Provider API  /api/sp/verify
```

## 2. Components

| File | Purpose |
| --- | --- |
| `src/prover/setup.js` | Sizes the Powers of Tau from the r1cs (same rule as snarkjs), reuses a cached `build/ptau/potN_final.ptau` or generates one, creates the zkey, checks it with `zKey.verifyFromR1cs`, exports the verification key, writes the manifest. `PTAU_FILE=<path>` uses an external ceremony file such as the public Hermez one. PLONK/FFLONK setups grow the ptau until setup succeeds. |
| `src/prover/prove.js` | `prove(input, { wasm, zkey, protocol })` runs witness generation and proving as two timed steps, and `verify()` is timed too. Inputs may be paths or `Uint8Array`s, so the same code runs in Node and the browser. `proofSize()` reports the raw affine size and the JSON size. |
| `src/prover/inputs.js` | `buildPresentationInput()` maps the signed 8-slot credential and current revocation path to the exact `KycPresentation` witness schema. It validates dates, issuer, policy, challenge expiry, accepted root, and field elements before witness generation. Every failure is a `ProverInputError` with a `code`. |
| `src/prover/artifacts.js` | SHA-256 checks of artifacts against the manifest (`ArtifactIntegrityError`). |
| `src/prover/browser-loader.js` | Downloads wasm and zkey once, stores them in the Cache API under their manifest hash, and re-checks the hash on every load. |
| `src/prover/prover.worker.js`, `worker-client.js` | Proving runs in a Web Worker with progress events (`artifacts`, `witness`, `proof`), so the UI stays responsive. |
| `src/wallet/` | `createWallet()`: holder secret generated on the device (uniform non-zero BN254 element), encrypted with PBKDF2-SHA256 (600 000 iterations) + AES-256-GCM. Credentials are stored only after the injected `verifyCredential` (credential module) accepts them, and the list view never shows private attributes. Storage is IndexedDB in the browser or in-memory for tests. |
| `scripts/setup-demo.mjs` | Demo setup using the above; defaults to `kyc_presentation`. `npm run setup:demo` compiles this circuit and generates local development-only setup artifacts. |
| `scripts/bench*.mjs` | Benchmarks (§4). |

### Commands

```powershell
npm test                    # circuit build + all credential, circuit, prover, input and wallet tests
npm run setup:demo          # presentation circuit + ptau (cached) + zkey + verification key + manifest
npm run bench               # Node, Groth16, 30 runs
npm run bench:compare       # Groth16 vs PLONK vs FFLONK
npm run bench:components    # Merkle depth and EdDSA cost
npm run bench:browser       # headless Chrome/Edge, via web/bench.html
```

Results are written to `build/bench/` as JSON plus per-run and summary CSV files, ready for plotting.

## 3. Security-relevant choices

- **Proving key check:** setup fails unless `zKey.verifyFromR1cs` confirms that the zkey matches the circuit and the Powers of Tau.
- **Artifact integrity:** the browser rejects a wasm or zkey whose SHA-256 differs from the manifest, and drops cached copies that fail the check. The manifest also lets the verifier pin the verification-key hash (verifier module).
- **Witness locality:** the witness is built and consumed inside the worker. The API receives the proof, public signals, and request ID, not the credential, DOB, holder secret, or witness.
- **Development ceremony:** the locally generated ptau and zkey contribution use one random contribution each. They are fine for the prototype, but not a substitute for a multi-party ceremony (`PTAU_FILE` allows the public Hermez file).
- **Wallet:** the holder secret never touches storage in plain text. A wrong passphrase or modified ciphertext fails AES-GCM authentication. Credentials that fail the issuer check are never stored.

## 4. Results

Host: AMD Ryzen 3 5300U (4 cores / 8 threads), Windows 11, Node 20.17.0, headless Chrome 156. Means are over measured runs after warm-up; p95 is the 95th percentile.

### 4.1 Starter circuit: proof-system comparison (Node, 30 runs, 3 warm-up)

| Protocol | Constraints | Proof (raw) | Proving key | Witness ms | Prove ms (mean / p95) | Verify ms |
| --- | --- | --- | --- | --- | --- | --- |
| Groth16 | 18 | **256 B** | 12.7 KB | 45.2 | **41.8** / 51.0 | 15.9 |
| PLONK | 18 | 768 B | 108.0 KB | 36.8 | 108.4 / 116.5 | 13.0 |
| FFLONK | 18 | 768 B | 156.5 KB | 37.6 | 132.0 / 139.9 | 10.2 |

Groth16 gives the smallest proof and the fastest proving. Its cost is a circuit-specific trusted setup, whereas PLONK and FFLONK need only the universal ceremony. Verification is about 10–16 ms for all three in snarkjs; on-chain, FFLONK is the cheapest of the three to verify.

### 4.2 Browser (headless Chrome, Web Worker, 30 runs, 3 warm-up)

| | Mean | Median | p95 |
| --- | --- | --- | --- |
| Witness | 25.3 ms | 6.0 ms | 91.4 ms |
| Proof | 55.3 ms | 45.5 ms | 123.5 ms |
| Total in worker | 80.6 ms | 51.8 ms | 179.8 ms |

The cold first proof took 259 ms, of which 48 ms was downloading and hash-checking the artifacts. Later proofs reuse the cached, verified artifacts.

### 4.3 Building blocks of the credential-bound circuit (Node, Groth16, 10 runs, 2 warm-up)

| Component | Constraints | Proving key | Prove ms (mean / p95) | Verify ms |
| --- | --- | --- | --- | --- |
| Poseidon Merkle inclusion, depth 3 | 729 | 0.4 MB | 109.8 / 121.1 | 17.8 |
| Poseidon Merkle inclusion, depth 10 | 2 430 | 1.4 MB | 265.4 / 284.5 | 15.9 |
| Poseidon Merkle inclusion, depth 16 | 3 888 | 2.1 MB | 353.7 / 372.7 | 14.2 |
| Poseidon Merkle inclusion, depth 20 | 4 860 | 2.9 MB | 475.0 / 487.0 | 15.0 |
| EdDSA-Poseidon signature check | 4 217 | 2.7 MB | 378.6 / 407.8 | 15.6 |

**Observations:**
- Each Merkle level costs exactly 243 constraints (one Poseidon(2) plus the selector), so constraints grow linearly with tree depth. Proving time also grows roughly linearly, at about 0.1 ms per constraint on this machine.
- Verification time is flat at about 15 ms whatever the circuit size, as expected for Groth16.
- Issuer binding (EdDSA) costs about as much as a depth-17 Merkle proof.

### 4.4 Earlier estimate for the full presentation circuit

| Part | Constraints |
| --- | --- |
| Issuer signature (EdDSA-Poseidon) | 4 217 (measured) |
| Revocation membership, depth 20 / 16 | 4 860 / 3 888 (measured) |
| Credential openings: 5 slots × depth 3 | 3 645 (measured), plus about 5 leaf hashes |
| Holder commitment, nullifier, date range checks, comparators | ≈ 1 000 (estimate) |
| **Total** | **≈ 13–15 k** |

This estimate predates the merged whole-tree optimization. The current circuit constraint count is recorded in the generated manifest; the exact setup and proving time depend on the machine. It needs a 2^14 Powers of Tau, which `setupCircuit` selects automatically.

**Optimisation for the circuit design:** the circuit could rebuild the depth-3 credential root once from all 8 leaves, taking the 3 unopened slots as leaf hashes. That needs 7 Poseidon(2) hashes (1 701 constraints) instead of 15 for five separate openings (3 645), saving about 1 900 constraints, or roughly 13 % of the circuit.

## 5. Integration status and open points

| Item | Status |
| --- | --- |
| D1 ptau sizing, caching, zkey verification | Done |
| D2 build manifest | Done; served at `/api/prover/manifest` |
| D3 witness-input builder | Done; matches the frozen `KycPresentation` interface (V1) and is used by the UI. `test/presentation-credential.test.mjs` checks it against the compiled circuit |
| D4 timed `prove()` / `verify()` | Done |
| D5 cached, hash-checked browser artifacts | Done; the verifier also pins the verification-key hash from the manifest at start-up |
| D6 Web Worker proving | Done; the UI uses it |
| D7 wallet storage | Done; uses `verifyCredential` (P5) on issue and import, with export/import in the UI |
| D8 wallet view | Done: wallet unlock, issued credential, consent screen with the disclosure policy (P7), proof progress, receipt with nullifier and public signals, network inspector (A4) |
| D9 benchmarks | Done (Node and browser), re-run on the final circuit (§4.1) |
| D10 comparisons | Done (proof systems, Merkle depth, EdDSA cost) |
| D11 CI | Dropped (course project); run `npm test` locally before pushing |
| D12 report section | This document |

End-to-end coverage with real proofs is in `test/e2e.test.mjs`: issue → wallet → input → Groth16 → verifier, then replay, tampered signals, a different verification key, and revocation. It also asserts that the submitted presentation contains no DOB, salt, credential ID or holder secret.
