# CS670-Project
Privacy-Preserving Digital KYC System Using Zero-Knowledge Proofs

Starter workspace for the team's privacy-preserving KYC prototype. The stack is Circom 2, circomlib, SnarkJS, React/Vite, and an Express verification API.

## Prerequisites

- Node.js 20 or later
- npm

## Setup

```powershell
npm install
npm test
```

Tests cover adult and underage circuit outputs, invalid circuit witnesses, credential signatures, selective attribute disclosures, tampering, issuer trust, and expiry. Generated files are written under `build/` and are ignored by Git.

## Run the Demo

Create local Groth16 proving and verification artifacts, then start the website and API:

```powershell
npm run setup:demo
npm run dev
```

Open `http://localhost:5173`. The first setup creates a local development-only ceremony; do not use its keys for production. Proofs are generated in the browser. The API receives only the proof and public outputs and does not store them.

Re-run `npm run setup:demo` after `npm test` or any circuit rebuild because rebuilding clears keys that could otherwise be stale.

## Work Areas

- `src/credential/`: issuer-signed Poseidon/Merkle credentials and selective presentations (Pallavi)
- `circuits/`: age and KYC claim constraints and circuit tests (Vaishnavi)
- `src/prover/`: witness/proof generation and proving performance (Durbasmriti)
- `src/verifier/`: proof/public-input verification and security tests (Someshwar)
- `web/`: interactive proof workspace
- `server/`: health, proof artifact, and verification endpoints
- `spec/`: shared interfaces and decisions that affect integration

Each owner can develop inside their module against the shared contracts in `spec/`. Keep cross-module changes small and coordinate interface changes before integrating. Pallavi's credential module is implemented and tested, but the current circuit still accepts self-asserted claims; issuer-signature and commitment verification inside the ZK circuit remain an integration task.

## Current Circuit Scope

`circuits/kyc_claims.circom` is an integration starter, not a production credential system. It proves the age comparison and that the supplied KYC flag is a bit. It does **not** prove that an authorized KYC Authority issued the flag, bind age to a credential, or provide revocation. The website marks the KYC flag as simulated. Those guarantees need to be designed and integrated before treating a proof as real KYC verification.

See [spec/claim-interface.md](spec/claim-interface.md) for the initial signal contract and security boundary.
