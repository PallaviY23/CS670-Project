# Credential Module

Owner: Reddi Pallavi

The module in `credential.mjs` provides a first credential prototype:

- The issuer signs a Poseidon hash over the credential commitment and metadata using EdDSA-Poseidon.
- `age` and `kycVerified` each have an independently salted Poseidon leaf in a two-leaf Merkle commitment.
- A wallet can create a presentation that reveals only selected attributes and their inclusion paths.
- A verifier checks the issuer against a trusted public key, the signature, expiry, and each disclosed Merkle path.

Run the credential tests with `node --test test/credential.test.mjs`.

This module is not yet bound to `circuits/kyc_claims.circom`. Attribute disclosure reveals the selected value; proving `age >= 18` without revealing age still requires the circuit owner to add commitment membership and issuer-signature verification. KYC status is a Boolean claim only, not a credential-revocation mechanism. See `spec/claim-interface.md` before integrating signal changes.