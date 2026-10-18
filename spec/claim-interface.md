# Initial Claim Interface

The starter circuit accepts two private witness values:

| Signal | Meaning | Constraint in starter |
| --- | --- | --- |
| `age` | Age in whole years | Must be in the range 0 to 255 |
| `kycVerified` | KYC status bit | Must be exactly 0 or 1 |

It exposes two public outputs:

| Signal | Meaning |
| --- | --- |
| `isAdult` | 1 when `age >= 18`, otherwise 0 |
| `isVerified` | The constrained KYC status bit |

## Security Boundary

This is a wiring contract for parallel development, not the final credential protocol. In particular, `kycVerified = 1` is currently self-asserted by the witness. Before the verifier can treat it as authoritative, the team must bind the status and age claim to an issuer-authenticated credential (and define revocation/public-input handling).

Coordinate changes to signal names, visibility, integer ranges, or credential binding here before changing module interfaces.