pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";

// The credential stores only holderCommitment = Poseidon(holderSecret).
// Recomputing it inside the circuit proves knowledge of holderSecret.
template HolderBinding() {
    signal input holderSecret;
    signal output holderCommitment;

    component h = Poseidon(1);
    h.inputs[0] <== holderSecret;
    holderCommitment <== h.out;
}

// Per-service-provider pseudonym: same holder + same SP -> same value,
// different SPs -> unlinkable values.
template Nullifier() {
    signal input holderSecret;
    signal input spId;
    signal output nullifier;

    component h = Poseidon(2);
    h.inputs[0] <== holderSecret;
    h.inputs[1] <== spId;
    nullifier <== h.out;
}
