pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";

// Leaf of the credential Merkle tree: Poseidon(slot, value, salt).
// `slot` is a compile-time constant, so a leaf hashed for one slot can
// never be reused as a different slot.
template AttributeLeaf(slot) {
    signal input value;
    signal input salt;
    signal output leaf;

    component h = Poseidon(3);
    h.inputs[0] <== slot;
    h.inputs[1] <== value;
    h.inputs[2] <== salt;
    leaf <== h.out;
}
