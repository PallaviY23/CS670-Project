pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";

// Internal node hash used everywhere: Poseidon(left, right).
template HashPair() {
    signal input left;
    signal input right;
    signal output out;
    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    out <== h.out;
}

// Inclusion proof for a leaf at a FIXED position `index` (compile-time).
// Used for the credential tree: the slot number decides the path, so the
// prover cannot open a leaf at a different position. No path bits needed.
template MerkleInclusionFixed(depth, index) {
    signal input leaf;
    signal input siblings[depth];
    signal output root;

    component hashers[depth];
    signal cur[depth + 1];
    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        hashers[i] = HashPair();
        if (((index >> i) & 1) == 0) {
            hashers[i].left  <== cur[i];
            hashers[i].right <== siblings[i];
        } else {
            hashers[i].left  <== siblings[i];
            hashers[i].right <== cur[i];
        }
        cur[i + 1] <== hashers[i].out;
    }
    root <== cur[depth];
}

// Inclusion proof with a PRIVATE position (path bits supplied by prover).
// Used for the revocation tree, where the position must stay hidden.
// pathIndices[i] = 0 -> current node is the left child, 1 -> right child.
template MerkleInclusion(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input pathIndices[depth];
    signal output root;

    component hashers[depth];
    signal cur[depth + 1];
    signal left[depth];
    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // path bit must be boolean, otherwise the swap below is meaningless
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        // b = 0: (cur, sib)   b = 1: (sib, cur)
        left[i] <== cur[i] + pathIndices[i] * (siblings[i] - cur[i]);

        hashers[i] = HashPair();
        hashers[i].left  <== left[i];
        hashers[i].right <== cur[i] + siblings[i] - left[i];
        cur[i + 1] <== hashers[i].out;
    }
    root <== cur[depth];
}

// Builds the WHOLE depth-3 credential tree once (V6 optimisation).
// Leaves 0..4 are computed in-circuit; leaves 5..7 (slots not used by this
// claim) are supplied as opaque hashes. Positions are fixed by construction,
// so a leaf cannot be moved to another slot. 7 Poseidon(2) calls instead of
// 15 for five separate inclusion proofs.
template CredentialRoot8() {
    signal input leaves[8];
    signal output root;

    component l1[4];
    for (var i = 0; i < 4; i++) {
        l1[i] = HashPair();
        l1[i].left  <== leaves[2 * i];
        l1[i].right <== leaves[2 * i + 1];
    }
    component l2[2];
    for (var i = 0; i < 2; i++) {
        l2[i] = HashPair();
        l2[i].left  <== l1[2 * i].out;
        l2[i].right <== l1[2 * i + 1].out;
    }
    component top = HashPair();
    top.left  <== l2[0].out;
    top.right <== l2[1].out;
    root <== top.out;
}
