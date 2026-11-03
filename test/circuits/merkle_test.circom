pragma circom 2.1.6;
include "../../circuits/lib/merkle.circom";
template T() {
    signal input leaf; signal input siblings[4]; signal input pathIndices[4];
    signal output root;
    component m = MerkleInclusion(4);
    m.leaf <== leaf;
    for (var i = 0; i < 4; i++) { m.siblings[i] <== siblings[i]; m.pathIndices[i] <== pathIndices[i]; }
    root <== m.root;
}
component main = T();
