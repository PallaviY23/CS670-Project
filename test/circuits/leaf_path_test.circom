pragma circom 2.1.6;
include "../../circuits/lib/attribute_leaf.circom";
include "../../circuits/lib/merkle.circom";
// Opens slot 1 (dob) of a depth-3 tree.
template T() {
    signal input value; signal input salt; signal input siblings[3];
    signal output leaf; signal output root;
    component l = AttributeLeaf(1); l.value <== value; l.salt <== salt;
    component p = MerkleInclusionFixed(3, 1); p.leaf <== l.leaf;
    for (var i = 0; i < 3; i++) p.siblings[i] <== siblings[i];
    leaf <== l.leaf; root <== p.root;
}
component main = T();
