pragma circom 2.1.6;
include "circomlib/circuits/eddsaposeidon.circom";

// Asserts that (R8x, R8y, S) is a valid EdDSA-Poseidon signature on
// `root` under the KYC Authority public key (Ax, Ay) on BabyJubJub.
// Must match circomlibjs eddsa.signPoseidon(privateKey, root).
template IssuerSignature() {
    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input root;

    component v = EdDSAPoseidonVerifier();
    v.enabled <== 1;
    v.Ax  <== Ax;
    v.Ay  <== Ay;
    v.R8x <== R8x;
    v.R8y <== R8y;
    v.S   <== S;
    v.M   <== root;
}
