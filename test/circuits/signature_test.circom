pragma circom 2.1.6;
include "../../circuits/lib/signature.circom";
template T() {
    signal input Ax; signal input Ay; signal input R8x; signal input R8y; signal input S; signal input root;
    component s = IssuerSignature();
    s.Ax <== Ax; s.Ay <== Ay; s.R8x <== R8x; s.R8y <== R8y; s.S <== S; s.root <== root;
}
component main = T();
