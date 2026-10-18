pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template KycClaims() {
    signal input age;
    signal input kycVerified;
    signal output isAdult;
    signal output isVerified;

    component ageRange = Num2Bits(8);
    ageRange.in <== age;

    component underage = LessThan(8);
    underage.in[0] <== age;
    underage.in[1] <== 18;
    isAdult <== 1 - underage.out;

    kycVerified * (kycVerified - 1) === 0;
    isVerified <== kycVerified;
}

component main = KycClaims();