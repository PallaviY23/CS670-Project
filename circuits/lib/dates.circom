pragma circom 2.1.6;
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Dates are integers in YYYYMMDD form (e.g. 20260315).
// DateRange forces 0 <= in < 2^32. This MUST be applied to every date
// before comparing, otherwise field arithmetic (mod p) lets a "negative"
// difference wrap around to a huge number and pass the comparison.
template DateRange() {
    signal input in;
    component bits = Num2Bits(32);
    bits.in <== in;
}

// Asserts currentDate >= dob + minAgeOffset.
// minAgeOffset = 180000 means "18 years" because adding 18 to YYYY adds
// 18 * 10000 to YYYYMMDD while leaving MMDD unchanged.
// PRECONDITION: dob, currentDate, minAgeOffset already range-checked to
// 32 bits (done once in the main circuit). Sum < 2^33, so 33-bit compare.
template AgeAtLeast() {
    signal input dob;
    signal input currentDate;
    signal input minAgeOffset;

    component ge = GreaterEqThan(33);
    ge.in[0] <== currentDate;
    ge.in[1] <== dob + minAgeOffset;
    ge.out === 1;
}

// Asserts expiry >= currentDate (credential still valid today).
// PRECONDITION: both range-checked to 32 bits.
template NotExpired() {
    signal input expiry;
    signal input currentDate;

    component ge = GreaterEqThan(33);
    ge.in[0] <== expiry;
    ge.in[1] <== currentDate;
    ge.out === 1;
}
