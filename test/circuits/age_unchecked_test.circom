pragma circom 2.1.6;
include "../../circuits/lib/dates.circom";
// Deliberately WITHOUT DateRange: shows why range checks are required.
template T() {
    signal input dob; signal input currentDate; signal input minAgeOffset;
    signal sum; sum <== dob + minAgeOffset;
    component bits = Num2Bits(33); bits.in <== sum;   // what a naive design might do
    component age = AgeAtLeast();
    age.dob <== dob; age.currentDate <== currentDate; age.minAgeOffset <== minAgeOffset;
}
component main = T();
