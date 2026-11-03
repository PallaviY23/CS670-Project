pragma circom 2.1.6;
include "../../circuits/lib/dates.circom";
template T() {
    signal input dob; signal input currentDate; signal input minAgeOffset;
    component a = DateRange(); a.in <== dob;
    component b = DateRange(); b.in <== currentDate;
    component c = DateRange(); c.in <== minAgeOffset;
    component age = AgeAtLeast();
    age.dob <== dob; age.currentDate <== currentDate; age.minAgeOffset <== minAgeOffset;
}
component main = T();
