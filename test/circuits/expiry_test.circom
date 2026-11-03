pragma circom 2.1.6;
include "../../circuits/lib/dates.circom";
template T() {
    signal input expiry; signal input currentDate;
    component a = DateRange(); a.in <== expiry;
    component b = DateRange(); b.in <== currentDate;
    component e = NotExpired(); e.expiry <== expiry; e.currentDate <== currentDate;
}
component main = T();
