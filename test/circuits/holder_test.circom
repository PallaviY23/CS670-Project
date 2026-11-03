pragma circom 2.1.6;
include "../../circuits/lib/holder.circom";
template T() {
    signal input holderSecret; signal input spId;
    signal output holderCommitment; signal output nullifier;
    component h = HolderBinding(); h.holderSecret <== holderSecret;
    component n = Nullifier(); n.holderSecret <== holderSecret; n.spId <== spId;
    holderCommitment <== h.holderCommitment; nullifier <== n.nullifier;
}
component main = T();
