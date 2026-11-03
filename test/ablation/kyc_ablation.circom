pragma circom 2.1.6;

// V7 ablation circuits: KycPresentation with exactly ONE constraint group
// removed (OFF, fixed at compile time). Used only by test/ablation.test.mjs to
// show which forgery each group prevents. Never used for proving. The test
// appends the `component main` line for each OFF value.
//   OFF = 1 issuer signature      OFF = 4 expiry
//   OFF = 2 credential-tree link  OFF = 5 holder binding
//   OFF = 3 kycStatus = 1         OFF = 6 revocation membership
// Keep the rest identical to circuits/kyc_presentation.circom.
include "../../circuits/lib/attribute_leaf.circom";
include "../../circuits/lib/merkle.circom";
include "../../circuits/lib/dates.circom";
include "../../circuits/lib/holder.circom";
include "../../circuits/lib/signature.circom";
include "../../circuits/RevocationMembership.circom";

template KycAblation(REV_DEPTH, OFF) {
    var NSLOTS = 5;

    signal input issuerAx;
    signal input issuerAy;
    signal input currentDate;
    signal input minAgeOffset;
    signal input challenge;
    signal input spId;
    signal input revocationRoot;

    signal input credentialId;
    signal input dob;
    signal input kycStatus;
    signal input expiry;
    signal input holderSecret;
    signal input salts[NSLOTS];
    signal input otherLeaves[3];
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input revSiblings[REV_DEPTH];
    signal input revPathIndices[REV_DEPTH];
    // Ablation-only inputs, ignored unless their group is OFF.
    signal input signedRoot;          // OFF = 2: root the signature is checked on
    signal input holderCommitment;    // OFF = 5: slot-4 value supplied, not computed

    signal output nullifier;

    component holder = HolderBinding();
    holder.holderSecret <== holderSecret;

    signal values[NSLOTS];
    values[0] <== credentialId;
    values[1] <== dob;
    values[2] <== kycStatus;
    values[3] <== expiry;
    if (OFF == 5) {
        values[4] <== holderCommitment;
    } else {
        values[4] <== holder.holderCommitment;
    }

    component leaves[NSLOTS];
    component tree = CredentialRoot8();
    for (var s = 0; s < NSLOTS; s++) {
        leaves[s] = AttributeLeaf(s);
        leaves[s].value <== values[s];
        leaves[s].salt  <== salts[s];
        tree.leaves[s] <== leaves[s].leaf;
    }
    for (var k = 0; k < 3; k++) {
        tree.leaves[NSLOTS + k] <== otherLeaves[k];
    }

    if (OFF != 1) {
        component sig = IssuerSignature();
        sig.Ax  <== issuerAx;
        sig.Ay  <== issuerAy;
        sig.R8x <== sigR8x;
        sig.R8y <== sigR8y;
        sig.S   <== sigS;
        if (OFF == 2) {
            sig.root <== signedRoot;
        } else {
            sig.root <== tree.root;
        }
    }

    component rDob = DateRange();      rDob.in <== dob;
    component rNow = DateRange();      rNow.in <== currentDate;
    component rExp = DateRange();      rExp.in <== expiry;
    component rOff = DateRange();      rOff.in <== minAgeOffset;

    component age = AgeAtLeast();
    age.dob <== dob;
    age.currentDate <== currentDate;
    age.minAgeOffset <== minAgeOffset;

    if (OFF != 3) {
        kycStatus === 1;
    }

    if (OFF != 4) {
        component notExp = NotExpired();
        notExp.expiry <== expiry;
        notExp.currentDate <== currentDate;
    }

    if (OFF != 6) {
        component rev = RevocationMembership(REV_DEPTH);
        rev.credentialId <== credentialId;
        rev.root <== revocationRoot;
        for (var i = 0; i < REV_DEPTH; i++) {
            rev.pathElements[i] <== revSiblings[i];
            rev.pathIndices[i] <== revPathIndices[i];
        }
    }

    component nul = Nullifier();
    nul.holderSecret <== holderSecret;
    nul.spId <== spId;
    nullifier <== nul.nullifier;

    signal challengeSquare;
    challengeSquare <== challenge * challenge;
}
