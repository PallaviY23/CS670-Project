pragma circom 2.1.6;

include "lib/attribute_leaf.circom";
include "lib/merkle.circom";
include "lib/dates.circom";
include "lib/holder.circom";
include "lib/signature.circom";
include "RevocationMembership.circom";   // Someshwar (S6)

// KycPresentation — proves, without revealing any attribute:
//   1. the credential root is signed by the issuer (issuerAx, issuerAy)
//   2. slots 0..4 used by the prover belong to that signed root
//   3. currentDate - dob >= minAgeOffset   (age >= 18 for 180000)
//   4. kycStatus == 1
//   5. expiry >= currentDate
//   6. prover knows holderSecret behind holderCommitment (slot 4)
//   7. credentialId is in the active-credential (revocation) tree
// and outputs nullifier = Poseidon(holderSecret, spId).
//
// Claims are ASSERTIONS: if any claim is false, no proof can be built.
//
// See spec/claim-interface.md. Public input DECLARATION ORDER below defines
// the publicSignals order — do not reorder without a spec change.

template KycPresentation(REV_DEPTH) {
    var NSLOTS = 5;   // slots opened: 0 credentialId, 1 dob, 2 kycStatus, 3 expiry, 4 holderCommitment

    // ---------- public inputs (order is part of the interface) ----------
    signal input issuerAx;
    signal input issuerAy;
    signal input currentDate;
    signal input minAgeOffset;
    signal input challenge;
    signal input spId;
    signal input revocationRoot;

    // ---------- private inputs ----------
    signal input credentialId;
    signal input dob;
    signal input kycStatus;
    signal input expiry;
    signal input holderSecret;
    signal input salts[NSLOTS];
    signal input otherLeaves[3];      // leaf hashes of slots 5, 6, 7 (not opened)
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input revSiblings[REV_DEPTH];
    signal input revPathIndices[REV_DEPTH];

    // ---------- public output ----------
    signal output nullifier;

    // (6) holder binding — slot 4 value is computed, never supplied
    component holder = HolderBinding();
    holder.holderSecret <== holderSecret;

    signal values[NSLOTS];
    values[0] <== credentialId;
    values[1] <== dob;
    values[2] <== kycStatus;
    values[3] <== expiry;
    values[4] <== holder.holderCommitment;

    // (2) recompute the credential root from slots 0..4 and the hashes of 5..7
    //     (V6: one tree build instead of five inclusion proofs)
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
    signal root;
    root <== tree.root;

    // (1) issuer signature on the root
    component sig = IssuerSignature();
    sig.Ax  <== issuerAx;
    sig.Ay  <== issuerAy;
    sig.R8x <== sigR8x;
    sig.R8y <== sigR8y;
    sig.S   <== sigS;
    sig.root <== root;

    // range checks — once per date value (shared by 3 and 5)
    component rDob = DateRange();      rDob.in <== dob;
    component rNow = DateRange();      rNow.in <== currentDate;
    component rExp = DateRange();      rExp.in <== expiry;
    component rOff = DateRange();      rOff.in <== minAgeOffset;

    // (3) age
    component age = AgeAtLeast();
    age.dob <== dob;
    age.currentDate <== currentDate;
    age.minAgeOffset <== minAgeOffset;

    // (4) KYC status
    kycStatus === 1;

    // (5) expiry
    component notExp = NotExpired();
    notExp.expiry <== expiry;
    notExp.currentDate <== currentDate;

    // (7) not revoked
    component rev = RevocationMembership(REV_DEPTH);
    rev.credentialId <== credentialId;
    rev.root <== revocationRoot;
    for (var i = 0; i < REV_DEPTH; i++) {
        rev.pathElements[i] <== revSiblings[i];
        rev.pathIndices[i] <== revPathIndices[i];
    }

    // nullifier
    component nul = Nullifier();
    nul.holderSecret <== holderSecret;
    nul.spId <== spId;
    nullifier <== nul.nullifier;

    // bind challenge: a public input with no constraint is a weak spot,
    // so tie it into the constraint system explicitly.
    signal challengeSquare;
    challengeSquare <== challenge * challenge;
}

component main {public [issuerAx, issuerAy, currentDate, minAgeOffset,
                        challenge, spId, revocationRoot]} = KycPresentation(16);
