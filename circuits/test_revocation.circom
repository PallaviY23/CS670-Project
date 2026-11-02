pragma circom 2.1.6;

include "./RevocationMembership.circom";

component main {public [root]} = RevocationMembership(4);
