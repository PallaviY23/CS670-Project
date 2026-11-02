pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

/**
 * RevocationMembership
 * Verifies that a credentialId is an active member of the revocation Merkle tree of depth `depth`.
 *
 * Inputs:
 * - credentialId: private field element identifier of the credential
 * - root: expected public Merkle root of active credentials
 * - pathElements[depth]: sibling hashes along the Merkle inclusion path
 * - pathIndices[depth]: direction bits (0 = current node is left sibling, 1 = current node is right sibling)
 */
template RevocationMembership(depth) {
    signal input credentialId;
    signal input root;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Compute leaf hash from credentialId
    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== credentialId;

    signal currentHashes[depth + 1];
    currentHashes[0] <== leafHasher.out;

    component hashers[depth];
    signal left[depth];
    signal right[depth];

    for (var i = 0; i < depth; i++) {
        // Enforce pathIndices[i] is boolean (0 or 1)
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Multiplexer:
        // When pathIndices[i] == 0: left = currentHashes[i], right = pathElements[i]
        // When pathIndices[i] == 1: left = pathElements[i], right = currentHashes[i]
        left[i] <== (pathElements[i] - currentHashes[i]) * pathIndices[i] + currentHashes[i];
        right[i] <== (currentHashes[i] - pathElements[i]) * pathIndices[i] + pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];

        currentHashes[i + 1] <== hashers[i].out;
    }

    // Constraint: The computed Merkle root must match the supplied active root
    currentHashes[depth] === root;
}
