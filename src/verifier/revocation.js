import { buildPoseidon } from "circomlibjs";

const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * PoseidonMerkleTree
 * Sparse / Dense Merkle tree using Poseidon hash for active credential tracking.
 */
export class RevocationRegistry {
  /**
   * @param {number} depth Tree depth (e.g. 16 supports 65,536 active credentials)
   * @param {number} maxHistory Maximum number of historical roots retained
   */
  constructor(depth = 16, maxHistory = 100) {
    if (depth < 1 || depth > 32) {
      throw new Error(`Invalid Merkle tree depth: ${depth}. Must be between 1 and 32.`);
    }
    this.depth = depth;
    this.maxHistory = maxHistory;
    this.poseidon = null;
    this.zeroHashes = [];
    this.leaves = new Map(); // index -> leafHash (BigInt)
    this.credentialToIndex = new Map(); // credentialId (string) -> index (number)
    this.indexToCredential = new Map(); // index (number) -> credentialId (string)
    this.nextIndex = 0;
    this.currentRoot = 0n;
    this.rootHistory = []; // list of BigInt roots with timestamps
    this.initialized = false;
  }

  /**
   * Initialize circomlibjs Poseidon instance and precompute zero level hashes.
   */
  async init() {
    if (this.initialized) return this;
    this.poseidon = await buildPoseidon();

    // Level 0 zero hash is poseidon([0n]) to match empty leaf hashing
    this.zeroHashes = new Array(this.depth + 1);
    this.zeroHashes[0] = this.hash([0n]);
    for (let i = 0; i < this.depth; i++) {
      this.zeroHashes[i + 1] = this.hash([this.zeroHashes[i], this.zeroHashes[i]]);
    }

    this.currentRoot = this.zeroHashes[this.depth];
    this.recordRoot(this.currentRoot);
    this.initialized = true;
    return this;
  }

  /**
   * Safe Poseidon hash returning BigInt in BN254 scalar field.
   * @param {BigInt[]} inputs
   * @returns {BigInt}
   */
  hash(inputs) {
    const raw = this.poseidon(inputs.map((x) => BigInt(x)));
    return BigInt(this.poseidon.F.toString(raw));
  }

  /**
   * Computes the leaf hash for a credential ID.
   * matches Poseidon(1) in RevocationMembership.circom
   */
  hashLeaf(credentialId) {
    return this.hash([BigInt(this.normalizeCredentialId(credentialId))]);
  }

  normalizeCredentialId(credentialId) {
    const id = String(credentialId);
    if (!/^(0|[1-9]\d*)$/.test(id)) {
      throw new TypeError("credentialId must be a canonical decimal field element.");
    }
    const value = BigInt(id);
    if (value >= FIELD_MODULUS) throw new RangeError("credentialId is outside the BN254 scalar field.");
    return value.toString();
  }

  recordRoot(root) {
    const rootStr = root.toString();
    const entry = {
      root: rootStr,
      timestamp: new Date().toISOString(),
    };
    this.rootHistory.unshift(entry);
    if (this.rootHistory.length > this.maxHistory) {
      this.rootHistory.pop();
    }
  }

  /**
   * Registers a new active credential ID.
   * @param {string|number|bigint} credentialId
   * @returns {{ index: number, root: string, leaf: string }}
   */
  register(credentialId) {
    const idStr = this.normalizeCredentialId(credentialId);
    if (this.credentialToIndex.has(idStr)) {
      const existingIdx = this.credentialToIndex.get(idStr);
      // Already registered and active
      if (this.leaves.has(existingIdx)) {
        return {
          index: existingIdx,
          root: this.currentRoot.toString(),
          leaf: this.leaves.get(existingIdx).toString(),
        };
      }
    }

    const index = this.nextIndex;
    if (index >= 2 ** this.depth) {
      throw new Error(`Revocation tree capacity exceeded (${2 ** this.depth} leaves).`);
    }

    const leafHash = this.hashLeaf(idStr);
    this.leaves.set(index, leafHash);
    this.credentialToIndex.set(idStr, index);
    this.indexToCredential.set(index, idStr);
    this.nextIndex++;

    this.currentRoot = this.recomputeRoot();
    this.recordRoot(this.currentRoot);

    return {
      index,
      root: this.currentRoot.toString(),
      leaf: leafHash.toString(),
    };
  }

  /**
   * Revokes an existing credential ID by clearing its leaf.
   * @param {string|number|bigint} credentialId
   * @returns {{ success: boolean, revokedId: string, newRoot: string }}
   */
  revoke(credentialId) {
    const idStr = this.normalizeCredentialId(credentialId);
    if (!this.credentialToIndex.has(idStr)) {
      throw new Error(`Credential ${idStr} is not registered in the revocation tree.`);
    }

    const index = this.credentialToIndex.get(idStr);
    if (!this.leaves.has(index)) {
      // Already revoked
      return {
        success: true,
        alreadyRevoked: true,
        revokedId: idStr,
        newRoot: this.currentRoot.toString(),
      };
    }

    // Set leaf to empty (zero level 0 hash)
    this.leaves.delete(index);
    this.currentRoot = this.recomputeRoot();
    this.recordRoot(this.currentRoot);

    return {
      success: true,
      alreadyRevoked: false,
      revokedId: idStr,
      newRoot: this.currentRoot.toString(),
    };
  }

  /**
   * Check if a credential is currently active.
   * @param {string|number|bigint} credentialId
   * @returns {boolean}
   */
  isActive(credentialId) {
    const idStr = this.normalizeCredentialId(credentialId);
    const index = this.credentialToIndex.get(idStr);
    return index !== undefined && this.leaves.has(index);
  }

  /**
   * Returns Merkle inclusion path for an active credential.
   * @param {string|number|bigint} credentialId
   * @returns {{ root: string, leaf: string, pathElements: string[], pathIndices: number[] }}
   */
  getMembershipPath(credentialId) {
    const idStr = this.normalizeCredentialId(credentialId);
    if (!this.isActive(idStr)) {
      throw new Error(`Credential ${idStr} is revoked or not found in active registry.`);
    }

    const index = this.credentialToIndex.get(idStr);
    const leafHash = this.leaves.get(index);
    const pathElements = [];
    const pathIndices = [];

    let currentIndex = index;
    // Map of nodes currently present at each level
    let currentLevelNodes = new Map(this.leaves);

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
      pathIndices.push(isRight ? 1 : 0);

      const siblingHash = currentLevelNodes.has(siblingIndex)
        ? currentLevelNodes.get(siblingIndex)
        : this.zeroHashes[level];
      pathElements.push(siblingHash.toString());

      // Advance to next level
      const nextLevelNodes = new Map();
      for (const [idx, nodeHash] of currentLevelNodes.entries()) {
        const parentIdx = Math.floor(idx / 2);
        if (!nextLevelNodes.has(parentIdx)) {
          const isLeft = idx % 2 === 0;
          const leftNode = isLeft ? nodeHash : (currentLevelNodes.get(idx - 1) ?? this.zeroHashes[level]);
          const rightNode = !isLeft ? nodeHash : (currentLevelNodes.get(idx + 1) ?? this.zeroHashes[level]);
          nextLevelNodes.set(parentIdx, this.hash([leftNode, rightNode]));
        }
      }
      currentLevelNodes = nextLevelNodes;
      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      credentialId: idStr,
      root: this.currentRoot.toString(),
      leaf: leafHash.toString(),
      pathElements,
      pathIndices,
    };
  }

  /**
   * Recomputes the root from current active leaves.
   * @returns {BigInt}
   */
  recomputeRoot() {
    if (this.leaves.size === 0) {
      return this.zeroHashes[this.depth];
    }

    let currentNodes = new Map(this.leaves);
    for (let level = 0; level < this.depth; level++) {
      const nextNodes = new Map();
      const parentIndices = new Set();
      for (const idx of currentNodes.keys()) {
        parentIndices.add(Math.floor(idx / 2));
      }

      for (const parentIdx of parentIndices) {
        const leftIdx = parentIdx * 2;
        const rightIdx = leftIdx + 1;
        const left = currentNodes.has(leftIdx) ? currentNodes.get(leftIdx) : this.zeroHashes[level];
        const right = currentNodes.has(rightIdx) ? currentNodes.get(rightIdx) : this.zeroHashes[level];
        nextNodes.set(parentIdx, this.hash([left, right]));
      }

      currentNodes = nextNodes;
    }

    return currentNodes.get(0) ?? this.zeroHashes[this.depth];
  }

  /**
   * Checks whether a root is currently accepted (either current or in recent root history).
   * @param {string|BigInt} root
   * @returns {boolean}
   */
  isRootAccepted(root) {
    const rootStr = String(root);
    return this.rootHistory.some((entry) => entry.root === rootStr);
  }

  getRoot() {
    return this.currentRoot.toString();
  }

  getRootHistory() {
    return this.rootHistory.map((entry) => entry.root);
  }
}

// Default singleton instance for the service provider / issuer node
let defaultRegistry = null;

export async function getDefaultRegistry(depth = 16) {
  if (!defaultRegistry) {
    defaultRegistry = new RevocationRegistry(depth);
    await defaultRegistry.init();
  }
  return defaultRegistry;
}
