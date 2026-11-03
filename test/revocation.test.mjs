import assert from "node:assert/strict";
import { test } from "node:test";
import { RevocationRegistry } from "../src/verifier/revocation.js";

test("RevocationRegistry computes deterministic empty root", async () => {
  const reg = new RevocationRegistry(4);
  await reg.init();
  const root = reg.getRoot();
  assert.ok(root && typeof root === "string");
  assert.equal(reg.isRootAccepted(root), true);
});

test("RevocationRegistry registers credential and produces verifiable membership path", async () => {
  const reg = new RevocationRegistry(4);
  await reg.init();
  const initialRoot = reg.getRoot();

  const regInfo = reg.register("1001");
  const newRoot = reg.getRoot();
  assert.notEqual(initialRoot, newRoot);
  assert.equal(reg.isActive("1001"), true);

  const path = reg.getMembershipPath("1001");
  assert.equal(path.credentialId, "1001");
  assert.equal(path.pathElements.length, 4);
  assert.equal(path.pathIndices.length, 4);
  assert.equal(path.root, newRoot);

  // Verify path off-circuit
  let current = BigInt(path.leaf);
  for (let i = 0; i < 4; i++) {
    const sibling = BigInt(path.pathElements[i]);
    const isRight = path.pathIndices[i] === 1;
    const left = isRight ? sibling : current;
    const right = isRight ? current : sibling;
    current = reg.hash([left, right]);
  }
  assert.equal(current.toString(), newRoot);
});

test("RevocationRegistry revokes credential, updates root, and denies path", async () => {
  const reg = new RevocationRegistry(4);
  await reg.init();

  reg.register("1001");
  reg.register("1002");
  const rootBefore = reg.getRoot();

  assert.equal(reg.isActive("1001"), true);
  assert.equal(reg.isActive("1002"), true);

  // Revoke 1001
  const revokeResult = reg.revoke("1001");
  assert.equal(revokeResult.success, true);
  assert.equal(revokeResult.alreadyRevoked, false);
  assert.equal(reg.isActive("1001"), false);
  assert.equal(reg.isActive("1002"), true);

  const rootAfter = reg.getRoot();
  assert.notEqual(rootBefore, rootAfter);

  // Membership path for 1001 should throw
  assert.throws(() => reg.getMembershipPath("1001"), /revoked or not found/);

  // Membership path for 1002 remains valid
  const path1002 = reg.getMembershipPath("1002");
  assert.equal(path1002.root, rootAfter);

  // Verify path for 1002 against new root
  let current = BigInt(path1002.leaf);
  for (let i = 0; i < 4; i++) {
    const sibling = BigInt(path1002.pathElements[i]);
    const isRight = path1002.pathIndices[i] === 1;
    const left = isRight ? sibling : current;
    const right = isRight ? current : sibling;
    current = reg.hash([left, right]);
  }
  assert.equal(current.toString(), rootAfter);

  // Revocation is final: registering the same ID again must not revive it.
  assert.throws(() => reg.register("1001"), /cannot be re-registered/);
  assert.equal(reg.isActive("1001"), false);
  assert.equal(reg.getRoot(), rootAfter);
});
