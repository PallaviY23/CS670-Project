import assert from "node:assert/strict";
import { test } from "node:test";
import * as snarkjs from "snarkjs";
import { RevocationRegistry } from "../src/verifier/revocation.js";

const wasmPath = "build/circuit/test_revocation_js/test_revocation.wasm";

test("RevocationMembership circuit accepts valid membership witness", async () => {
  const reg = new RevocationRegistry(4);
  await reg.init();
  reg.register("42");
  reg.register("99");

  const path = reg.getMembershipPath("42");
  const witnessPath = "build/circuit/rev_valid.wtns";

  const input = {
    credentialId: "42",
    root: path.root,
    pathElements: path.pathElements,
    pathIndices: path.pathIndices,
  };

  await snarkjs.wtns.calculate(input, wasmPath, witnessPath);
  const wtns = await snarkjs.wtns.exportJson(witnessPath);
  assert.ok(wtns && wtns.length > 0);
});

test("RevocationMembership circuit rejects wrong credentialId", async () => {
  const reg = new RevocationRegistry(4);
  await reg.init();
  reg.register("42");

  const path = reg.getMembershipPath("42");
  const witnessPath = "build/circuit/rev_invalid.wtns";

  const input = {
    credentialId: "43", // Wrong ID
    root: path.root,
    pathElements: path.pathElements,
    pathIndices: path.pathIndices,
  };

  await assert.rejects(snarkjs.wtns.calculate(input, wasmPath, witnessPath));
});

test("RevocationMembership circuit rejects altered Merkle sibling path", async () => {
  const reg = new RevocationRegistry(4);
  await reg.init();
  reg.register("42");

  const path = reg.getMembershipPath("42");
  const witnessPath = "build/circuit/rev_tampered.wtns";

  const tamperedElements = [...path.pathElements];
  tamperedElements[0] = "123456789"; // Alter sibling

  const input = {
    credentialId: "42",
    root: path.root,
    pathElements: tamperedElements,
    pathIndices: path.pathIndices,
  };

  await assert.rejects(snarkjs.wtns.calculate(input, wasmPath, witnessPath));
});
