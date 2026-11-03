// V7: ablation circuits. Each forgery below is rejected by the complete
// circuit (control) but accepted once the one constraint group that blocks it
// is removed, so every group is shown to be necessary. A witness that
// satisfies the constraints is all a prover needs to build a Groth16 proof.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { before, describe, test } from "node:test";
import { loadCircuit } from "./helpers/circuit.mjs";
import { ActiveSet, H, init, newIssuer, presentationInput, randField, scenario } from "./helpers/fixtures.mjs";

const DEPTH = 4;
const OFF = {
  control: 0,
  ablation_no_signature: 1,
  ablation_no_tree_link: 2,
  ablation_no_kyc_status: 3,
  ablation_no_expiry: 4,
  ablation_no_holder_binding: 5,
  ablation_no_revocation: 6,
};
let control;

// Each variant is the template plus a main line. Written as one self-contained
// file because circom2 (WASI) cannot include files outside circuits/. Each gets
// its own folder: the compile cache compares against the newest file in the
// source folder, so variants sharing a folder would invalidate each other.
function variantCircuit(name) {
  const template = fs.readFileSync("test/ablation/kyc_ablation.circom", "utf8");
  const source = `${template}
component main {public [issuerAx, issuerAy, currentDate, minAgeOffset,
                        challenge, spId, revocationRoot]} = KycAblation(${DEPTH}, ${OFF[name]});
`;
  const file = path.join("build/ablation-src", name, `${name}.circom`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!fs.existsSync(file) || fs.readFileSync(file, "utf8") !== source) fs.writeFileSync(file, source);
  return loadCircuit(file);
}

async function forgeryScenario(options = {}) {
  const sc = await scenario(options);
  sc.active = new ActiveSet(DEPTH);
  for (const id of [999n, sc.cred.slotValues[0], 1002n]) sc.active.add(id);
  return sc;
}

// Ablation-only inputs default to their honest values.
const witnessInput = (sc, over = {}) => ({
  ...presentationInput(sc),
  signedRoot: sc.cred.root,
  holderCommitment: H(sc.holderSecret),
  ...over,
});

const forgeries = [
  {
    variant: "ablation_no_signature",
    group: "issuer signature",
    attack: "self-signed credential presented under the trusted issuer key",
    build: async () => witnessInput(await forgeryScenario({ signer: newIssuer("forger") })),
  },
  {
    variant: "ablation_no_tree_link",
    group: "credential-tree link",
    attack: "minor reuses a genuine signature but substitutes an adult DOB",
    build: async () => {
      const sc = await forgeryScenario({ values: { dob: 20100101n } });
      return witnessInput(sc, { dob: 20000101n });
    },
  },
  {
    variant: "ablation_no_kyc_status",
    group: "kycStatus = 1",
    attack: "validly signed credential with KYC not verified",
    build: async () => witnessInput(await forgeryScenario({ values: { kycStatus: 0n } })),
  },
  {
    variant: "ablation_no_expiry",
    group: "expiry check",
    attack: "credential that expired yesterday",
    build: async () => witnessInput(await forgeryScenario({ values: { expiry: 20261102n } })),
  },
  {
    variant: "ablation_no_holder_binding",
    group: "holder binding",
    attack: "stolen credential file used without the holder secret",
    build: async () => {
      const sc = await forgeryScenario();
      return witnessInput(sc, { holderSecret: randField() });
    },
  },
  {
    variant: "ablation_no_revocation",
    group: "revocation membership",
    attack: "revoked credential proving against the current root",
    build: async () => {
      const sc = await forgeryScenario();
      const before = sc.active.path(sc.cred.slotValues[0]);
      sc.active.revoke(sc.cred.slotValues[0]);
      return witnessInput(sc, {
        revSiblings: before.siblings,
        revPathIndices: before.bits,
        revocationRoot: sc.active.root(),
      });
    },
  },
];

describe("V7 ablation circuits", () => {
  before(async () => {
    await init();
    control = await variantCircuit("control");
  });

  test("control (nothing removed) accepts an honest witness", async () => {
    await assert.doesNotReject(control.witness(witnessInput(await forgeryScenario())));
  });

  for (const { variant, group, attack, build } of forgeries) {
    test(`without ${group}: ${attack} succeeds; the full circuit rejects it`, async () => {
      const forged = await build();
      await assert.rejects(control.witness(forged), undefined, "control circuit must reject the forgery");
      const weakened = await variantCircuit(variant);
      await assert.doesNotReject(weakened.witness(forged), `${variant} should accept the forgery`);
    });
  }
});
