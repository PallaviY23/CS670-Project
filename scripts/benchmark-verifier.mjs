import { performance } from "node:perf_hooks";
import { RevocationRegistry } from "../src/verifier/revocation.js";
import { ChallengeStore, isCanonicalFieldElement, SNARK_SCALAR_FIELD } from "../src/verifier/index.js";

async function runBenchmarks() {
  console.log("==========================================================");
  console.log(" CS670: Verifier & Revocation Scalability Benchmarks");
  console.log(" Author: Someshwar Singh (231020)");
  console.log("==========================================================\n");

  // 1. Revocation Tree Benchmark (Depth 16)
  console.log("--- 1. Poseidon Merkle Revocation Tree (Depth 16) ---");
  const tree = new RevocationRegistry(16);
  const tInitStart = performance.now();
  await tree.init();
  const initMs = performance.now() - tInitStart;
  console.log(`[Init] Tree initialization and zero-hash precomputation: ${initMs.toFixed(2)} ms`);

  const numCredentials = 50;
  const regTimes = [];
  for (let i = 0; i < numCredentials; i++) {
    const t0 = performance.now();
    tree.register(`cred_${10000 + i}`);
    regTimes.push(performance.now() - t0);
  }
  const avgRegMs = regTimes.reduce((a, b) => a + b, 0) / regTimes.length;
  console.log(`[Register] Batch insertion of ${numCredentials} credentials: avg ${avgRegMs.toFixed(2)} ms/op`);

  const pathTimes = [];
  for (let i = 0; i < numCredentials; i++) {
    const t0 = performance.now();
    tree.getMembershipPath(`cred_${10000 + i}`);
    pathTimes.push(performance.now() - t0);
  }
  const avgPathMs = pathTimes.reduce((a, b) => a + b, 0) / pathTimes.length;
  console.log(`[Path Gen] Membership path computation (depth 16): avg ${avgPathMs.toFixed(2)} ms/op`);

  const revokeTimes = [];
  for (let i = 0; i < 10; i++) {
    const t0 = performance.now();
    tree.revoke(`cred_${10000 + i}`);
    revokeTimes.push(performance.now() - t0);
  }
  const avgRevokeMs = revokeTimes.reduce((a, b) => a + b, 0) / revokeTimes.length;
  console.log(`[Revoke] Revocation & root recomputation: avg ${avgRevokeMs.toFixed(2)} ms/op`);

  // 2. Challenge Service Benchmark
  console.log("\n--- 2. Challenge Service & Anti-Replay Throughput ---");
  const store = new ChallengeStore();
  const numChallenges = 1000;
  const tChStart = performance.now();
  for (let i = 0; i < numChallenges; i++) {
    store.issue({ spId: "sp_benchmark", currentDate: 20261102 });
  }
  const chDurationMs = performance.now() - tChStart;
  const chThroughput = (numChallenges / (chDurationMs / 1000)).toFixed(0);
  console.log(`[Challenge Gen] Issued ${numChallenges} nonces in ${chDurationMs.toFixed(2)} ms (${chThroughput} ops/sec)`);

  // 3. Public Signal Validation Throughput
  console.log("\n--- 3. Canonical Field Validation Throughput ---");
  const sampleSignals = [
    "1948201948201948201948201948201948201948201948201948201948201948",
    "11513271168449174522649033324628286280208269784305886616238612196620584742680",
    "4525892543290680321743110595304724213031024621041926618587428172605809756083",
    "20261102",
    "180000",
    "1847291048291048201948201948201948201948201948201948201948201948",
    "123456789",
    "20875382947104928192847291048291048201948201948201948201948201948",
  ];

  const numChecks = 10000;
  const tCheckStart = performance.now();
  for (let i = 0; i < numChecks; i++) {
    for (const sig of sampleSignals) {
      isCanonicalFieldElement(sig);
    }
  }
  const checkDurationMs = performance.now() - tCheckStart;
  const checkThroughput = ((numChecks * sampleSignals.length) / (checkDurationMs / 1000)).toFixed(0);
  console.log(`[Field Validation] Validated ${numChecks * sampleSignals.length} signals in ${checkDurationMs.toFixed(2)} ms (${checkThroughput} ops/sec)`);

  console.log("\n==========================================================");
  console.log(" Scalability benchmarks completed successfully.");
  console.log("==========================================================");
}

runBenchmarks().catch(console.error);
