// In-browser proving benchmark. Opened manually (dev server, /bench.html) or
// headlessly by scripts/bench-browser.mjs, which also serves /bench/input and
// collects /bench/results.
import { createProverClient } from "../../src/prover/worker-client.js";

const params = new URLSearchParams(location.search);
const runs = Number(params.get("runs") ?? 10);
const warmup = Number(params.get("warmup") ?? 2);
const status = document.getElementById("status");
const output = document.getElementById("results");

async function benchmarkInput() {
  const response = await fetch("/bench/input").catch(() => null);
  return response?.ok ? response.json() : { age: 21, kycVerified: 1 };
}

async function main() {
  const input = await benchmarkInput();
  const prover = createProverClient();

  status.textContent = "Cold run (downloads and checks artifacts)…";
  const coldStart = performance.now();
  const cold = await prover.prove(input);
  const coldTotalMs = Number((performance.now() - coldStart).toFixed(2));

  const samples = [];
  for (let i = 0; i < warmup + runs; i += 1) {
    status.textContent = i < warmup ? `Warm-up ${i + 1}/${warmup}` : `Run ${i - warmup + 1}/${runs}`;
    const start = performance.now();
    const result = await prover.prove(input);
    if (i >= warmup) {
      samples.push({ ...result.timings, roundTripMs: Number((performance.now() - start).toFixed(2)) });
    }
  }
  prover.terminate();

  return {
    environment: "browser",
    userAgent: navigator.userAgent,
    hardwareConcurrency: navigator.hardwareConcurrency,
    circuit: cold.artifacts.circuit,
    cold: { totalMs: coldTotalMs, artifactLoadMs: cold.artifacts.loadMs, fromCache: cold.artifacts.fromCache, ...cold.timings },
    proofBytes: cold.proofBytes,
    runs,
    warmup,
    samples,
  };
}

main()
  .then(async (results) => {
    status.textContent = "Done.";
    output.textContent = JSON.stringify(results, null, 2);
    await fetch("/bench/results", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(results) }).catch(() => {});
  })
  .catch(async (error) => {
    status.textContent = `Failed: ${error.message}`;
    await fetch("/bench/results", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ error: error.message }) }).catch(() => {});
  });
