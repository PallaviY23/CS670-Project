// Browser proving benchmark: builds the web app, serves it with the current
// demo artifacts, and runs web/bench.html in headless Chrome/Edge.
//   node scripts/bench-browser.mjs [--runs 10] [--warmup 2] [--input input.json] [--browser <path>]
// Requires npm run setup:demo. Set BROWSER_PATH if the browser is not found.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import express from "express";
import { build } from "vite";
import { hostInfo, parseOptions, summarizeSamples, timestamp, writeCsv, writeJson } from "./lib/bench-utils.mjs";

const options = parseOptions({
  runs: { type: "string", default: "10" },
  warmup: { type: "string", default: "2" },
  input: { type: "string" },
  browser: { type: "string" },
  timeout: { type: "string", default: "600" },
});

const circuitDir = resolve("build/circuit");
const manifestPath = resolve(circuitDir, "manifest.json");
if (!existsSync(manifestPath)) {
  console.error("No proving artifacts found. Run npm run setup:demo first.");
  process.exit(1);
}
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const input = options.input ? JSON.parse(await readFile(options.input, "utf8")) : { age: 21, kycVerified: 1 };

function findBrowser() {
  const candidates = [
    options.browser,
    process.env.BROWSER_PATH,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ];
  return candidates.find((candidate) => candidate && existsSync(candidate));
}

const browserPath = findBrowser();
if (!browserPath) {
  console.error("No Chrome/Edge/Chromium found. Pass --browser <path> or set BROWSER_PATH.");
  process.exit(1);
}

console.log("Building web app...");
await build({ configFile: resolve("vite.config.js"), logLevel: "warn" });

let deliver;
const delivered = new Promise((resolveResults) => {
  deliver = resolveResults;
});

const app = express();
app.use(express.json({ limit: "1mb" }));
app.get("/api/prover/manifest", (_request, response) => response.sendFile(manifestPath));
app.get("/api/prover/wasm", (_request, response) => response.sendFile(resolve(circuitDir, manifest.artifacts.wasm.file)));
app.get("/api/prover/zkey", (_request, response) => response.sendFile(resolve(circuitDir, manifest.artifacts.zkey.file)));
app.get("/bench/input", (_request, response) => response.json(input));
app.post("/bench/results", (request, response) => {
  response.json({ ok: true });
  deliver(request.body);
});
app.use(express.static(resolve("build/web")));

const server = await new Promise((resolveServer) => {
  const listening = app.listen(0, "127.0.0.1", () => resolveServer(listening));
});
const url = `http://127.0.0.1:${server.address().port}/bench.html?runs=${options.runs}&warmup=${options.warmup}`;
const profileDir = await mkdtemp(join(tmpdir(), "kyc-bench-"));

console.log(`Running ${options.warmup} warm-up + ${options.runs} proofs in ${browserPath}...`);
const browser = spawn(browserPath, [
  "--headless=new",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  `--user-data-dir=${profileDir}`,
  url,
], { stdio: "ignore" });

const timeout = setTimeout(() => deliver({ error: `Timed out after ${options.timeout} s.` }), Number(options.timeout) * 1000);
const results = await delivered;
clearTimeout(timeout);
browser.kill();
server.close();
await rm(profileDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 }).catch(() => {});

if (results.error) {
  console.error(`Browser benchmark failed: ${results.error}`);
  process.exit(1);
}

const stamp = timestamp();
const report = {
  kind: "browser-prover",
  generatedAt: new Date().toISOString(),
  host: hostInfo(),
  browser: { path: browserPath, userAgent: results.userAgent, hardwareConcurrency: results.hardwareConcurrency },
  circuit: results.circuit,
  runs: results.runs,
  warmup: results.warmup,
  cold: results.cold,
  proofBytes: results.proofBytes,
  timings: summarizeSamples(results.samples, ["witnessMs", "provingMs", "totalMs", "roundTripMs"]),
};
await writeJson(resolve("build/bench", `browser-${results.circuit}-${stamp}.json`), report);
await writeCsv(resolve("build/bench", `browser-${results.circuit}-${stamp}-runs.csv`), results.samples.map((sample, i) => ({ run: i + 1, ...sample })));

console.log(`Browser: ${results.userAgent}`);
console.log(`Cold run: ${results.cold.totalMs} ms total (artifact download + hash check ${results.cold.artifactLoadMs} ms).`);
console.table(Object.fromEntries(Object.entries(report.timings).map(([field, stats]) => [field, stats])));
console.log(`Results written to build/bench/browser-${results.circuit}-${stamp}*.`);
process.exit(0);
