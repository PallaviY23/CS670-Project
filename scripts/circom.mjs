// Picks the circom compiler:
//   1. $CIRCOM env variable, if set
//   2. bin/circom.exe (Windows) or bin/circom (Linux/macOS) inside the project
//   3. a native `circom` on PATH
//   4. fallback: the circom2 npm package (WebAssembly; fails to write files on Windows)
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

let cached;
export function circomCmd() {
  if (cached) return cached;
  const local = path.resolve("bin", process.platform === "win32" ? "circom.exe" : "circom");
  if (process.env.CIRCOM) cached = `"${process.env.CIRCOM}"`;
  else if (fs.existsSync(local)) cached = `"${local}"`;
  else {
    try { execSync("circom --version", { stdio: "pipe" }); cached = "circom"; }
    catch { cached = "npx circom2"; }
  }
  return cached;
}

export function runCircom(args, options = {}) {
  try {
    return execSync(`${circomCmd()} ${args}`, { stdio: "pipe", ...options }).toString().replace(/\x1b\[[0-9;]*m/g, "");
  } catch (e) {
    const clean = (b) => (b ? b.toString().replace(/\x1b\[[0-9;]*m/g, "") : "");
    throw new Error(`circom failed (${circomCmd()} ${args}):\n${clean(e.stdout)}${clean(e.stderr)}`);
  }
}
