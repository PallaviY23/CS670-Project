// Web Worker that keeps proving off the UI thread. The witness never leaves
// the browser: it arrives here by postMessage and only the proof is returned.
import { DEFAULT_ARTIFACT_URLS, loadProverArtifacts } from "./browser-loader.js";
import { prove } from "./prove.js";

let artifacts = null;

function post(message) {
  self.postMessage(message);
}

self.onmessage = async ({ data }) => {
  const { id, input, urls = DEFAULT_ARTIFACT_URLS } = data;
  try {
    post({ id, type: "progress", stage: "artifacts" });
    artifacts ??= loadProverArtifacts(urls);
    const { manifest, wasm, zkey, loadMs, fromCache } = await artifacts;

    const result = await prove(input, {
      wasm,
      zkey,
      protocol: manifest.protocol,
      onProgress: (stage) => post({ id, type: "progress", stage }),
    });

    post({
      id,
      type: "result",
      ...result,
      artifacts: { loadMs, fromCache, circuit: manifest.circuit, publicSignalNames: manifest.publicSignals },
    });
  } catch (error) {
    // Drop a failed or tampered download so the next attempt starts clean.
    artifacts = null;
    post({ id, type: "error", message: error?.message ?? "Proof generation failed.", code: error?.code });
  }
};
