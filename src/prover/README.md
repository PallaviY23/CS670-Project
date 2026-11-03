# Prover Module

Owner: Durbasmriti Saha

Trusted setup, witness/proof generation, browser proving and proving-time/proof-size measurement. Design, results and integration status are in [docs/prover-pipeline.md](../../docs/prover-pipeline.md).

| File | Runs in | Use |
| --- | --- | --- |
| `setup.js` | Node | `setupCircuit()`, `ensurePtau()`, `writeManifest()` |
| `prove.js` | Node + browser | `prove()`, `verify()`, `proofSize()` |
| `inputs.js` | Node + browser | `buildStarterInput()`, `buildPresentationInput()`, date and field helpers |
| `artifacts.js` | Node + browser | SHA-256 artifact checks against the manifest |
| `browser-loader.js`, `prover.worker.js`, `worker-client.js` | Browser | Cached, hash-checked artifacts and proving in a Web Worker |

```js
import { createProverClient } from "../src/prover/worker-client.js";
const prover = createProverClient();
const { proof, publicSignals, timings, proofBytes } = await prover.prove(input, { onProgress: console.log });
```

Generated keys, witnesses and ptau files stay under `build/` and out of version control. Coordinate circuit artifact paths and public signals with the circuit and verifier owners; the manifest (`build/circuit/manifest.json`) is the shared source of truth for signal order and artifact hashes.
