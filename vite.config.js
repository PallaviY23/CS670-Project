import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

const page = (path) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  root: "web",
  plugins: [
    react(),
    nodePolyfills({
      include: ["assert", "buffer", "events", "util"],
      globals: { Buffer: true, global: true, process: true },
    }),
  ],
  server: {
    proxy: {
      "/api": process.env.API_PROXY_TARGET ?? "http://127.0.0.1:4000",
    },
  },
  // Pre-bundle snarkjs at start-up. Otherwise the dev server discovers it on the
  // first proof and reloads the page in the middle of proving.
  optimizeDeps: {
    include: ["snarkjs"],
  },
  // The prover worker loads snarkjs, which needs code splitting.
  worker: {
    format: "es",
  },
  build: {
    outDir: "../build/web",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: page("./web/index.html"),
        bench: page("./web/bench.html"),
      },
    },
  },
});
