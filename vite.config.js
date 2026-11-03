import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const page = (path) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  root: "web",
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:4000",
    },
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
