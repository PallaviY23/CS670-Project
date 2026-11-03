// Promise wrapper around prover.worker.js for UI code.

export function createProverClient() {
  const worker = new Worker(new URL("./prover.worker.js", import.meta.url), { type: "module" });
  const pending = new Map();
  let nextId = 1;

  worker.onmessage = ({ data }) => {
    const request = pending.get(data.id);
    if (!request) return;
    if (data.type === "progress") {
      request.onProgress?.(data.stage);
      return;
    }
    pending.delete(data.id);
    if (data.type === "result") {
      const { id: _id, type: _type, ...result } = data;
      request.resolve(result);
    } else {
      request.reject(Object.assign(new Error(data.message), { code: data.code }));
    }
  };

  worker.onerror = (event) => {
    const error = new Error(event.message || "The prover worker crashed.");
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  };

  return {
    prove(input, { onProgress, urls } = {}) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject, onProgress });
        worker.postMessage({ id, input, ...(urls ? { urls } : {}) });
      });
    },
    terminate() {
      worker.terminate();
      for (const request of pending.values()) request.reject(new Error("Prover stopped."));
      pending.clear();
    },
  };
}
