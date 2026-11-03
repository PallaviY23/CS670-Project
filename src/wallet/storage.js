// Key-value storage backends for the wallet: IndexedDB in the browser and an
// in-memory map for tests and Node scripts. Both store structured clones.

export function memoryStorage() {
  const records = new Map();
  return {
    async get(key) {
      return records.has(key) ? structuredClone(records.get(key)) : undefined;
    },
    async set(key, value) {
      records.set(key, structuredClone(value));
    },
    async delete(key) {
      records.delete(key);
    },
    async keys() {
      return [...records.keys()];
    },
  };
}

function promisify(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export function indexedDbStorage({ dbName = "cs670-kyc-wallet", storeName = "records" } = {}) {
  let database;
  const db = () => {
    database ??= new Promise((resolve, reject) => {
      const request = indexedDB.open(dbName, 1);
      request.onupgradeneeded = () => request.result.createObjectStore(storeName);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return database;
  };
  const run = async (mode, action) => {
    const store = (await db()).transaction(storeName, mode).objectStore(storeName);
    return promisify(action(store));
  };

  return {
    get: (key) => run("readonly", (store) => store.get(key)),
    set: (key, value) => run("readwrite", (store) => store.put(value, key)).then(() => {}),
    delete: (key) => run("readwrite", (store) => store.delete(key)).then(() => {}),
    keys: () => run("readonly", (store) => store.getAllKeys()),
  };
}
