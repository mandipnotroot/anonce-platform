// SPDX-License-Identifier: AGPL-3.0-only
// Only authenticated ciphertext records belong here. Secrets stay in memory.
const DATABASE = "anonce-encrypted-v1";
const STORE = "records";
let opening;

function database() {
  if (!opening)
    opening = new Promise((resolve, reject) => {
      const req = indexedDB.open(DATABASE, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => {
        opening = undefined;
        reject(new Error("Encrypted local storage unavailable."));
      };
      req.onblocked = () => {
        opening = undefined;
        reject(new Error("Close other Anonce tabs and retry."));
      };
    });
  return opening;
}

async function transact(mode, operation) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = operation(tx.objectStore(STORE));
    tx.oncomplete = () => resolve(req.result);
    tx.onerror = tx.onabort = () =>
      reject(new Error("Encrypted local storage operation failed."));
  });
}

export const getEncrypted = (key) =>
  transact("readonly", (store) => store.get(key));
export const allEncrypted = () =>
  transact("readonly", (store) => store.getAll());
export const deleteEncrypted = (key) =>
  transact("readwrite", (store) => store.delete(key));
export const getDeviceRecord = (key) =>
  transact("readonly", (store) => store.get("device:" + key));
export const putDeviceRecord = (key, value) =>
  transact("readwrite", (store) => store.put(value, "device:" + key));
export const deleteDeviceRecord = (key) =>
  transact("readwrite", (store) => store.delete("device:" + key));
export function putEncrypted(key, object) {
  if (
    !object ||
    typeof object !== "object" ||
    !object.ciphertext ||
    !object.nonce
  ) {
    throw new TypeError("Only encrypted vault objects may be persisted.");
  }
  return transact("readwrite", (store) => store.put(object, key));
}

export async function saveSealed({
  accountId,
  masterKey,
  objectId,
  revision,
  value,
  sealVaultObject,
}) {
  const object = await sealVaultObject({
    accountId,
    masterKey,
    objectId,
    revision,
    plaintext: new TextEncoder().encode(JSON.stringify(value)),
  });
  await putEncrypted(`${accountId}:${objectId}`, object);
  return object;
}

export async function loadSealed({
  accountId,
  masterKey,
  objectId,
  openVaultObject,
}) {
  const object = await getEncrypted(`${accountId}:${objectId}`);
  if (!object) return undefined;
  const plaintext = await openVaultObject({ accountId, masterKey, object });
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
  );
}
