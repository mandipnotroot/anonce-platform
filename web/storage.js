// SPDX-License-Identifier: AGPL-3.0-only
// Only authenticated ciphertext records belong here. Secrets stay in memory.
import { openDB } from "idb";

const DATABASE = "anonce-encrypted-v1";
const STORE = "records";
let opening;

function database() {
  if (!opening) {
    let abandoned = false;
    let connection;
    const invalidate = () => {
      if (opening === attempt) opening = undefined;
    };
    const attempt = new Promise((resolve, reject) => {
      // Defer open so the attempt identity exists even for synchronous failures.
      Promise.resolve()
        .then(() => {
          return openDB(DATABASE, 1, {
            upgrade(db) {
              db.createObjectStore(STORE);
            },
            blocked() {
              abandoned = true;
              invalidate();
              reject(new Error("Close other Anonce tabs and retry."));
            },
            blocking() {
              connection?.close();
              invalidate();
            },
            terminated: invalidate,
          }).then((db) => {
            connection = db;
            if (abandoned) db.close();
            else resolve(db);
          });
        })
        .catch(() => {
          invalidate();
          reject(new Error("Encrypted local storage unavailable."));
        });
    });
    opening = attempt;
  }
  return opening;
}

async function transact(mode, operation, beforePersist) {
  const db = await database();
  beforePersist?.();
  let tx;
  let done;
  try {
    tx = db.transaction(STORE, mode);
    done = tx.done;
    // Observe both rejections immediately, and wait for commit, not just request success.
    const [result] = await Promise.all([
      operation(tx.objectStore(STORE)),
      done,
    ]);
    return result;
  } catch {
    // A synchronous request error can leave a transaction active.
    try {
      tx?.abort();
    } catch {
      // Already completed or aborted.
    }
    await done?.catch(() => {});
    throw new Error("Encrypted local storage operation failed.");
  }
}

export const getEncrypted = (key) =>
  transact("readonly", (store) => store.get(key));
export const allEncrypted = () =>
  transact("readonly", (store) => store.getAll());
export const deleteEncrypted = (key) =>
  transact("readwrite", (store) => store.delete(key));
export const getDeviceRecord = (key) =>
  transact("readonly", (store) => store.get("device:" + key));
export const putDeviceRecord = (key, value, beforePersist) =>
  transact(
    "readwrite",
    (store) => store.put(value, "device:" + key),
    beforePersist,
  );
export const deleteDeviceRecord = (key) =>
  transact("readwrite", (store) => store.delete("device:" + key));
export function putEncrypted(key, object, beforePersist) {
  if (
    !object ||
    typeof object !== "object" ||
    !object.ciphertext ||
    !object.nonce
  ) {
    throw new TypeError("Only encrypted vault objects may be persisted.");
  }
  return transact(
    "readwrite",
    (store) => store.put(object, key),
    beforePersist,
  );
}

export async function saveSealed({
  accountId,
  masterKey,
  objectId,
  revision,
  value,
  sealVaultObject,
  beforePersist,
}) {
  const object = await sealVaultObject({
    accountId,
    masterKey,
    objectId,
    revision,
    plaintext: new TextEncoder().encode(JSON.stringify(value)),
  });
  beforePersist?.();
  await putEncrypted(`${accountId}:${objectId}`, object, beforePersist);
  beforePersist?.();
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
