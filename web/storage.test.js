// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { putEncrypted } from "./storage.js";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
test("plaintext cannot enter encrypted record store", () => {
  assert.throws(
    () => putEncrypted("key", { seed: "secret" }),
    /Only encrypted/,
  );
});

test("stale save after delayed database open never starts a write transaction", async () => {
  const source = (
    await readFile(new URL("./storage.js", import.meta.url), "utf8")
  ).replace(/\bexport /g, "");
  let opening,
    transactions = 0,
    valid = true;
  let opened;
  const entered = new Promise((resolve) => {
    opened = resolve;
  });
  const context = vm.createContext({
    TextEncoder,
    indexedDB: {
      open: () => {
        opening = {};
        opened();
        return opening;
      },
    },
  });
  vm.runInContext(source + ";globalThis.save=saveSealed;", context);
  const work = context.save({
    accountId: "account",
    objectId: "pending",
    revision: "1",
    value: {},
    sealVaultObject: async () => ({ ciphertext: "opaque", nonce: "nonce" }),
    beforePersist: () => {
      if (!valid) throw Error("SESSION_CHANGED");
    },
  });
  // Drain encryption and enter database.open without resolving it.
  await entered;
  assert.ok(opening);
  valid = false;
  opening.result = {
    transaction: () => {
      transactions++;
      throw Error("unexpected transaction");
    },
  };
  opening.onsuccess();
  await assert.rejects(work, /SESSION_CHANGED/);
  assert.equal(transactions, 0);
});

test("save committed before session change rejects its delayed completion instead of returning stale ciphertext", async () => {
  const source = (
    await readFile(new URL("./storage.js", import.meta.url), "utf8")
  ).replace(/\bexport /g, "");
  let tx,
    valid = true,
    started;
  const entered = new Promise((resolve) => {
    started = resolve;
  });
  const context = vm.createContext({
    TextEncoder,
    indexedDB: {
      open: () => {
        const opening = {};
        queueMicrotask(() => {
          opening.result = {
            transaction: () => {
              tx = {
                objectStore: () => ({
                  put: () => {
                    started();
                    return {};
                  },
                }),
              };
              return tx;
            },
          };
          opening.onsuccess();
        });
        return opening;
      },
    },
  });
  vm.runInContext(source + ";globalThis.save=saveSealed;", context);
  const work = context.save({
    accountId: "account",
    objectId: "pending",
    revision: "1",
    value: {},
    sealVaultObject: async () => ({ ciphertext: "opaque", nonce: "nonce" }),
    beforePersist: () => {
      if (!valid) throw Error("SESSION_CHANGED");
    },
  });
  await entered;
  valid = false;
  tx.oncomplete();
  await assert.rejects(work, /SESSION_CHANGED/);
});
