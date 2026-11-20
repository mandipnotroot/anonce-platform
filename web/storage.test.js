// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
};
async function fixture() {
  const opens = [];
  const source = (
    await readFile(new URL("./storage.js", import.meta.url), "utf8")
  )
    .replace('import { openDB } from "idb";', "")
    .replace(/\bexport /g, "");
  const context = vm.createContext({
    TextEncoder,
    openDB: (_name, _version, callbacks) => {
      const pending = deferred();
      opens.push({ ...pending, callbacks });
      return pending.promise;
    },
  });
  vm.runInContext(
    source +
      ";globalThis.api={getEncrypted,allEncrypted,putEncrypted,deleteEncrypted,getDeviceRecord,putDeviceRecord,deleteDeviceRecord,saveSealed};",
    context,
  );
  const tick = () => new Promise(setImmediate);
  return { api: context.api, opens, tick };
}
function connection() {
  const transactions = [];
  let closed = false;
  const db = {
    close() {
      closed = true;
    },
    transaction(store, mode) {
      assert.equal(store, "records");
      const done = deferred(),
        request = deferred();
      const calls = [];
      const tx = {
        done: done.promise,
        abort() {
          done.reject(Error("abort"));
        },
        objectStore: () =>
          Object.fromEntries(
            ["get", "getAll", "put", "delete"].map((name) => [
              name,
              (...args) => {
                calls.push([name, ...args]);
                return request.promise;
              },
            ]),
          ),
      };
      transactions.push({ done, request, calls, mode });
      return tx;
    },
  };
  return {
    db,
    transactions,
    get closed() {
      return closed;
    },
  };
}
test("ciphertext guard and CRUD wait for transaction commit", async () => {
  const f = await fixture(),
    c = connection();
  assert.throws(
    () => f.api.putEncrypted("x", { secret: true }),
    /Only encrypted/,
  );
  const object = { ciphertext: "opaque", nonce: "nonce" };
  const cases = [
    ["putEncrypted", ["x", object], ["put", object, "x"]],
    ["getEncrypted", ["x"], ["get", "x"]],
    ["allEncrypted", [], ["getAll"]],
    ["deleteEncrypted", ["x"], ["delete", "x"]],
    ["putDeviceRecord", ["x", object], ["put", object, "device:x"]],
    ["getDeviceRecord", ["x"], ["get", "device:x"]],
    ["deleteDeviceRecord", ["x"], ["delete", "device:x"]],
  ];
  for (const [method, args, expected] of cases) {
    let settled = false;
    const work = f.api[method](...args).then((value) => {
      settled = true;
      return value;
    });
    await f.tick();
    if (f.opens.length === 1 && !c.transactions.length) {
      f.opens[0].resolve(c.db);
      await f.tick();
    }
    const tx = c.transactions.at(-1);
    assert.deepEqual(tx.calls[0], expected);
    tx.request.resolve("result");
    await f.tick();
    assert.equal(settled, false);
    tx.done.resolve();
    assert.equal(await work, "result");
  }
});
test("request failure and transaction abort are stable errors without unhandled rejection", async () => {
  for (const failure of ["request", "commit"]) {
    const f = await fixture(),
      c = connection();
    const work = f.api.getEncrypted("x");
    const rejected = assert.rejects(
      work,
      /Encrypted local storage operation failed/,
    );
    await f.tick();
    f.opens[0].resolve(c.db);
    await f.tick();
    const tx = c.transactions[0];
    if (failure === "request") tx.request.reject(Error("request"));
    else tx.request.resolve("value");
    tx.done.reject(Error("abort"));
    await rejected;
  }
});
test("failed opens retry; blocked late success closes without clearing a newer attempt", async () => {
  const f = await fixture();
  let work = f.api.getEncrypted("x");
  let rejection = assert.rejects(work, /unavailable/);
  await f.tick();
  f.opens[0].reject(Error("open"));
  await rejection;
  work = f.api.getEncrypted("x");
  rejection = assert.rejects(work, /Close other Anonce tabs/);
  await f.tick();
  f.opens[1].callbacks.blocked();
  await rejection;
  const retry = f.api.getEncrypted("x");
  await f.tick();
  const late = connection();
  f.opens[1].resolve(late.db);
  await f.tick();
  assert.equal(late.closed, true);
  const c = connection();
  f.opens[2].resolve(c.db);
  await f.tick();
  c.transactions[0].request.resolve();
  c.transactions[0].done.resolve();
  await retry;
  assert.equal(f.opens.length, 3);
  f.opens[2].callbacks.blocking();
  assert.equal(c.closed, true);
  work = f.api.getEncrypted("x");
  rejection = assert.rejects(work, /unavailable/);
  await f.tick();
  f.opens[3].reject(Error("open"));
  await rejection;
});
test("terminated connections invalidate the cached open", async () => {
  const f = await fixture(),
    c = connection();
  const work = f.api.getEncrypted("x");
  await f.tick();
  f.opens[0].resolve(c.db);
  await f.tick();
  c.transactions[0].request.resolve();
  c.transactions[0].done.resolve();
  await work;
  f.opens[0].callbacks.terminated();
  const retry = f.api.getEncrypted("x");
  const rejected = assert.rejects(retry, /unavailable/);
  await f.tick();
  assert.equal(f.opens.length, 2);
  f.opens[1].reject(Error("open"));
  await rejected;
});

test("session invalidation before transaction and after commit preserves callback timing", async () => {
  for (const when of ["open", "commit"]) {
    const f = await fixture(),
      c = connection();
    let valid = true,
      checks = 0;
    const work = f.api.saveSealed({
      accountId: "account",
      objectId: "object",
      revision: "1",
      value: {},
      sealVaultObject: async () => ({ ciphertext: "opaque", nonce: "nonce" }),
      beforePersist() {
        checks++;
        if (!valid) throw Error("SESSION_CHANGED");
      },
    });
    const rejected = assert.rejects(work, /SESSION_CHANGED/);
    await f.tick();
    if (when === "open") valid = false;
    f.opens[0].resolve(c.db);
    await f.tick();
    if (when === "open") assert.equal(c.transactions.length, 0);
    else {
      valid = false;
      c.transactions[0].request.resolve();
      c.transactions[0].done.resolve();
    }
    await rejected;
    assert.equal(checks, when === "open" ? 2 : 3);
  }
});
