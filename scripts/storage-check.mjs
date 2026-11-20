// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright";

// Disposable origin and browser context: never touches an operator's database.
const bundle = await readFile(
  new URL("../web/storage.bundle.js", import.meta.url),
);
const server = createServer((req, res) => {
  res.setHeader(
    "Content-Type",
    req.url === "/storage.js" ? "text/javascript" : "text/html",
  );
  res.end(
    req.url === "/storage.js"
      ? bundle
      : "<!doctype html><title>Storage test</title>",
  );
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.evaluate(async () => {
    const s = await import("/storage.js");
    const record = { ciphertext: "synthetic", nonce: "synthetic" };
    const check = (condition) => {
      if (!condition) throw Error("storage assertion failed");
    };
    await s.putEncrypted("test", record);
    check((await s.getEncrypted("test")).ciphertext === "synthetic");
    check((await s.allEncrypted()).length === 1);
    await s.putDeviceRecord("key", record);
    check((await s.getDeviceRecord("key")).nonce === "synthetic");
    await s.deleteDeviceRecord("key");
    await s.deleteEncrypted("test");
    check((await s.allEncrypted()).length === 0);
    // A non-cloneable device value exercises synchronous request failure handling.
    try {
      await s.putDeviceRecord("bad", () => {});
      throw Error("unexpected success");
    } catch (error) {
      check(error.message === "Encrypted local storage operation failed.");
    }
    // A real versionchange closes the cached connection; reopening version 1 fails.
    const upgraded = await new Promise((resolve, reject) => {
      const req = indexedDB.open("anonce-encrypted-v1", 2);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    upgraded.close();
    try {
      await s.getEncrypted("test");
      throw Error("unexpected success");
    } catch (error) {
      check(error.message === "Encrypted local storage unavailable.");
    }
  });
  assert.deepEqual(errors, []);
  console.log(
    "Chromium storage CRUD, request failure, and versionchange passed.",
  );
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
