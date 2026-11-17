// SPDX-License-Identifier: AGPL-3.0-only
import { createServer, get } from "node:http";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright";
import { build } from "esbuild";
import assert from "node:assert/strict";

const encoder = await build({
  stdin: {
    contents: "import QRCode from 'qrcode/lib/browser.js'; export {QRCode};",
    resolveDir: process.cwd(),
  },
  bundle: true,
  format: "esm",
  platform: "browser",
  write: false,
});
const assets = new Map([
  ["/", { type: "text/html", body: "<!doctype html>" }],
  [
    "/encoder.js",
    { type: "text/javascript", body: encoder.outputFiles[0].contents },
  ],
]);
for (const name of [
  "receipt-qr.bundle.js",
  "app.js",
  "crypto.bundle.js",
  "api.js",
  "storage.js",
  "receipt-card.js",
]) {
  assets.set(`/${name}`, {
    type: "text/javascript",
    body: await readFile(new URL(`../web/${name}`, import.meta.url)),
  });
}
const vector = JSON.parse(await readFile("testdata/receipt-v2.json", "utf8"));
const csp =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const server = createServer((req, res) => {
  res.setHeader("Content-Security-Policy", csp);
  const asset = assets.get(req.url);
  if (!asset) {
    res.statusCode = 404;
    res.end();
    return;
  }
  res.setHeader("Content-Type", asset.type);
  res.end(asset.body);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
try {
  // Use raw HTTP paths: URL-based clients can normalize traversal before sending.
  for (const path of [
    ...assets.keys(),
    "/unknown.js",
    "/../package.json",
    "/../../etc/passwd",
    "/%2e%2e/package.json",
    "/..%2fpackage.json",
    "/%252e%252e%252fpackage.json",
    "/..\\package.json",
    "/app.js?file=../package.json",
    "//app.js",
  ]) {
    const response = await new Promise((resolve, reject) => {
      get(
        { hostname: "127.0.0.1", port: server.address().port, path },
        (res) => {
          const chunks = [];
          res.on("data", (chunk) => chunks.push(chunk));
          res.on("end", () =>
            resolve({ status: res.statusCode, body: Buffer.concat(chunks) }),
          );
          res.on("error", reject);
        },
      ).on("error", reject);
    });
    assert.equal(response.status, assets.has(path) ? 200 : 404, path);
    assert.deepEqual(
      response.body,
      assets.has(path) ? Buffer.from(assets.get(path).body) : Buffer.alloc(0),
      path,
    );
  }
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on("console", (message) => {
    if (message.type() === "error") console.error(message.text());
  });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.evaluate(() => {
    window.cspViolations = [];
    document.addEventListener("securitypolicyviolation", (event) =>
      window.cspViolations.push({
        directive: event.effectiveDirective,
        blockedURI: event.blockedURI,
      }),
    );
  });
  const result = await page.evaluate(async (vector) => {
    const { createReceiptQRCanvas, decodeReceiptPNG } =
      await import("/receipt-qr.bundle.js");
    const { verifySavedReceipt } = await import("/app.js");
    const { QRCode } = await import("/encoder.js");
    const png = (canvas) =>
      new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
    const canvas = await createReceiptQRCanvas({ receipt: vector.receipt });
    const text = await decodeReceiptPNG({ file: await png(canvas) });
    if (text !== JSON.stringify(vector.receipt))
      throw Error("Roundtrip changed bytes");
    await verifySavedReceipt({
      receiptText: text,
      trustText: JSON.stringify(vector.trust),
    });
    const { renderReceiptPNG } = await import("/receipt-card.js");
    const cardText = await decodeReceiptPNG({
      file: await renderReceiptPNG({ receipt: vector.receipt }),
    });
    if (cardText !== text) throw Error("Full card changed receipt bytes");
    await verifySavedReceipt({
      receiptText: cardText,
      trustText: JSON.stringify(vector.trust),
    });
    let negatives = 0;
    async function reject(action) {
      try {
        await action();
      } catch {
        negatives++;
        return;
      }
      throw Error("Expected rejection");
    }
    const blank = document.createElement("canvas");
    blank.width = blank.height = 512;
    await reject(async () => decodeReceiptPNG({ file: await png(blank) }));
    for (const payload of ["x".repeat(1601), new Uint8Array([0xc3, 0x28])]) {
      const qr = await QRCode.toCanvas(
        document.createElement("canvas"),
        [{ data: payload, mode: "byte" }],
        { scale: 8, margin: 4 },
      );
      await reject(async () => decodeReceiptPNG({ file: await png(qr) }));
    }
    const duplicate = text.replace('"v":2', '"v":2,"v":2');
    const qr = await QRCode.toCanvas(
      document.createElement("canvas"),
      duplicate,
      { scale: 8, margin: 4 },
    );
    const decoded = await decodeReceiptPNG({ file: await png(qr) });
    if (decoded !== duplicate) throw Error("Duplicate keys lost");
    await reject(() =>
      verifySavedReceipt({
        receiptText: decoded,
        trustText: JSON.stringify(vector.trust),
      }),
    );
    const bad = { ...vector.receipt, signature: "A".repeat(86) };
    const badText = await decodeReceiptPNG({
      file: await png(await createReceiptQRCanvas({ receipt: bad })),
    });
    await reject(() =>
      verifySavedReceipt({
        receiptText: badText,
        trustText: JSON.stringify(vector.trust),
      }),
    );
    return {
      width: canvas.width,
      negatives,
      exact: true,
      signatureVerified: true,
      fullCardVerified: true,
    };
  }, vector);
  assert.equal(result.negatives, 5);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  console.log(JSON.stringify(result));
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
