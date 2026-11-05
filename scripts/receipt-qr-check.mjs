// SPDX-License-Identifier: AGPL-3.0-only
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright";
import { build } from "esbuild";
import assert from "node:assert/strict";

await build({
  stdin: {
    contents: "import QRCode from 'qrcode/lib/browser.js'; export {QRCode};",
    resolveDir: process.cwd(),
  },
  bundle: true,
  format: "esm",
  platform: "browser",
  outfile: "/tmp/opencode/qr-test-encoder.js",
});
const vector = JSON.parse(await readFile("testdata/receipt-v2.json", "utf8"));
const csp =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const server = createServer(async (req, res) => {
  res.setHeader("Content-Security-Policy", csp);
  try {
    if (req.url === "/") {
      res.end("<!doctype html>");
      return;
    }
    const path =
      req.url === "/encoder.js"
        ? "/tmp/opencode/qr-test-encoder.js"
        : `${process.cwd()}/web/${req.url.slice(1)}`;
    res.setHeader("Content-Type", "text/javascript");
    res.end(await readFile(path));
  } catch {
    res.statusCode = 404;
    res.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
try {
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
