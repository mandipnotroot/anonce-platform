// SPDX-License-Identifier: AGPL-3.0-only
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "playwright";

test("receipt card downloads as a verifiable PNG and fits mobile layouts", async () => {
  const vector = JSON.parse(await readFile(new URL("../testdata/receipt-v2.json", import.meta.url), "utf8"));
  const server = createServer(async (request, response) => {
    try {
      if (request.url === "/") {
        response.end('<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/styles.css"><main id="app"></main>');
        return;
      }
      const path = `${process.cwd()}/web/${request.url.slice(1)}`;
      response.setHeader("Content-Type", request.url.endsWith(".css") ? "text/css" : "text/javascript");
      response.end(await readFile(path));
    } catch {
      response.statusCode = 404;
      response.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.evaluate(() => {
      document.querySelector("#app").innerHTML = '<section class="notice receipt-notice"><h2>Response accepted</h2><p class="receipt-status">Receipt signature verified</p><p>Accepted <time>Nov 5, 2026</time></p><p>Keep a copy of this receipt. It confirms acceptance, not what your response said.</p><div class="receipt-actions"><button type="button" class="button" id="download">Download receipt PNG</button><a class="button ghost" href="#/verify-receipt">Verify a receipt</a></div></section>';
    });
    const layouts = [];
    for (const width of [320, 375, 1280]) {
      await page.setViewportSize({ width, height: 900 });
      layouts.push(await page.evaluate(() => ({ width: innerWidth, document: document.documentElement.scrollWidth })));
    }
    assert.ok(layouts.every(({ width, document }) => document <= width));

    const card = await page.evaluate(async (receipt) => {
      const { renderReceiptPNG } = await import("/receipt-card.js");
      const blob = await renderReceiptPNG({ receipt });
      window.cardURL = URL.createObjectURL(blob);
      document.querySelector("#download").onclick = () => {
        const link = document.createElement("a");
        link.href = window.cardURL;
        link.download = "anonce-receipt.png";
        document.body.append(link);
        link.click();
        link.remove();
      };
      return { type: blob.type, size: blob.size };
    }, vector.receipt);
    assert.equal(card.type, "image/png");
    const downloadEvent = page.waitForEvent("download");
    await page.click("#download");
    const download = await downloadEvent;
    assert.equal(download.suggestedFilename(), "anonce-receipt.png");
    const png = await readFile(await download.path());
    const verification = await page.evaluate(async ({ receipt, trust, bytes }) => {
      const { decodeReceiptPNG } = await import("/receipt-qr.bundle.js");
      const { verifySavedReceipt } = await import("/app.js");
      const text = await decodeReceiptPNG({ file: new Blob([new Uint8Array(bytes)], { type: "image/png" }) });
      if (text !== JSON.stringify(receipt)) throw new Error("Downloaded card changed receipt bytes.");
      await verifySavedReceipt({ receiptText: text, trustText: JSON.stringify(trust) });
      return { decodedExact: true, signatureVerified: true };
    }, { receipt: vector.receipt, trust: vector.trust, bytes: [...png] });
    assert.deepEqual(verification, { decodedExact: true, signatureVerified: true });
    console.log(JSON.stringify({ card, filename: download.suggestedFilename(), verification, layouts }));
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
