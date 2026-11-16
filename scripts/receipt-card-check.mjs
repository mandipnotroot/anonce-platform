// SPDX-License-Identifier: AGPL-3.0-only
import { createServer } from "node:http";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import assert from "node:assert/strict";
import { test } from "node:test";
import { chromium } from "playwright";

test("receipt card downloads as a verifiable PNG and fits mobile layouts", async () => {
  const vector = JSON.parse(
    await readFile(
      new URL("../testdata/receipt-v2.json", import.meta.url),
      "utf8",
    ),
  );
  const server = createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url, "http://localhost").pathname;
      if (pathname === "/api/member/me") {
        response.statusCode = 401;
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }
      if (pathname === "/api/public/config") {
        response.setHeader("Content-Type", "application/json");
        response.end(
          JSON.stringify({ ...vector.trust, ca_certificate: "unused" }),
        );
        return;
      }
      const path =
        pathname === "/"
          ? `${process.cwd()}/web/index.html`
          : `${process.cwd()}/web/${pathname.slice(1)}`;
      response.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      );
      response.setHeader(
        "Content-Type",
        pathname === "/" || pathname.endsWith(".html")
          ? "text/html"
          : pathname.endsWith(".css")
            ? "text/css"
            : "text/javascript",
      );
      response.end(await readFile(path));
    } catch {
      response.statusCode = 404;
      response.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  let browser;
  let tempDir;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({
      acceptDownloads: true,
      viewport: { width: 1280, height: 900 },
    });
    const pageErrors = [];
    const requestFailures = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    page.on("console", (message) => {
      if (
        new URL(message.location().url || "about:blank").pathname ===
          "/api/member/me" &&
        message.text().includes("401 (Unauthorized)")
      )
        return;
      if (message.type() === "error") pageErrors.push(message.text());
    });
    page.on("requestfailed", (request) =>
      requestFailures.push(`${request.url()}: ${request.failure()?.errorText}`),
    );
    await page.goto(
      `http://127.0.0.1:${server.address().port}/#/verify-receipt`,
    );
    await page
      .waitForSelector("#verify-receipt-file", {
        state: "attached",
        timeout: 5000,
      })
      .catch(() => {
        throw new Error(
          `Verifier did not render: ${JSON.stringify({ errors: pageErrors })}`,
        );
      });
    const layouts = [];
    for (const width of [320, 375, 1280]) {
      await page.setViewportSize({ width, height: 900 });
      layouts.push(
        await page.evaluate(() => ({
          width: innerWidth,
          document: document.documentElement.scrollWidth,
        })),
      );
    }
    assert.ok(layouts.every(({ width, document }) => document <= width));

    tempDir = await mkdtemp("/tmp/opencode/anonce-receipt-");
    const pngPath = join(tempDir, "receipt.png");
    const trustPath = join(tempDir, "trust.json");
    const card = await page.evaluate(async (receipt) => {
      const { renderReceiptPNG } = await import("/receipt-card.js");
      const { createReceiptQRCanvas } = await import("/receipt-qr.bundle.js");
      const blob = await renderReceiptPNG({ receipt });
      const qr = await createReceiptQRCanvas({ receipt });
      const image = await createImageBitmap(blob);
      const pixels = document.createElement("canvas");
      pixels.width = image.width;
      pixels.height = image.height;
      const context = pixels.getContext("2d", { willReadFrequently: true });
      context.drawImage(image, 0, 0);
      const outputData = context.getImageData(
        0,
        0,
        image.width,
        image.height,
      ).data;
      const qrData = qr
        .getContext("2d", { willReadFrequently: true })
        .getImageData(0, 0, qr.width, qr.height).data;
      const matches =
        image.width === qr.width &&
        image.height === qr.height &&
        outputData.every((value, index) => value === qrData[index]);
      image.close();
      return {
        type: blob.type,
        size: blob.size,
        width: qr.width,
        height: qr.height,
        matchesQR: matches,
        bytes: [...new Uint8Array(await blob.arrayBuffer())],
      };
    }, vector.receipt);
    assert.equal(card.type, "image/png");
    assert.equal(card.width, card.height, "receipt PNG is square");
    assert.equal(
      card.matchesQR,
      true,
      "PNG pixels equal the generated QR including quiet zone",
    );
    await writeFile(pngPath, Buffer.from(card.bytes));
    await writeFile(trustPath, JSON.stringify(vector.trust));
    await page.locator(".verify-trust summary").click();
    await page.locator("#verify-trust-file").setInputFiles(trustPath);
    await page.waitForFunction(
      () =>
        document.querySelector("#verify-trust-text").value.includes('"keys"') ||
        document.querySelector("#verify-trust-text").value.length > 0,
    );
    await page.locator("#verify-receipt-file").setInputFiles(pngPath);
    await page
      .waitForFunction(
        () =>
          document.querySelector("#receipt-file-status").textContent ===
          "Receipt image loaded. Ready to verify.",
        null,
        { timeout: 15000 },
      )
      .catch(async () => {
        throw new Error(
          `PNG decode state: ${JSON.stringify(await page.evaluate(() => ({ files: [...document.querySelector("#verify-receipt-file").files].map((file) => file.name), receiptTextLength: document.querySelector("#verify-receipt-text").value.length, status: document.querySelector("#receipt-file-status").textContent, result: document.querySelector("#verify-result").textContent })))}; errors=${JSON.stringify(pageErrors)} requests=${JSON.stringify(requestFailures)}`,
        );
      });
    const states = await page.evaluate(() => ({
      fileCount: document.querySelector("#verify-receipt-file").files.length,
      receiptTextLength: document.querySelector("#verify-receipt-text").value
        .length,
      status: document.querySelector("#receipt-file-status").textContent,
    }));
    assert.ok(states.receiptTextLength > 0, JSON.stringify(states));
    await page.click("#verify-receipt");
    await page.waitForFunction(() =>
      document
        .querySelector("#verify-result")
        .textContent.includes("Receipt signature verified"),
    );
    assert.deepEqual(pageErrors, []);
    console.log(
      JSON.stringify({
        card: { type: card.type, size: card.size },
        states,
        verified: true,
        layouts,
      }),
    );
  } finally {
    await browser?.close();
    if (tempDir) await rm(tempDir, { recursive: true });
    await new Promise((resolve) => server.close(resolve));
  }
});
