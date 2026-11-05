// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir, readFile } from "node:fs/promises";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { chromium } from "playwright";

const root = resolve(fileURLToPath(new URL("../web/", import.meta.url)));
const artifactDir = process.env.ANONCE_UI_ARTIFACT_DIR || join(tmpdir(), "anonce-ui");
await mkdir(artifactDir, { recursive: true });
const mime = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".woff2": "font/woff2", ".svg": "image/svg+xml" };
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, "http://127.0.0.1").pathname;
  if (pathname === "/app.js") {
    response.writeHead(200, { "content-type": "text/javascript" });
    response.end(mockModule);
    return;
  }
  const file = resolve(root, `.${decodeURIComponent(pathname)}`);
  if (file !== root && !file.startsWith(root + sep)) {
    response.writeHead(404).end();
    return;
  }
  try {
    response.writeHead(200, { "content-type": mime[extname(file)] || "application/octet-stream" });
    response.end(await readFile(file));
  } catch {
    response.writeHead(404).end();
  }
});

const mockModule = `
let active = null;
const phrase = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima"];
export const getSourceURL=()=>"https://example.invalid/source";
export const getSession=async()=>active;
export const register=async()=>{active={account_id:"acct",login:"demo"};return {recoveryWords:phrase,session:active};};
export const login=async()=>{active={account_id:"acct",login:"demo"};return active;};
export const recover=async()=>{active={account_id:"acct",login:"demo"};return {recoveryWords:phrase,session:active};};
export const rotateRecovery=async()=>({recoveryWords:phrase,session:active});
export const listOrganizations=async()=>({items:[{id:"org",name:"Demo",role:"reviewer"}]});
export const listReviews=async()=>({items:[],next:null});
export const listPendingResponses=async()=>({items:[]});
export const getReview=async()=>({id:"review",title:"Demo review",status:"published",creator_account_id:"acct",revision:1,questions:[]});
export const listResponses=async()=>({items:[{id:"r1",acceptedAt:"2026-01-01T00:00:00Z",status:"invalid",error:"RESPONSE_UNREADABLE",answers:[]}],next:null});
`;

async function verifyRecoveryTools(page, expected) {
  await page.getByRole("button", { name: "Copy phrase" }).click();
  await page.getByText("Phrase copied.").waitFor();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), expected);
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download .txt" }).click();
  const download = await downloadPromise;
  assert.equal(download.suggestedFilename(), "anonce-recovery-phrase.txt");
  assert.equal(await readFile(await download.path(), "utf8"), `${expected}\n`);
}

let browser;
try {
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const { port } = server.address();
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  const requestPayloads = [];
  page.on("request", (request) => requestPayloads.push(`${request.url()} ${request.postData() || ""}`));
  const captures = async (name) => {
    for (const viewport of [{ width: 1365, height: 900 }, { width: 768, height: 1024 }, { width: 390, height: 844 }, { width: 375, height: 812 }, { width: 320, height: 720 }]) {
      await page.setViewportSize(viewport);
      for (const colorScheme of ["light", "dark"]) {
        await page.emulateMedia({ colorScheme });
        await page.evaluate(() => window.scrollTo(0, 0));
        assert.equal(await page.evaluate(() => Math.abs(document.querySelector("main").getBoundingClientRect().left - document.querySelector(".brand").getBoundingClientRect().left) < 1), true, `${name} main offset suggests phantom sidebar at ${viewport.width}px`);
        assert.equal(await page.evaluate(() => { const nav = document.querySelector(".site-header nav").getBoundingClientRect(); const header = document.querySelector(".site-header").getBoundingClientRect(); return nav.left >= header.left && nav.right <= header.right; }), true, `${name} navigation exceeds header at ${viewport.width}px`);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), true, `${name} overflow at ${viewport.width}px`);
        await page.screenshot({ path: join(artifactDir, `anonce-${name}-${viewport.width}-${colorScheme}.png`), fullPage: true });
      }
    }
  };
  await page.goto(`http://127.0.0.1:${port}/index.html#/login`);
  assert.ok(await page.locator(".site-header nav").count(), "reference-style centered navigation missing");
  assert.equal(await page.locator(".side,.mobile-head").count(), 0, "legacy sidebar or mobile dock remains");
  assert.ok(await page.locator(".site-footer").count(), "reference-style footer missing");
  await captures("auth");
  await page.goto(`http://127.0.0.1:${port}/index.html#/register`);
  await page.locator("#login").fill("demo");
  await page.locator("#password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByRole("heading", { name: "Your recovery phrase" }).waitFor();
  await captures("recovery");

  for (const viewport of [{ width: 1365, height: 900 }, { width: 768, height: 1024 }, { width: 390, height: 844 }, { width: 375, height: 812 }, { width: 320, height: 720 }]) {
    await page.setViewportSize(viewport);
    const theme = await page.evaluate(() => ({
      scheme: getComputedStyle(document.documentElement).colorScheme,
      background: getComputedStyle(document.body).backgroundColor,
      overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      iconFailures: [...document.querySelectorAll(".icon")].filter((icon) => !icon.complete || icon.naturalWidth === 0).length,
    }));
    assert.equal(theme.scheme, "light dark");
    assert.equal(theme.overflow, false, `horizontal overflow at ${viewport.width}px`);
    assert.equal(theme.iconFailures, 0, `broken Lucide icon at ${viewport.width}px`);
  }

  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const expectedPhrase = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima";
  await verifyRecoveryTools(page, expectedPhrase);
  assert.ok(requestPayloads.every((payload) => !payload.includes("alpha bravo charlie")), "recovery phrase leaked into a network request");

  await page.evaluate(() => { location.hash = "#/review/review/results"; });
  await page.getByText("This response could not be decrypted or validated.").waitFor();
  await captures("results");
  const routeBeforeSkip = await page.evaluate(() => location.hash);
  const headingBeforeSkip = await page.getByRole("heading", { level: 1 }).textContent();
  await page.locator(".skip-link").focus();
  await page.locator(".skip-link").press("Enter");
  const skipResult = await page.evaluate(() => ({
    route: location.hash,
    focus: document.activeElement?.id,
    heading: document.querySelector(".page-head h1")?.textContent || document.querySelector(".response-card h1")?.textContent,
  }));
  assert.equal(skipResult.route, routeBeforeSkip, "skip navigation changed application route");
  assert.equal(skipResult.focus, "main-content", "skip navigation did not focus main landmark");
  assert.equal(skipResult.heading, headingBeforeSkip, "skip navigation replaced current page");

  for (const viewport of [{ width: 1365, height: 900 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const iconFilters = {};
    for (const colorScheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme });
      const theme = await page.evaluate(() => ({
        scheme: getComputedStyle(document.documentElement).colorScheme,
        background: getComputedStyle(document.documentElement).getPropertyValue("--paper").trim(),
        iconFilter: getComputedStyle(document.querySelector(".icon")).filter,
        overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        iconFailures: [...document.querySelectorAll(".icon")].filter((icon) => !icon.complete || icon.naturalWidth === 0).length,
      }));
      assert.equal(theme.scheme, "light dark");
      assert.equal(theme.background, colorScheme === "dark" ? "#141a1f" : "#f4f7f9", `${colorScheme} theme missing at ${viewport.width}px`);
      iconFilters[colorScheme] = theme.iconFilter;
      assert.equal(theme.overflow, false, `horizontal overflow at ${viewport.width}px`);
      assert.equal(theme.iconFailures, 0, `broken Lucide icon at ${viewport.width}px`);
      await page.screenshot({ path: join(artifactDir, `anonce-${viewport.width}-${colorScheme}.png`), fullPage: true });
    }
    assert.notEqual(iconFilters.dark, iconFilters.light, `icon filter did not change for dark mode at ${viewport.width}px`);
  }

  const recoveryPage = await context.newPage();
  await recoveryPage.goto(`http://127.0.0.1:${port}/index.html#/recover`);
  await recoveryPage.locator("#login").fill("demo");
  await recoveryPage.locator("#words").fill("old phrase from user");
  await recoveryPage.locator("#password").fill("another correct horse battery staple");
  await recoveryPage.getByRole("button", { name: "Recover account" }).click();
  await recoveryPage.getByRole("heading", { name: "Your recovery phrase" }).waitFor();
  await verifyRecoveryTools(recoveryPage, expectedPhrase);
  await recoveryPage.locator("#saved").check();
  await recoveryPage.getByRole("button", { name: "Continue to Anonce" }).click();
  await recoveryPage.getByRole("heading", { name: "Overview" }).waitFor();
  for (const viewport of [{ width: 1365, height: 900 }, { width: 390, height: 844 }]) {
    await recoveryPage.setViewportSize(viewport);
    for (const colorScheme of ["light", "dark"]) {
      await recoveryPage.emulateMedia({ colorScheme });
      await recoveryPage.evaluate(() => window.scrollTo(0, 0));
      assert.equal(await recoveryPage.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), true, `workspace overflow at ${viewport.width}px`);
      assert.equal(await recoveryPage.evaluate(() => Math.abs(document.querySelector("main").getBoundingClientRect().left - document.querySelector(".brand").getBoundingClientRect().left) < 1), true, `workspace main offset suggests phantom sidebar at ${viewport.width}px`);
      await recoveryPage.screenshot({ path: join(artifactDir, `anonce-workspace-${viewport.width}-${colorScheme}.png`), fullPage: true });
    }
  }
  await recoveryPage.evaluate(() => { location.hash = "#/account"; });
  await recoveryPage.getByRole("heading", { name: "Recovery phrase" }).waitFor();
  await recoveryPage.locator('input[name="currentPassword"]').last().fill("current password");
  await recoveryPage.getByRole("button", { name: "Rotate recovery phrase" }).click();
  await recoveryPage.getByRole("button", { name: "Copy phrase" }).waitFor();
  await verifyRecoveryTools(recoveryPage, expectedPhrase);
  console.log("UI check passed: light/dark themes, responsive overflow, Lucide assets, skip navigation, recovery flows, invalid response notice.");
} finally {
  await browser?.close();
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
}
