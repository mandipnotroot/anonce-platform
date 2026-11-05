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
let mockRole = "owner";
export const addedMembers=[];
const phrase = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima"];
export const getSourceURL=()=>"https://example.invalid/source";
export const getSession=async()=>active;
export const register=async({email})=>{active={account_id:"acct",email};return {recoveryWords:phrase,session:active};};
export const login=async({email,password})=>{if(password==="fail-password")throw new Error("Email or password is incorrect.");active={account_id:"acct",email};return active;};
export const recover=async({email})=>{active={account_id:"acct",email};return {recoveryWords:phrase,session:active};};
export const rotateRecovery=async()=>({recoveryWords:phrase,session:active});
export const setMockRole=role=>mockRole=role;
export const listOrganizations=async()=>({items:[{id:"org",name:"Demo workspace",role:mockRole},{id:"other",name:"Other workspace",role:mockRole}]});
export const listMembers=async()=>({items:[{id:"owner",email:"owner@example.net",role:"owner",status:"approved"},{id:"admin",email:"admin@example.net",role:"admin",status:"approved"},{id:"reviewer",email:"reviewer@example.net",role:"reviewer",status:"approved"},{id:"respondent",email:"respondent@example.net",role:"respondent",status:"approved"},{id:"pending",email:"pending@example.net",role:"respondent",status:"pending"},{id:"revoked",email:"revoked@example.net",role:"reviewer",status:"revoked"}]});
export const addMember=async({email,role})=>addedMembers.push({email,role});
export const approveMember=async()=>{};
export const revokeMember=async()=>{};
export const changeMemberRole=async()=>{};
export const listReviews=async()=>({items:[],next:null});
export const listPendingResponses=async()=>({items:[]});
export const createReview=async()=>({id:"new-review",org_id:"org",title:"Draft review",status:"draft",creator_account_id:"acct",revision:1,questions:[]});
export const updateReview=async()=>({});
export const publishReview=async()=>({});
export const prepareResponse=async()=>({pendingId:"pending-response"});
export const submitResponse=async()=>({status:"accepted",receipt:{version:1,signature:"mock-signed-receipt"}});
export const lookupReceipt=async()=>({status:"accepted",receipt:{version:1,signature:"mock-signed-receipt"}});
export const getReview=async({reviewId})=>({id:reviewId,org_id:reviewId==="review"?"other":"org",title:reviewId==="review"?"Demo review":"Draft review",description:"Share feedback",status:reviewId==="review"?"closed":"draft",creator_account_id:"acct",revision:1,questions:[{id:"question-1",text:"What should change?",type:"text",required:true,options:[]}]});
export const listResponses=async()=>({items:[{id:"r1",acceptedAt:"2026-01-01T00:00:00Z",status:"invalid",error:"RESPONSE_UNREADABLE",answers:[]}],next:null});
`;

async function verifyRecoveryTools(page, expected) {
  await page.getByRole("button", { name: "Copy phrase" }).click();
  await page.locator("#toast-region").getByText("Phrase copied.").waitFor();
  await page.getByRole("button", { name: "Dismiss notification" }).click();
  await page.locator("#toast-region").getByText("Phrase copied.").waitFor({ state: "detached" });
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
        assert.equal(await page.evaluate(() => [...document.querySelectorAll(".button")].every((button) => button.getAttribute("aria-label") || button.textContent.trim())), true, `${name} button accessible name missing`);
        assert.equal(await page.evaluate(() => [...document.querySelectorAll(".button .icon")].every((icon) => icon.complete && icon.naturalWidth > 0)), true, `${name} action icon failed to load`);
        assert.equal(await page.evaluate(() => [...document.querySelectorAll(".button")].every((button) => button.querySelector(".icon"))), true, `${name} action button icon missing`);
        if (name === "recovery") assert.equal(await page.evaluate(() => { const alert = document.querySelector(".auth-card .alert").getBoundingClientRect(); const firstWord = document.querySelector(".word").getBoundingClientRect(); return firstWord.top - alert.bottom >= 12; }), true, `recovery warning touches word grid at ${viewport.width}px`);
        if (name === "results") {
          const contrast = await page.evaluate(() => {
            const luminance = (color) => color.match(/[\d.]+/g).slice(0, 3).map(value => Number(value) / 255).map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
            return ["positive", "warning", "danger", "closed", "muted"].map(tone => {
              const badge = document.createElement("span");
              badge.className = `status-badge status-${tone}`;
              const icon = document.querySelector(".status-badge .icon")?.cloneNode();
              if (icon) badge.appendChild(icon);
              document.body.appendChild(badge);
              const style = getComputedStyle(badge);
              const ratio = (first, second) => { const colors = [first, second].map(luminance).sort((a, b) => b - a); return (colors[0] + .05) / (colors[1] + .05); };
              const textContrast = ratio(style.color, style.backgroundColor);
              const borderContrast = ratio(style.borderTopColor, style.backgroundColor);
              const iconStyle = icon && getComputedStyle(icon);
              const iconVisible = Boolean(iconStyle && iconStyle.filter !== "none" && iconStyle.opacity !== "0");
              badge.remove();
              return { tone, textContrast, borderContrast, iconVisible };
            });
          });
          for (const { tone, textContrast, borderContrast, iconVisible } of contrast) {
            assert.ok(textContrast >= 4.5, `${tone} badge text contrast ${textContrast.toFixed(2)} below WCAG AA at ${viewport.width}px (${colorScheme})`);
            assert.ok(borderContrast >= 3, `${tone} badge boundary contrast ${borderContrast.toFixed(2)} below 3:1 at ${viewport.width}px (${colorScheme})`);
            assert.equal(iconVisible, true, `${tone} badge icon filter missing at ${viewport.width}px (${colorScheme})`);
          }
        }
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
  await page.locator("#email").fill("demo@example.net");
  await page.locator("#password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByRole("heading", { name: "Your recovery phrase" }).waitFor();
  await captures("recovery");
  assert.ok(await page.locator(".recovery-actions .icon").count() >= 2, "recovery action icons missing");
  const errorContext = await browser.newContext();
  const errorPage = await errorContext.newPage();
  await errorPage.goto(`http://127.0.0.1:${port}/index.html#/login`);
  await errorPage.locator("#email").fill("demo@example.net");
  await errorPage.locator("#password").fill("fail-password");
  await errorPage.getByRole("button", { name: "Sign in" }).click();
  await errorPage.locator("#toast-region").getByText("Email or password is incorrect.").waitFor();
  assert.equal(await errorPage.locator("#toast-region").getByText("Email or password is incorrect.").count(), 1, "form error duplicated toast");
  assert.equal(await errorPage.locator("#auth .form-error").textContent(), "", "inline error duplicated toast");

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

  await page.evaluate(() => { location.hash = "#/orgs"; });
  await page.getByText("reviewer@example.net", { exact: true }).waitFor();
  assert.equal(await page.locator(".workspace-label strong").textContent(), "Demo workspace");
  assert.equal(await page.locator("#member-area [data-role]").count(), 3, "owners can edit roles only for approved non-owners");
  assert.equal(await page.locator('#member-area [data-revoke="revoked"]').count(), 0, "revoked members have no revoke action");
  await page.getByRole("button", { name: "Add by email" }).click();
  assert.deepEqual(await page.locator("#member-role option").evaluateAll(options => options.map(option => option.value)), ["admin", "reviewer", "respondent"]);
  await page.getByLabel("Member email").fill("new.member@example.net");
  await page.getByLabel("Role").last().selectOption("admin");
  await page.getByRole("button", { name: "Add member" }).click();
  await page.locator("#toast-region").getByText("Member added.").waitFor();
  assert.deepEqual(await page.evaluate(async () => (await import("/app.js")).addedMembers), [{ email: "new.member@example.net", role: "admin" }]);
  await captures("members");

  await page.evaluate(async () => { (await import("/app.js")).setMockRole("admin"); location.hash = "#/"; });
  await page.getByRole("heading", { name: "Overview" }).waitFor();
  await page.evaluate(() => { location.hash = "#/orgs"; });
  await page.getByText("reviewer@example.net", { exact: true }).waitFor();
  assert.equal(await page.locator("#member-area [data-role]").count(), 0, "admins cannot change member roles");
  assert.equal(await page.locator('#member-area [data-revoke="reviewer"],#member-area [data-revoke="respondent"]').count(), 2, "admins can manage non-admin reviewer and respondent members");
  assert.equal(await page.locator('#member-area [data-approve="owner"],#member-area [data-approve="admin"]').count(), 0, "admins cannot approve owner or admin targets");
  assert.equal(await page.locator('#member-area [data-revoke="revoked"]').count(), 0, "admins cannot revoke an already revoked member");
  await page.getByRole("button", { name: "Add by email" }).click();
  assert.deepEqual(await page.locator("#member-role option").evaluateAll(options => options.map(option => option.value)), ["reviewer", "respondent"], "admins cannot add other admins");
  let revokePrompt = "";
  page.once("dialog", async (dialog) => { revokePrompt = dialog.message(); await dialog.accept(); });
  await page.locator('[data-revoke="reviewer"]').click();
  await page.locator("#toast-region").getByText("Membership revoked.").waitFor();
  assert.equal(revokePrompt, "Revoke this membership?");

  await page.evaluate(() => { location.hash = "#/review/review/results"; });
  await page.getByText("This response could not be decrypted or validated.").waitFor();
  assert.equal(await page.locator(".status-badge").textContent(), "Closed", "review status badge renders as markup");
  assert.equal(await page.locator(".workspace-label strong").textContent(), "Other workspace", "workspace label follows review organization");
  assert.equal(await page.locator(".page-head .subtitle").evaluate(node => node.textContent.includes("<span")), false, "review status markup is not escaped as text");
  assert.notEqual(await page.locator(".status-badge").evaluate(node => getComputedStyle(node).color), await page.locator(".status-badge").evaluate(node => getComputedStyle(node).backgroundColor), "closed badge text contrasts with fill");
  await page.getByRole("button", { name: "Share" }).click();
  await page.locator("#toast-region").getByText("Response link copied.").waitFor();
  assert.match(await page.evaluate(() => navigator.clipboard.readText()), /#\/respond\/review$/);
  await captures("results");
  await page.evaluate(() => { location.hash = "#/review/new/edit"; });
  await page.getByRole("heading", { name: "Start a new review" }).waitFor();
  await page.getByLabel("Review title").fill("New journey review");
  await page.getByRole("button", { name: "Create draft" }).click();
  await page.getByRole("heading", { name: "Draft review" }).waitFor();
  await page.getByRole("button", { name: "Add question" }).click();
  await page.locator('[name="qtext"]').last().fill("What would help?");
  await page.getByRole("button", { name: "Preview" }).click();
  await page.getByText("What would help?", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Save draft" }).click();
  await page.locator("#toast-region").getByText("Review draft saved.").waitFor();
  await page.getByRole("button", { name: "Publish review" }).click();
  await page.locator("#toast-region").getByText("Review published.").waitFor();
  await page.evaluate(() => { location.hash = "#/respond/review"; });
  await page.getByRole("heading", { name: "Demo review" }).waitFor();
  await page.getByLabel("What should change?").fill("Clearer guidance");
  await page.getByRole("button", { name: "Send response" }).click();
  await page.getByText("Response accepted.").waitFor();
  await page.getByRole("button", { name: "Copy receipt" }).waitFor();
  assert.match(await page.locator(".receipt-data").textContent(), /mock-signed-receipt/);
  await page.keyboard.press("Tab");
  const focused = await page.evaluate(() => document.activeElement.matches(":focus-visible") && getComputedStyle(document.activeElement).outlineStyle !== "none" && getComputedStyle(document.activeElement).outlineWidth !== "0px");
  assert.equal(focused, true, "keyboard focus indicator missing on receipt action");
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
      assert.equal(theme.background, colorScheme === "dark" ? "#141318" : "#f4f7f9", `${colorScheme} theme missing at ${viewport.width}px`);
      if (colorScheme === "dark") assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), "rgb(20, 19, 24)", "dark theme background must use charcoal");
      iconFilters[colorScheme] = theme.iconFilter;
      const palette = await page.evaluate(() => ({
        accent: getComputedStyle(document.documentElement).getPropertyValue("--accent-icon-filter").trim(),
        generic: getComputedStyle(document.documentElement).getPropertyValue("--icon-filter").trim(),
        source: getComputedStyle(document.querySelector(".source-link .icon")).filter,
        navigation: getComputedStyle(document.querySelector(".nav .icon")).filter,
      }));
      assert.equal(palette.generic, palette.accent, `${colorScheme} generic icon token is stale`);
      assert.equal(palette.source, palette.navigation, `${colorScheme} accent link icons mismatch`);
      assert.equal(theme.overflow, false, `horizontal overflow at ${viewport.width}px`);
      assert.equal(theme.iconFailures, 0, `broken Lucide icon at ${viewport.width}px`);
      await page.screenshot({ path: join(artifactDir, `anonce-${viewport.width}-${colorScheme}.png`), fullPage: true });
    }
    assert.notEqual(iconFilters.dark, iconFilters.light, `icon filter did not change for dark mode at ${viewport.width}px`);
  }

  const recoveryPage = await context.newPage();
  await recoveryPage.goto(`http://127.0.0.1:${port}/index.html#/recover`);
  await recoveryPage.locator("#email").fill("demo@example.net");
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
  assert.ok(await recoveryPage.locator("#new-phrase .recovery-actions .icon").count() >= 2, "rotated recovery action icons missing");
  await verifyRecoveryTools(recoveryPage, expectedPhrase);
  const rotateButton = recoveryPage.getByRole("button", { name: "Rotate recovery phrase" });
  await rotateButton.click();
  await recoveryPage.locator("#new-phrase .word").first().waitFor();
  assert.ok(await rotateButton.locator(".icon").count(), "icon disappeared after submit busy-state restore");
  console.log("UI check passed: auth, registration/recovery, org membership and confirm dialog, review create/edit/preview/publish/results, submission/receipt, account rotation, notifications, focus, theme and responsive checks.");
} finally {
  await browser?.close();
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
}
