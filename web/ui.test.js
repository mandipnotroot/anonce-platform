// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./ui.js", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const helperSource = source.slice(source.indexOf("function recoveryPhrasePanel"), source.indexOf("async function load()"));
const toastSource = source.slice(source.indexOf("function toast("), source.indexOf("async function copyText("));

function harness({ clipboard } = {}) {
  const phraseWords = ["alpha", "bravo", "charlie"];
  const nodes = new Map();
  const clicks = [];
  const removed = [];
  const revoked = [];
  const notices = [];
  let blob;
  let nextURL = "blob:recovery-test";
  class FakeBlob {
    constructor(parts, options) {
      this.parts = parts;
      this.type = options.type;
      blob = this;
    }
  }
  const body = {
    appendChild(node) { node.isConnected = true; },
  };
  const document = {
    body,
    querySelector(selector) { return nodes.get(selector); },
    createElement(tag) {
      assert.equal(tag, "a");
      return {
        isConnected: false,
        click() { clicks.push({ href: this.href, download: this.download }); },
        remove() { this.isConnected = false; removed.push(true); },
      };
    },
  };
  for (const id of ["#test-copy", "#test-download", "#test-feedback"]) {
    nodes.set(id, { isConnected: true, textContent: "" });
  }
  const context = {
    phrase: phraseWords,
    toast(message, type) { notices.push({ message, type }); },
    document,
    navigator: clipboard === undefined ? {} : { clipboard },
    Blob: FakeBlob,
    URL: {
      createObjectURL(value) { assert.equal(value, blob); return nextURL; },
      revokeObjectURL(url) { revoked.push(url); },
    },
  };
  vm.runInNewContext(`${helperSource}\nbindRecoveryPhraseTools(phrase, "test");`, context);
  return { nodes, clicks, removed, revoked, notices, get blob() { return blob; } };
}

test("copy writes exact recovery phrase and confirms success", async () => {
  let copied;
  const h = harness({ clipboard: { async writeText(value) { copied = value; } } });
  await h.nodes.get("#test-copy").onclick();
  assert.equal(copied, "alpha bravo charlie");
  assert.deepEqual(h.notices, [{ message: "Phrase copied.", type: "success" }]);
});

test("clipboard rejection and missing clipboard show safe failure feedback", async () => {
  const rejected = harness({ clipboard: { async writeText() { throw new Error("denied"); } } });
  await rejected.nodes.get("#test-copy").onclick();
  assert.match(rejected.notices[0].message, /Could not copy recovery phrase/);
  const missing = harness();
  await missing.nodes.get("#test-copy").onclick();
  assert.match(missing.notices[0].message, /Could not copy recovery phrase/);
});

test("toast DOM updates live priority, text safely, and supports dismissal", () => {
  const nodes = new Map();
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.attributes = {}; this.removed = false; }
    setAttribute(key, value) { this.attributes[key] = value; }
    appendChild(child) { this.children.push(child); return child; }
    replaceChildren() { this.children = []; }
    remove() { this.removed = true; }
    set textContent(value) { this.text = value; }
    get textContent() { return (this.text || "") + this.children.map(child => child.textContent).join(""); }
  }
  const document = {
    body: { appendChild(node) { nodes.set(`#${node.id}`, node); } },
    createElement(tag) { return new Element(tag); },
    querySelector(selector) { return nodes.get(selector); },
  };
  const context = { document, setTimeout: () => 1, clearTimeout() {} };
  vm.runInNewContext(`${toastSource}\ntoast("Copied.", "success"); toast("Request failed.");`, context);
  const region = nodes.get("#toast-region");
  assert.equal(region.attributes["aria-live"], "assertive");
  assert.equal(region.attributes.role, "alert");
  assert.equal(region.children.length, 1);
  assert.match(region.textContent, /Request failed\./);
  assert.doesNotMatch(region.textContent, /Copied\./);
  region.children[0].children[1].onclick();
  assert.equal(region.children[0].removed, true);
});

test("download contains exact text, uses expected filename, removes anchor, and revokes URL", () => {
  const h = harness();
  h.nodes.get("#test-download").onclick();
  assert.equal(h.blob.parts[0], "alpha bravo charlie\n");
  assert.equal(h.blob.type, "text/plain;charset=utf-8");
  assert.deepEqual(h.clicks, [{ href: "blob:recovery-test", download: "anonce-recovery-phrase.txt" }]);
  assert.equal(h.removed.length, 1);
  assert.deepEqual(h.revoked, ["blob:recovery-test"]);
});

test("registration and account rotation share recovery controls", () => {
  assert.match(source, /recoveryPhrasePanel\(words\)/);
  assert.match(source, /recoveryPhrasePanel\(phrase, "rotated-recovery"\)/);
  assert.match(source, /bindRecoveryPhraseTools\(phrase, "rotated-recovery"\)/);
  assert.match(source, /const result = await api\.recover\([\s\S]*?phrase = result\.recoveryWords;[\s\S]*?session = result\.session;[\s\S]*?renderAuth\("recover"\)/);
  assert.match(source, /This response could not be decrypted or validated\./);
});

test("response invitation routes use strict app parser and fail closed", () => {
  const routeSource = source.slice(source.indexOf("const routeHash"), source.indexOf("const go ="));
  const parser = source.slice(source.indexOf("function responseInvitation()"), source.indexOf("function authHref("));
  const api = { parseResponseInvitation(fragment) { if (fragment.includes("duplicate")) throw Error("invalid"); return { reviewId: "canonical", contentKey: new Uint8Array(32) }; } };
  const parse = vm.runInNewContext(`${routeSource}\n${parser}\nresponseInvitation`, { api, location: { hash: "#/respond/id?v=1&k=duplicate" } });
  assert.equal(parse().invalid, true);
  const valid = vm.runInNewContext(`${routeSource}\n${parser}\nresponseInvitation`, { api, location: { hash: "#/respond/id?v=1&k=canonical" } });
  assert.equal(valid().reviewId, "canonical");
  assert.match(source, /This invitation could not be read/);
  assert.match(source, /contentState === "locked"/);
  assert.match(source, /Encrypted review/);
  assert.match(source, /api\.getReview\(\{ reviewId: id, contentKey: invitation\.contentKey \}\)/);
  assert.match(source, /api\.prepareResponse\(\{ reviewId: id, contentKey: invitation\.contentKey, answers \}\)/);
});

test("auth continuation preserves full invitation fragment through refresh and auth switches", () => {
  assert.match(source, /returnRoute = route\[0\] === "respond" \? routeHash\(\)/);
  assert.match(source, /hashParams\.has\("next"\)[\s\S]*?returnRoute = hashParams\.get\("next"\)/);
  assert.match(source, /function authHref\(mode\)[\s\S]*?encodeURIComponent\(returnRoute\)/);
  assert.match(source, /go\(destination\);\s*load\(\);/);
});

test("same-hash auth continuation reloads route without waiting for hashchange", () => {
  const goSource = source.slice(source.indexOf("const go ="), source.indexOf("const say ="));
  let loads = 0;
  let hash = "#/respond/review?v=1&k=secret";
  const location = {
    get hash() { return hash; },
    set hash(value) { hash = value.startsWith("#") ? value : `#${value}`; },
  };
  const go = vm.runInNewContext(`${goSource}\ngo`, { location, load: () => { loads++; } });
  go("/respond/review?v=1&k=secret");
  assert.equal(loads, 1);
  assert.equal(location.hash, "#/respond/review?v=1&k=secret");
  go("/overview");
  assert.equal(location.hash, "#/overview");
  assert.equal(loads, 1);
});

test("creator share copies app-produced secret invitation URL", () => {
  assert.match(source, /api\.getInvitationURL\(\{ reviewId: id \}\)/);
  assert.match(source, /copyText\(await api\.getInvitationURL/);
  assert.doesNotMatch(source, /Anyone with this link can read the review title and questions/);
  assert.doesNotMatch(source, /does not grant response authorization or let its holder decrypt answers/);
  assert.doesNotMatch(source, /Browsers and link-sharing tools may retain fragments/);
});

test("review dashboard hides locked member metadata and aggregates creator-owned reviews only", () => {
  const dashboard = source.slice(source.indexOf("function renderHome()"), source.indexOf("async function loadMoreReviews("));
  const helpers = source.slice(source.indexOf("function countText("), source.indexOf("function renderPendingResponses("));
  const creator = { id: "creator", is_creator: true, status: "published", contentState: "unlocked", accepted_count: "4", issued_count: "7", title: "Creator review" };
  const member = { id: "member", is_creator: false, status: "published", contentState: "locked", title: "Secret title" };
  let rendered;
  const context = {
    reviews: [creator, member], reviewNext: null, pendingResponses: [], frame(markup) { rendered = markup; },
    head: () => "", renderPendingResponses: () => "", button: () => "", statusBadge: () => "Open",
    emptyCard: () => "", esc: String, encodeURIComponent, countText(value) { return String(value); },
    root: { querySelectorAll() { return []; } },
    document: { querySelectorAll() { return []; }, querySelector() { return null; } },
  };
  vm.runInNewContext(`${helpers}\n${dashboard}\nrenderHome()`, context);
  assert.match(rendered, /Your reviews/);
  assert.match(rendered, /4 accepted/);
  assert.match(rendered, /7 issued/);
  assert.doesNotMatch(rendered, /Secret title|Unavailable accepted|0 accepted/);
  assert.match(source, /return r\.is_creator === true/);
  assert.doesNotMatch(source, /Anyone with this link/);
});

test("workspace navigation keeps complete accessible names and responsive app navigation", () => {
  assert.match(source, /aria-label="Account and recovery"[^>]*>[\s\S]*?<span class="nav-item">[\s\S]*?<span class="nav-label"><span>Account<\/span><span class="nav-detail">&amp; recovery<\/span><\/span>/);
  assert.match(source, /aria-current="page"/);
  assert.match(styles, /@media \(max-width:640px\)[\s\S]*?grid-template-columns: repeat\(4,minmax\(0,1fr\)\)/);
  assert.match(styles, /\.nav \{ display: grid; grid-template-columns: repeat\(4,minmax\(0,1fr\)\)/);
  assert.match(styles, /\.nav a\.active \{ box-shadow: inset 0 -2px 0 var\(--blue\) \}/);
  assert.match(source, /aria-label="Current workspace:/);
  assert.doesNotMatch(source, /<small>WORKSPACE<\/small>/);
  assert.match(styles, /\.site-header \{ position: sticky; top: 0/);
  assert.match(styles, /inset: auto 0 0/);
  assert.match(styles, /env\(safe-area-inset-bottom\)/);
});

test("accepted receipt shows verified success and time, with JSON behind disclosure", () => {
  const receiptSource = source.slice(source.indexOf("function receiptHTML("), source.indexOf("function icon("));
  const receipt = {
    version: 1,
    signature: "sig<&>",
    issuer: { keyId: "key-1", proof: "complete-proof" },
    accepted_at: "1794000000",
  };
  const escaped = JSON.stringify(receipt, null, 2)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
  const escapeSource = source.slice(source.indexOf("const esc ="), source.indexOf("const path ="));
  const timeSource = source.slice(source.indexOf("function formatReceiptTime("), source.indexOf("async function verifyReceiptLocally("));
  const { rendered } = vm.runInNewContext(`${escapeSource}\n${receiptSource}\n${timeSource}\n({ rendered: receiptHTML(receipt) })`, { receipt, BigInt, Date });
  assert.ok(rendered.includes(`<details class="receipt-details"><summary>Technical details (JSON)</summary><button type="button" class="button secondary" data-receipt-copy>Copy receipt data</button><pre class="receipt-data">${escaped}</pre></details>`));
  assert.match(rendered, /Response accepted/);
  assert.match(rendered, /Receipt signature verified/);
  assert.match(rendered, /<time>/);
  assert.match(rendered, /confirms acceptance, not what your response said/);
  assert.match(rendered, /aria-labelledby="receipt-heading"/);
  assert.match(rendered, /data-receipt-copy/);
  assert.match(rendered, /data-receipt-download/);
  assert.ok(rendered.indexOf("data-receipt-download") < rendered.indexOf("data-receipt-copy"));
  assert.doesNotMatch(rendered, /\[object Object\]/);
  assert.match(source, /box\.innerHTML = receiptHTML\(x\.receipt\);[\s\S]*?bindReceiptTools\(box, x\.receipt\)/);
  assert.match(source, /box\.innerHTML = receiptHTML\(result\.receipt\);[\s\S]*?bindReceiptTools\(box, result\.receipt\)/);
});

test("receipt tools copy JSON only as advanced detail and download a PNG asynchronously", async () => {
  const receipt = { signature: "full-signature", nested: { proof: "complete-proof" } };
  const copied = [];
  const notices = [];
  const blob = { type: "image/png" };
  const callbacks = {};
  const download = { isConnected: true, disabled: false, dataset: {}, set onclick(callback) { callbacks["[data-receipt-download]"] = callback; } };
  const copy = { set onclick(callback) { callbacks["[data-receipt-copy]"] = callback; } };
  const box = { querySelector(selector) { return selector.includes("download") ? download : copy; } };
  const sourceTools = source.slice(source.indexOf("function bindReceiptTools("), source.indexOf("function icon("));
  const context = {
    JSON,
    Blob,
    renderReceiptPNG: async ({ receipt: value }) => { assert.equal(value, receipt); return blob; },
    URL: { createObjectURL() { return "blob:receipt"; }, revokeObjectURL() {} },
    document: { body: { appendChild() {} }, createElement() { return { click() {}, remove() {}, set href(value) { this.url = value; }, set download(value) { this.filename = value; } }; } },
    copyText: async (text, label) => copied.push({ text, label }),
    setButtonText: (control, text) => { control.textContent = text; },
    toast: (message, type = "error") => notices.push({ message, type }),
  };
  vm.runInNewContext(`${sourceTools}\nbindReceiptTools(box, receipt);`, { ...context, box, receipt });
  await callbacks["[data-receipt-copy]"]();
  await callbacks["[data-receipt-download]"]();
  const expected = JSON.stringify(receipt, null, 2);
  assert.deepEqual(copied, [{ text: expected, label: "Receipt" }]);
  assert.equal(blob.type, "image/png");
  assert.deepEqual(notices, [{ message: "Receipt PNG download started.", type: "success" }]);
});

test("receipt details and controls support narrow layouts and keyboard access", () => {
  assert.match(styles, /\.receipt-data\s*\{[^}]*overflow-wrap:\s*anywhere/);
  assert.match(styles, /\.receipt-data\s*\{[^}]*max-width:\s*100%/);
  assert.match(styles, /\.hidden\s*\{\s*display:\s*none/);
  assert.match(styles, /\.receipt-notice\s*\{\s*margin-top:\s*18px/);
  assert.match(styles, /\.receipt-actions\s*\{[^}]*display:\s*flex[^}]*flex-wrap:\s*wrap/);
  assert.match(styles, /\.receipt-details summary\s*\{[^}]*min-height:\s*44px/);
  assert.match(source, /receipt-notice[\s\S]*?receipt-actions/);
  assert.match(source, /return to this signed-in browser later and check its status/);
  assert.match(source, /pending-state" role="status"/);
});

test("receipt verifier uses local API only and enforces UTF-8 byte bounds", async () => {
  const calls = [];
  const api = { async verifySavedReceipt(input) { calls.push(input); return { receipt: { v: 2 } }; } };
  const helper = source.slice(source.indexOf("async function verifyReceiptLocally("), source.indexOf("async function loadVerifierFile("));
  const context = { api, TextEncoder };
  const run = vm.runInNewContext(`(async () => { ${helper}; return verifyReceiptLocally; })()`, context);
  const verify = await run;
  assert.equal((await verify("receipt", "trust")).receipt.v, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ receiptText: "receipt", trustText: "trust" }]);
  await assert.rejects(verify("é".repeat(32769), "trust"), /64 KiB/);
  assert.equal(calls.length, 1);
  assert.match(source, /route\[0\] === "verify-receipt"\) \{\s*session = null;\s*return await renderReceiptVerifier\(\);/);
  assert.ok(source.indexOf('if (route[0] === "verify-receipt")') < source.indexOf("session = await api.getSession()"));
  assert.match(source, /verifyReceiptLocally\(inputText, selectedTrust\)/);
  assert.match(source, /verifySavedReceipt/);
  assert.match(source, /href="#\/verify-receipt"/);
  assert.match(source, /does not prove response contents, storage, anonymity, or trusted time/);
  assert.match(source, /does not match the receipt to your original response/);
  assert.doesNotMatch(source.slice(source.indexOf("function renderReceiptVerifier"), source.indexOf("function formatReceiptTime")), /fetch\s*\(|api\.(?!loadReceiptTrust|verifySavedReceipt)/);
});

test("receipt verifier is file-first, keeps JSON and trust choices disclosed, and stays in navigation", () => {
  const verifier = source.slice(source.indexOf("async function renderReceiptVerifier()"), source.indexOf("function formatReceiptTime("));
  assert.match(source, /href="#\/verify-receipt" aria-label="Verify receipt"/);
  assert.match(verifier, /Choose the receipt file you downloaded/);
  assert.match(verifier, /<details class="verifier-paste"><summary>Paste receipt JSON instead/);
  assert.match(verifier, /<details class="verify-trust"><summary>Choose which public signing keys to trust/);
  assert.match(verifier, /This configuration uses keys published by this site/);
  assert.match(verifier, /A receipt cannot provide or replace its own trusted key; never trust a replacement key supplied with a receipt/);
  assert.match(verifier, /independent check, get a configuration from a source you trust/);
  assert.match(verifier, /decodeReceiptPNG\(\{ file: selectedFile \}\)/);
  assert.match(verifier, /Receipt image loaded\. Ready to verify\./);
  assert.match(verifier, /Choose a receipt PNG or paste receipt JSON first\./);
  assert.match(verifier, /Receipt signature verified/);
  assert.match(verifier, /Receipt could not be verified/);
  assert.match(verifier, /does not match the receipt to your original response/);
});

test("receipt verifier DOM handlers report empty, successful, failed, and stale checks", async () => {
  const verifier = source.slice(source.indexOf("async function renderReceiptVerifier()"), source.indexOf("function formatReceiptTime("));
  const nodes = new Map();
  const make = (value = "") => ({ value, textContent: "", innerHTML: "", disabled: false, files: [], listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }, replaceChildren() { this.textContent = ""; this.innerHTML = ""; } });
  for (const id of ["#verify-receipt-text", "#verify-receipt-file", "#verify-trust-text", "#verify-trust-file", "#verify-result", "#verify-receipt", "#receipt-file-status", "#download-trust"]) nodes.set(id, make());
  const radios = [{ value: "current", checked: true, addEventListener(_type, fn) { this.onchange = fn; } }, { value: "import", checked: false, addEventListener(_type, fn) { this.onchange = fn; } }];
  const document = { querySelector: selector => selector.includes("trust-source") ? radios.find(radio => radio.checked) : nodes.get(selector), querySelectorAll: selector => selector.includes("trust-source") ? radios : [] };
  const pending = [];
  const api = { loadReceiptTrust: async () => ({ trust: "current" }), verifySavedReceipt: input => new Promise((resolve, reject) => pending.push({ input, resolve, reject })) };
  const context = { document, api, frame: markup => { context.markup = markup; }, head: () => "", esc: String, icon: () => "", JSON, toast() {}, URL: {}, Blob: class {}, formatReceiptTime: () => "accepted time", verifyReceiptLocally: (receiptText, trustText) => api.verifySavedReceipt({ receiptText, trustText }), path: () => ["verify-receipt"] };
  await vm.runInNewContext("(async () => { " + verifier + "; await renderReceiptVerifier(); })()", context);
  const input = nodes.get("#verify-receipt-text"), result = nodes.get("#verify-result"), button = nodes.get("#verify-receipt");
  await button.onclick();
  assert.match(result.textContent, /Choose a receipt PNG/);
  input.value = "valid";
  input.listeners.input();
  const success = button.onclick();
  pending.at(-1).resolve({ receipt: { accepted_at: "1" } });
  await success;
  assert.match(result.innerHTML, /Receipt signature verified/);
  input.value = "bad";
  input.listeners.input();
  const failure = button.onclick();
  pending.at(-1).reject(Error("invalid"));
  await failure;
  assert.match(result.innerHTML, /Receipt could not be verified/);
  input.value = "old";
  input.listeners.input();
  const stale = button.onclick();
  input.value = "new";
  input.listeners.input();
  pending.at(-1).resolve({ receipt: { accepted_at: "1" } });
  await stale;
  assert.equal(result.innerHTML, "");
  assert.equal(button.disabled, false);
});

test("pending receipt image decode disables verification and reports invalidation", async () => {
  const verifier = source.slice(source.indexOf("async function renderReceiptVerifier()"), source.indexOf("function formatReceiptTime("));
  const nodes = new Map();
  const make = (value = "") => ({ value, textContent: "", innerHTML: "", disabled: false, isConnected: true, files: [], listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }, replaceChildren() { this.textContent = ""; this.innerHTML = ""; } });
  for (const id of ["#verify-receipt-text", "#verify-receipt-file", "#verify-trust-text", "#verify-trust-file", "#verify-result", "#verify-receipt", "#receipt-file-status", "#download-trust"]) nodes.set(id, make());
  const radios = [{ value: "current", checked: true, addEventListener(_type, fn) { this.onchange = fn; } }, { value: "import", checked: false, addEventListener(_type, fn) { this.onchange = fn; } }];
  const document = { querySelector: selector => selector.includes("trust-source") ? radios.find(radio => radio.checked) : nodes.get(selector), querySelectorAll: selector => selector.includes("trust-source") ? radios : [] };
  const pending = [];
  const api = { loadReceiptTrust: async () => ({ trust: "current" }) };
  const context = { document, api, frame() {}, head: () => "", esc: String, icon: () => "", JSON, toast() {}, URL: {}, Blob: class {}, decodeReceiptPNG: () => new Promise((resolve, reject) => pending.push({ resolve, reject })), verifyReceiptLocally: async () => ({ receipt: { accepted_at: "1" } }), formatReceiptTime: () => "accepted time", path: () => ["verify-receipt"] };
  await vm.runInNewContext("(async () => { " + verifier + "; await renderReceiptVerifier(); })()", context);
  const file = nodes.get("#verify-receipt-file"), button = nodes.get("#verify-receipt"), status = nodes.get("#receipt-file-status"), text = nodes.get("#verify-receipt-text"), trust = nodes.get("#verify-trust-text");
  file.files = [{ size: 10 }];
  file.listeners.change();
  assert.equal(button.disabled, true);
  assert.match(status.textContent, /Reading receipt image/);
  await button.onclick();
  assert.equal(button.disabled, false);
  assert.match(status.textContent, /loading interrupted/i);
  pending[0].resolve("stale decoded receipt");
  await Promise.resolve();
  assert.equal(text.value, "");

  file.listeners.change();
  assert.equal(button.disabled, true);
  trust.listeners.input();
  assert.equal(button.disabled, false);
  assert.match(status.textContent, /loading interrupted/i);
  pending[1].resolve("stale decoded receipt");
  await Promise.resolve();
  assert.equal(text.value, "");
});

test("unavailable site trust leaves independent configuration editable and preserves image error", async () => {
  const verifier = source.slice(source.indexOf("async function renderReceiptVerifier()"), source.indexOf("function formatReceiptTime("));
  const nodes = new Map();
  const make = () => ({ value: "", textContent: "", innerHTML: "", disabled: false, files: [], listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }, replaceChildren() { this.textContent = ""; this.innerHTML = ""; } });
  for (const id of ["#verify-receipt-text", "#verify-receipt-file", "#verify-trust-text", "#verify-trust-file", "#verify-result", "#verify-receipt", "#receipt-file-status", "#download-trust"]) nodes.set(id, make());
  const radios = [{ value: "current", checked: true, disabled: false, addEventListener() {} }, { value: "import", checked: false, addEventListener() {} }];
  const document = { querySelector: selector => selector.includes("trust-source") ? radios.find(radio => radio.checked) : nodes.get(selector), querySelectorAll: selector => selector.includes("trust-source") ? radios : [] };
  const context = { document, api: { async loadReceiptTrust() { throw Error("offline"); } }, frame: markup => { context.markup = markup; }, head: () => "", esc: String, icon: () => "", JSON, toast() {}, URL: {}, Blob: class {}, formatReceiptTime: () => "accepted time", path: () => ["verify-receipt"] };
  await vm.runInNewContext("(async () => { " + verifier + "; await renderReceiptVerifier(); })()", context);
  assert.match(context.markup, /value="current" disabled/);
  assert.match(context.markup, /value="import" checked/);
  assert.doesNotMatch(context.markup, /id="verify-trust-text"[^>]*disabled/);
  assert.equal(nodes.get("#verify-trust-text").disabled, false);
  const status = nodes.get("#receipt-file-status"), result = nodes.get("#verify-result");
  status.textContent = "Could not read receipt image. Choose another PNG.";
  result.textContent = "This image does not contain a readable receipt QR code.";
  await nodes.get("#verify-receipt").onclick();
  assert.equal(result.textContent, "This image does not contain a readable receipt QR code.");
});

test("receipt times never render invalid dates for out-of-range values", () => {
  const helper = source.slice(source.indexOf("function formatReceiptTime("), source.indexOf("async function verifyReceiptLocally("));
  const format = vm.runInNewContext(`${helper}; formatReceiptTime`, { BigInt, Date });
  assert.equal(format("18446744073709551615"), "Unix time 18446744073709551615 (outside display range)");
  assert.equal(format("not-a-time"), "Acceptance time unavailable");
  assert.doesNotMatch(format("18446744073709551615"), /Invalid Date/);
});

test("stale receipt file reads cannot replace edits or surface old read errors", async () => {
  const helper = source.slice(source.indexOf("async function loadVerifierFile("), source.indexOf("function emptyCard("));
  const run = vm.runInNewContext(`(async () => { ${helper}; return loadVerifierFile; })()`, { });
  const load = await run;
  let generation = 0;
  const messages = [];
  const target = { value: "old" };
  const result = { set textContent(value) { messages.push(value); } };
  const clear = () => ++generation;
  const current = token => token === generation;
  let resolveRead;
  const pendingRead = load({ size: 3, text: () => new Promise(resolve => { resolveRead = resolve; }) }, target, result, clear, current);
  target.value = "new user edit";
  generation++;
  resolveRead("stale file text");
  await pendingRead;
  assert.equal(target.value, "new user edit");
  assert.deepEqual(messages, []);
  let rejectRead;
  const pendingError = load({ size: 3, text: () => new Promise((_resolve, reject) => { rejectRead = reject; }) }, target, result, clear, current);
  generation++;
  rejectRead(new Error("private file error"));
  await pendingError;
  assert.deepEqual(messages, []);
  await load({ size: 65537, text() { throw new Error("must not read oversized file"); } }, target, result, clear, current);
  assert.match(messages.at(-1), /exceeds 64 KiB/);
});

test("receipt file feedback handles cancel, empty files, failures, and stale edits", async () => {
  const helper = source.slice(source.indexOf("async function loadVerifierFile("), source.indexOf("function emptyCard("));
  const load = await vm.runInNewContext(`(async () => { ${helper}; return loadVerifierFile; })()`, {});
  let generation = 0;
  const target = { value: "old" };
  const result = { textContent: "" };
  const status = { textContent: "" };
  const clear = () => ++generation;
  const current = token => token === generation;
  await load(null, target, result, clear, current, status);
  assert.equal(status.textContent, "Choose your Anonce receipt PNG.");
  await load({ size: 0, async text() { return "  \n"; } }, target, result, clear, current, status);
  assert.match(status.textContent, /File is empty/);
  assert.match(result.textContent, /file is empty/i);
  await load({ size: 1, async text() { throw Error("read failed"); } }, target, result, clear, current, status);
  assert.match(status.textContent, /Could not read file/);
  let finish;
  const pending = load({ size: 3, text: () => new Promise(resolve => { finish = resolve; }) }, target, result, clear, current, status);
  target.value = "edited by user";
  status.textContent = "Using pasted receipt JSON.";
  generation++;
  finish("stale receipt");
  await pending;
  assert.equal(target.value, "edited by user");
  assert.equal(status.textContent, "Using pasted receipt JSON.");
});

test("shared spacing tokens drive cards, forms, fields, and responsive layouts", () => {
  for (const token of ["--space-2", "--space-3", "--space-4", "--space-6"]) {
    assert.match(styles, new RegExp(`\\bvar\\(${token}\\)`), `${token} must be used`);
  }
  assert.match(styles, /\.card \{\s*padding:\s*var\(--space-6\)/);
  assert.match(styles, /\.field\s*\{[^}]*gap:\s*var\(--space-2\)/);
  assert.match(styles, /\.card\s*\{\s*padding:\s*var\(--space-4\)/);
  assert.match(styles, /\.form-card,.auth-card\s*\{\s*padding:\s*var\(--space-4\)/);
  assert.match(styles, /--radius-control:\s*8px/);
  assert.match(styles, /--radius-card:\s*12px/);
});

test("browser theme metadata follows light and dark system preference", () => {
  assert.match(html, /theme-color" content="#f4f7f9" media="\(prefers-color-scheme: light\)"/);
  assert.match(html, /theme-color" content="#141318" media="\(prefers-color-scheme: dark\)"/);
});

test("successful mutations report success without duplicating password inline feedback", () => {
  for (const message of ["Organization created.", "Invitation created.", "Member approved.", "Membership revoked.", "Password updated.", "Recovery phrase replaced. Save your new phrase.", "Review draft created.", "Review published.", "Review closed.", "Review draft saved.", "Receipt PNG download started.", "Recovery phrase download started."]) {
    assert.ok(source.includes(`toast("${message}", "success")`), `missing success feedback: ${message}`);
  }
  assert.match(source, /catch \(error\) \{\s*toast\(say\(error\)\);\s*button\.disabled = false;/);
  assert.match(source, /document\.querySelector\("#password \.form-error"\)\.textContent = ""/);
  assert.doesNotMatch(source, /#password \.form-error"\)\.textContent\s*=\s*"Password updated/);
});

test("security copy stays concise and keeps network-correlation limit", () => {
  assert.match(source, /Your response is submitted without account credentials/);
  assert.match(source, /cannot prevent network or timing correlation/);
  assert.match(source, /Anyone with this phrase may recover your account/);
  assert.match(source, /Replacing it disables your old phrase/);
  assert.doesNotMatch(source, /Create a replacement phrase\. Your old recovery phrase will no longer work/);
});

test("shared responsive rules live with components rather than appended overrides", () => {
  assert.match(styles, /\.card \{\s*padding: var\(--space-6\)/);
  assert.match(styles, /\.simple-table \{ min-width: 620px \}/);
  assert.match(styles, /\.review-row \{[^}]*flex-wrap: wrap/);
  assert.match(styles, /@media \(max-width:640px\)[\s\S]*?\.stat:last-child:nth-child\(odd\)/);
  assert.doesNotMatch(styles, /Shared rhythm and resilient layouts/);
});

test("organization rows group role and status while preserving Open action target", () => {
  assert.match(source, /class="review-row org-row"[\s\S]*?class="review-info org-info"[\s\S]*?class="org-meta"[\s\S]*?class="org-role"[\s\S]*?\$\{statusBadge\(o\.status \|\| "active"\)\}[\s\S]*?class="button secondary org-open" data-org="\$\{esc\(o\.id\)\}"/);
  assert.match(styles, /\.org-row \.org-info strong \{[^}]*font-size: 15px/);
  assert.match(styles, /\.org-row \+ \.org-row \{[^}]*border-top: 1px solid var\(--line\)/);
  assert.doesNotMatch(styles, /\.org-meta \.status-positive \.icon/);
  assert.match(styles, /\.org-open \{[^}]*min-height: 44px/);
  assert.match(styles, /\.org-row > \.org-open \{ grid-column: 1 \/ -1; width: 100%; margin-inline-start: 0; \}/);
  assert.match(styles, /\.org-list \.status-positive \.icon \{ filter: var\(--accent-icon-filter\); \}/);
  assert.match(styles, /\.org-list\.card \{ padding: var\(--space-2\); \}/);
  assert.match(styles, /\.review-row\.org-row \{ padding: var\(--space-3\); \}/);
});

test("JSON and CSV exports confirm that browser download started", async () => {
  const handlers = new Map();
  const notices = [];
  const clicks = [];
  let urlNumber = 0;
  const context = {
    api: { async exportResponses({ format }) { return { blob: { format }, filename: `responses.${format}` }; } },
    document: {
      querySelector(selector) { return { addEventListener(_type, handler) { handlers.set(selector, handler); } }; },
      createElement() { return { click() { clicks.push(this.download); } }; },
    },
    URL: { createObjectURL() { return `blob:${++urlNumber}`; }, revokeObjectURL() {} },
    toast: (message, type = "error") => notices.push({ message, type }),
    say: String,
  };
  const exportsSource = source.slice(source.indexOf("function bindResponseExports("), source.indexOf("function renderResponseResults("));
  vm.runInNewContext(`${exportsSource}\nbindResponseExports("review-1");`, context);
  await handlers.get("#export-json")();
  await handlers.get("#export-csv")();
  assert.deepEqual(clicks, ["responses.json", "responses.csv"]);
  assert.deepEqual(notices, [
    { message: "JSON export download started.", type: "success" },
    { message: "CSV export download started.", type: "success" },
  ]);
});

test("logout reports success or failure and restores button after failure", async () => {
  const button = { disabled: false };
  const notices = [];
  const navigations = [];
  let logoutFails = false;
  const context = {
    api: { async logout() { if (logoutFails) throw new Error("Logout failed."); } },
    document: { querySelector() { return button; } },
    session: { account_id: "acct" },
    go: (route) => navigations.push(route),
    toast: (message, type = "error") => notices.push({ message, type }),
    say: (error) => error.message,
  };
  const handler = source.match(/document\.querySelector\("#logout"\)\.onclick = async \(\) => \{([\s\S]*?)\n  \};/);
  assert.ok(handler, "logout handler must remain testable");
  const logout = vm.runInNewContext(`(async () => {${handler[1]}\n})`, context);
  logoutFails = true;
  await logout();
  assert.equal(button.disabled, false);
  assert.deepEqual(notices[0], { message: "Logout failed.", type: "error" });
  assert.equal(context.session.account_id, "acct");
  assert.deepEqual(navigations, []);
  logoutFails = false;
  await logout();
  assert.equal(button.disabled, true);
  assert.equal(context.session, null);
  assert.deepEqual(navigations, ["/login"]);
  assert.deepEqual(notices[1], { message: "Signed out.", type: "success" });
});
