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

test("workspace navigation keeps complete accessible names and compact mobile labels", () => {
  assert.match(source, /aria-label="Account and recovery"[^>]*>[\s\S]*?<span class="nav-item">[\s\S]*?<span class="nav-label"><span>Account<\/span><span class="nav-detail">&amp; recovery<\/span><\/span>/);
  assert.match(source, /aria-current="page"/);
  assert.match(styles, /@media \(max-width:640px\)[\s\S]*?grid-template-columns: repeat\(3,minmax\(0,1fr\)\)/);
  assert.match(styles, /\.nav a\.active \{ box-shadow: inset 0 -2px 0 var\(--blue\) \}/);
});

test("accepted signed receipts render complete escaped JSON for initial and retry acceptance", () => {
  const receiptSource = source.slice(source.indexOf("function receiptHTML("), source.indexOf("function icon("));
  const receipt = {
    version: 1,
    signature: "sig<&>",
    issuer: { keyId: "key-1", proof: "complete-proof" },
  };
  const escaped = JSON.stringify(receipt, null, 2)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
  const escapeSource = source.slice(source.indexOf("const esc ="), source.indexOf("const path ="));
  const { rendered } = vm.runInNewContext(`${escapeSource}\n${receiptSource}\n({ rendered: receiptHTML(receipt) })`, { receipt });
  assert.ok(rendered.includes(`<pre class="receipt-data">${escaped}</pre>`));
  assert.match(rendered, /data-receipt-copy/);
  assert.match(rendered, /data-receipt-download/);
  assert.doesNotMatch(rendered, /\[object Object\]/);
  assert.match(source, /box\.innerHTML = receiptHTML\(x\.receipt\);[\s\S]*?bindReceiptTools\(box, x\.receipt\)/);
  assert.match(source, /box\.innerHTML = receiptHTML\(result\.receipt\);[\s\S]*?bindReceiptTools\(box, result\.receipt\)/);
});

test("receipt tools copy and download complete formatted JSON", async () => {
  const receipt = { signature: "full-signature", nested: { proof: "complete-proof" } };
  const copied = [];
  const notices = [];
  let blob;
  const callbacks = {};
  const box = { querySelector(selector) { return { set onclick(callback) { callbacks[selector] = callback; } }; } };
  const sourceTools = source.slice(source.indexOf("function bindReceiptTools("), source.indexOf("function icon("));
  const context = {
    JSON,
    Blob: class { constructor(parts, options) { this.parts = parts; this.type = options.type; blob = this; } },
    URL: { createObjectURL() { return "blob:receipt"; }, revokeObjectURL() {} },
    document: { body: { appendChild() {} }, createElement() { return { click() {}, remove() {} }; } },
    copyText: async (text, label) => copied.push({ text, label }),
    toast: (message, type = "error") => notices.push({ message, type }),
  };
  vm.runInNewContext(`${sourceTools}\nbindReceiptTools(box, receipt);`, { ...context, box, receipt });
  await callbacks["[data-receipt-copy]"]();
  callbacks["[data-receipt-download]"]();
  const expected = JSON.stringify(receipt, null, 2);
  assert.deepEqual(copied, [{ text: expected, label: "Receipt" }]);
  assert.equal(blob.parts[0], `${expected}\n`);
  assert.equal(blob.type, "application/json;charset=utf-8");
  assert.deepEqual(notices, [{ message: "Receipt download started.", type: "success" }]);
});

test("receipt JSON wraps within narrow layouts", () => {
  assert.match(styles, /\.receipt-data\s*\{[^}]*overflow-wrap:\s*anywhere/);
  assert.match(styles, /\.receipt-data\s*\{[^}]*max-width:\s*100%/);
  assert.match(styles, /\.hidden\s*\{\s*display:\s*none/);
  assert.match(styles, /\.receipt-notice\s*\{\s*margin-top:\s*18px/);
  assert.match(styles, /\.receipt-actions\s*\{[^}]*display:\s*flex[^}]*gap:\s*10px/);
  assert.match(source, /receipt-notice[\s\S]*?receipt-actions/);
});

test("shared spacing tokens drive cards, forms, fields, and responsive layouts", () => {
  for (const token of ["--space-2", "--space-3", "--space-4", "--space-6"]) {
    assert.match(styles, new RegExp(`\\bvar\\(${token}\\)`), `${token} must be used`);
  }
  assert.match(styles, /\.card \{\s*padding:\s*var\(--space-6\)/);
  assert.match(styles, /\.field\s*\{[^}]*gap:\s*var\(--space-2\)/);
  assert.match(styles, /\.card\s*\{\s*padding:\s*var\(--space-4\)/);
  assert.match(styles, /\.form-card,.auth-card\s*\{\s*padding:\s*var\(--space-3\)/);
  assert.match(styles, /--radius-control:\s*8px/);
  assert.match(styles, /--radius-card:\s*12px/);
});

test("browser theme metadata follows light and dark system preference", () => {
  assert.match(html, /theme-color" content="#f4f7f9" media="\(prefers-color-scheme: light\)"/);
  assert.match(html, /theme-color" content="#141a1f" media="\(prefers-color-scheme: dark\)"/);
});

test("successful mutations report success without duplicating password inline feedback", () => {
  for (const message of ["Organization created.", "Invitation created.", "Member approved.", "Membership revoked.", "Password updated.", "Recovery phrase replaced. Save your new phrase.", "Review draft created.", "Review published.", "Review closed.", "Review draft saved.", "Receipt download started.", "Recovery phrase download started."]) {
    assert.ok(source.includes(`toast("${message}", "success")`), `missing success feedback: ${message}`);
  }
  assert.match(source, /catch \(error\) \{\s*toast\(say\(error\)\);\s*button\.disabled = false;/);
  assert.match(source, /document\.querySelector\("#password \.form-error"\)\.textContent = ""/);
  assert.doesNotMatch(source, /#password \.form-error"\)\.textContent\s*=\s*"Password updated/);
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
