// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./ui.js", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
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
