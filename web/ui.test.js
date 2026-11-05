// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./ui.js", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
const helperSource = source.slice(source.indexOf("function recoveryPhrasePanel"), source.indexOf("async function load()"));

function harness({ clipboard } = {}) {
  const phraseWords = ["alpha", "bravo", "charlie"];
  const nodes = new Map();
  const clicks = [];
  const removed = [];
  const revoked = [];
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
    document,
    navigator: clipboard === undefined ? {} : { clipboard },
    Blob: FakeBlob,
    URL: {
      createObjectURL(value) { assert.equal(value, blob); return nextURL; },
      revokeObjectURL(url) { revoked.push(url); },
    },
  };
  vm.runInNewContext(`${helperSource}\nbindRecoveryPhraseTools(phrase, "test");`, context);
  return { nodes, clicks, removed, revoked, get blob() { return blob; } };
}

test("copy writes exact recovery phrase and confirms success", async () => {
  let copied;
  const h = harness({ clipboard: { async writeText(value) { copied = value; } } });
  await h.nodes.get("#test-copy").onclick();
  assert.equal(copied, "alpha bravo charlie");
  assert.equal(h.nodes.get("#test-feedback").textContent, "Phrase copied.");
});

test("clipboard rejection and missing clipboard show safe failure feedback", async () => {
  const rejected = harness({ clipboard: { async writeText() { throw new Error("denied"); } } });
  await rejected.nodes.get("#test-copy").onclick();
  assert.equal(rejected.nodes.get("#test-feedback").textContent, "Copy failed. Select and copy the words above.");
  const missing = harness();
  await missing.nodes.get("#test-copy").onclick();
  assert.equal(missing.nodes.get("#test-feedback").textContent, "Copy failed. Select and copy the words above.");
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
