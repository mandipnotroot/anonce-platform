// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./ui.js", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const helperSource = source.slice(
  source.indexOf("function recoveryPhrasePanel"),
  source.indexOf("async function load()"),
);
const toastSource = source.slice(
  source.indexOf("function toast("),
  source.indexOf("async function copyText("),
);

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
    appendChild(node) {
      node.isConnected = true;
    },
  };
  const document = {
    body,
    querySelector(selector) {
      return nodes.get(selector);
    },
    createElement(tag) {
      assert.equal(tag, "a");
      return {
        isConnected: false,
        click() {
          clicks.push({ href: this.href, download: this.download });
        },
        remove() {
          this.isConnected = false;
          removed.push(true);
        },
      };
    },
  };
  for (const id of ["#test-copy", "#test-download", "#test-feedback"]) {
    nodes.set(id, { isConnected: true, textContent: "" });
  }
  const context = {
    phrase: phraseWords,
    toast(message, type) {
      notices.push({ message, type });
    },
    document,
    navigator: clipboard === undefined ? {} : { clipboard },
    Blob: FakeBlob,
    URL: {
      createObjectURL(value) {
        assert.equal(value, blob);
        return nextURL;
      },
      revokeObjectURL(url) {
        revoked.push(url);
      },
    },
  };
  vm.runInNewContext(
    `${helperSource}\nbindRecoveryPhraseTools(phrase, "test");`,
    context,
  );
  return {
    nodes,
    clicks,
    removed,
    revoked,
    notices,
    get blob() {
      return blob;
    },
  };
}

test("copy writes exact recovery phrase and confirms success", async () => {
  let copied;
  const h = harness({
    clipboard: {
      async writeText(value) {
        copied = value;
      },
    },
  });
  await h.nodes.get("#test-copy").onclick();
  assert.equal(copied, "alpha bravo charlie");
  assert.deepEqual(h.notices, [{ message: "Phrase copied.", type: "success" }]);
});

test("clipboard rejection and missing clipboard show safe failure feedback", async () => {
  const rejected = harness({
    clipboard: {
      async writeText() {
        throw new Error("denied");
      },
    },
  });
  await rejected.nodes.get("#test-copy").onclick();
  assert.match(rejected.notices[0].message, /Could not copy recovery phrase/);
  const missing = harness();
  await missing.nodes.get("#test-copy").onclick();
  assert.match(missing.notices[0].message, /Could not copy recovery phrase/);
});

test("toast DOM updates live priority, text safely, and supports dismissal", () => {
  const nodes = new Map();
  class Element {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
      this.attributes = {};
      this.removed = false;
    }
    setAttribute(key, value) {
      this.attributes[key] = value;
    }
    appendChild(child) {
      this.children.push(child);
      return child;
    }
    replaceChildren() {
      this.children = [];
    }
    remove() {
      this.removed = true;
    }
    set textContent(value) {
      this.text = value;
    }
    get textContent() {
      return (
        (this.text || "") +
        this.children.map((child) => child.textContent).join("")
      );
    }
  }
  const document = {
    body: {
      appendChild(node) {
        nodes.set(`#${node.id}`, node);
      },
    },
    createElement(tag) {
      return new Element(tag);
    },
    querySelector(selector) {
      return nodes.get(selector);
    },
  };
  const context = { document, setTimeout: () => 1, clearTimeout() {} };
  vm.runInNewContext(
    `${toastSource}\ntoast("Copied.", "success"); toast("Request failed.");`,
    context,
  );
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
  assert.deepEqual(h.clicks, [
    { href: "blob:recovery-test", download: "anonce-recovery-phrase.txt" },
  ]);
  assert.equal(h.removed.length, 1);
  assert.deepEqual(h.revoked, ["blob:recovery-test"]);
});

test("registration and account rotation share recovery controls", () => {
  assert.match(source, /recoveryPhrasePanel\(words\)/);
  assert.match(source, /recoveryPhrasePanel\(phrase, "rotated-recovery"\)/);
  assert.match(source, /bindRecoveryPhraseTools\(phrase, "rotated-recovery"\)/);
  assert.match(
    source,
    /const result = await api\.recover\([\s\S]*?phrase = result\.recoveryWords;[\s\S]*?session = result\.session;[\s\S]*?renderAuth\("recover"\)/,
  );
  assert.match(source, /This response could not be decrypted or validated\./);
});

test("cancelled route change preserves page and unsaved phrase; unload warns", () => {
  const guardSource = source.slice(
    source.indexOf("let acknowledgedPhraseHash"),
    source.indexOf("const canCreateReviews"),
  );
  const listeners = {};
  let hash = "#/account";
  let prompted = 0;
  let loads = 0;
  const context = {
    phrase: ["new", "phrase"],
    location: {
      get hash() {
        return hash;
      },
    },
    history: {
      replaceState(_state, _title, value) {
        hash = value;
      },
    },
    window: {
      addEventListener(name, callback) {
        listeners[name] = callback;
      },
      confirm() {
        prompted++;
        return false;
      },
    },
    load() {
      loads++;
    },
  };
  vm.runInNewContext(`${guardSource}\n`, context);
  hash = "#/overview";
  listeners.hashchange();
  assert.equal(hash, "#/account");
  assert.equal(context.phrase.length, 2);
  assert.equal(prompted, 1);
  assert.equal(loads, 0);
  const event = {
    preventDefault() {
      this.prevented = true;
    },
  };
  listeners.beforeunload(event);
  assert.equal(event.prevented, true);
  assert.equal(event.returnValue, "");
  assert.equal(loads, 0);
});

test("confirmed route discard clears phrase and phrase-free unload stays quiet", () => {
  const guardSource = source.slice(
    source.indexOf("let acknowledgedPhraseHash"),
    source.indexOf("const canCreateReviews"),
  );
  const listeners = {};
  let hash = "#/account";
  let loads = 0;
  const context = {
    phrase: ["new", "phrase"],
    location: {
      get hash() {
        return hash;
      },
    },
    history: {
      replaceState(_state, _title, value) {
        hash = value;
      },
    },
    window: {
      addEventListener(name, callback) {
        listeners[name] = callback;
      },
      confirm() {
        return true;
      },
    },
    load() {
      loads++;
    },
  };
  vm.runInNewContext(`${guardSource}\n`, context);
  hash = "#/overview";
  listeners.hashchange();
  assert.equal(context.phrase, null);
  assert.equal(hash, "#/overview");
  assert.equal(loads, 1);
  const event = {
    preventDefault() {
      this.prevented = true;
    },
  };
  listeners.beforeunload(event);
  assert.equal(event.prevented, undefined);
});

test("rotation checks unsaved phrase before issuing credential mutation", () => {
  const rotation = source.slice(
    source.indexOf('bind("#rotate"'),
    source.indexOf('document.querySelector("#logout")'),
  );
  assert.match(
    rotation,
    /if \(phrase && !protectRecoveryPhrase\(\)\) return;[\s\S]*?api\.rotateRecovery/,
  );
  assert.match(
    rotation,
    /session = r\.session;[\s\S]*?phrase = r\.recoveryWords/,
  );
  assert.match(rotation, /current password/);
});

test("responses render review content and prepare answers by review ID", () => {
  assert.match(source, /async function renderRespond\(id, isCurrent\)/);
  assert.match(source, /contentState === "locked"/);
  assert.match(
    source,
    /api\.prepareResponse\(\{\s*reviewId: id,\s*answers,?\s*\}\)/,
  );
});

test("late respond review success and failure do not render after navigation, active load renders", async () => {
  assert.match(source, /renderRespond\(route\[1\], isCurrentLoad\)/);
  const renderSource = source.slice(
    source.indexOf("async function renderRespond("),
    source.indexOf("\nload();"),
  );
  const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => {
      resolve = yes;
      reject = no;
    });
    return { promise, resolve, reject };
  };
  async function attempt(outcome, current) {
    const frames = [],
      notices = [];
    const context = {
      api: { getReview: () => outcome.promise },
      frame: (...args) => frames.push(args),
      toast: (message) => notices.push(message),
      say: String,
      esc: (value) => String(value ?? ""),
      head: (...args) => args.join(" "),
      emptyCard: (...args) => args.join(" "),
      document: {
        querySelectorAll: () => [],
        querySelector: () => ({ addEventListener() {} }),
      },
      bind() {},
      renderButtonIcons() {},
      isCurrent: current,
    };
    vm.runInNewContext(`${renderSource}\nrenderRespond`, context);
    const rendering = context.renderRespond("review", current);
    return { rendering, frames, notices };
  }
  let active = true;
  const lateSuccess = deferred(),
    staleSuccess = await attempt(lateSuccess, () => active);
  // Change the route after the sensitive fetch begins, before it completes.
  active = false;
  lateSuccess.resolve({ title: "Private review", questions: [] });
  await staleSuccess.rendering;
  assert.deepEqual(staleSuccess.frames, []);

  active = true;
  const lateError = deferred(),
    staleError = await attempt(lateError, () => active);
  active = false;
  lateError.reject(new Error("late failure"));
  await staleError.rendering;
  assert.deepEqual(staleError.frames, []);
  assert.deepEqual(staleError.notices, []);

  const fresh = await attempt(
    { promise: Promise.resolve({ title: "Current", questions: [] }) },
    () => true,
  );
  await fresh.rendering;
  assert.equal(fresh.frames.length, 1);
  assert.match(fresh.frames[0][0], /Current/);
});

test("respond submit and retry completions respect route invalidation", async () => {
  const renderSource = source.slice(
    source.indexOf("async function renderRespond("),
    source.indexOf("\nload();"),
  );
  const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => {
      resolve = yes;
      reject = no;
    });
    return { promise, resolve, reject };
  };
  async function setup(api) {
    let active = true,
      submit;
    const notices = [],
      nodes = new Map();
    nodes.set("#respond", {
      addEventListener(_event, callback) {
        submit = callback;
      },
      classList: { add() {} },
    });
    nodes.set("#receipt", { innerHTML: "" });
    nodes.set("#retry", { disabled: false });
    nodes.set("#pending-state", { textContent: "" });
    const context = {
      api: {
        getReview: async () => ({ title: "Review", questions: [] }),
        ...api,
      },
      frame() {},
      toast: (message) => notices.push(message),
      say: String,
      esc: (value) => String(value ?? ""),
      head: (...args) => args.join(" "),
      emptyCard: (...args) => args.join(" "),
      document: {
        querySelectorAll: () => [],
        querySelector: (selector) => nodes.get(selector),
      },
      bind(_selector, callback) {
        submit = async (fd) => callback(fd);
      },
      renderButtonIcons() {},
      receiptHTML: () => "receipt",
    };
    vm.runInNewContext(`${renderSource}\nrenderRespond`, context);
    await context.renderRespond("review", () => active);
    return {
      nodes,
      notices,
      submit: (fd = { getAll: () => [], get: () => null }) => submit(fd),
      invalidate() {
        active = false;
      },
    };
  }

  const preparing = deferred();
  let submitCalls = 0;
  const duringPrepare = await setup({
    prepareResponse: () => preparing.promise,
    submitResponse: async () => {
      submitCalls++;
      return { status: "accepted" };
    },
  });
  const preparingRequest = duringPrepare.submit();
  duringPrepare.invalidate();
  preparing.resolve({ pendingId: "pending" });
  await preparingRequest;
  assert.equal(submitCalls, 0);
  assert.equal(duringPrepare.nodes.get("#receipt").innerHTML, "");

  for (const rejected of [false, true]) {
    const submission = deferred();
    let started;
    const submitStarted = new Promise((resolve) => {
      started = resolve;
    });
    const duringSubmit = await setup({
      prepareResponse: async () => ({ pendingId: "pending" }),
      submitResponse: () => {
        started();
        return submission.promise;
      },
    });
    const request = duringSubmit.submit();
    await submitStarted;
    duringSubmit.invalidate();
    rejected
      ? submission.reject(new Error("stale submit"))
      : submission.resolve({ status: "accepted", receipt: "secret" });
    await request;
    assert.equal(duringSubmit.nodes.get("#receipt").innerHTML, "");
    assert.deepEqual(duringSubmit.notices, []);
  }

  for (const rejected of [false, true]) {
    const lookup = deferred();
    const retry = await setup({
      prepareResponse: async () => ({ pendingId: "pending" }),
      submitResponse: async () => ({ status: "pending", pendingId: "pending" }),
      lookupReceipt: () => lookup.promise,
    });
    await retry.submit();
    const retryClick = retry.nodes.get("#retry").onclick;
    assert.equal(typeof retryClick, "function");
    const retryRequest = retryClick();
    retry.invalidate();
    rejected
      ? lookup.reject(new Error("stale lookup"))
      : lookup.resolve({ status: "accepted", receipt: "secret" });
    await retryRequest;
    assert.equal(
      retry.nodes.get("#receipt").innerHTML.includes("receipt"),
      false,
    );
    assert.equal(retry.nodes.get("#retry").disabled, true);
    assert.deepEqual(retry.notices, []);
  }

  const current = await setup({
    prepareResponse: async () => ({ pendingId: "pending" }),
    submitResponse: async () => ({ status: "accepted", receipt: "valid" }),
  });
  await current.submit();
  assert.equal(current.nodes.get("#receipt").innerHTML, "receipt");
});

test("response pagination and exports ignore stale success and failure", async () => {
  assert.doesNotMatch(source, /renderRespond\(id\)/);
  const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => {
      resolve = yes;
      reject = no;
    });
    return { promise, resolve, reject };
  };
  const paginationSource = source.slice(
    source.indexOf("const loadMoreResponses = async"),
    source.indexOf(
      '\n  document\n    .querySelector("#load-more-responses")',
      source.indexOf("const loadMoreResponses = async"),
    ),
  );
  async function runPagination(outcome, active) {
    let content = "",
      notice = "";
    const button = { disabled: false },
      panel = {
        set innerHTML(value) {
          content = value;
        },
        querySelector() {
          return null;
        },
      };
    const context = {
      api: { listResponses: () => outcome.promise },
      responseResult: { items: [], next: "cursor" },
      review: {},
      id: "review",
      isCurrent: () => active.value,
      document: { querySelector: () => panel },
      renderResponseResults: () => "private response results",
      bindResponseExports() {},
      setButtonText() {},
      toast: (message) => {
        notice = message;
      },
      say: String,
    };
    const loadMore = vm.runInNewContext(
      `${paginationSource}\nloadMoreResponses`,
      context,
    );
    const request = loadMore({ currentTarget: button });
    return {
      request,
      button,
      get content() {
        return content;
      },
      get notice() {
        return notice;
      },
    };
  }
  for (const rejected of [false, true]) {
    const wait = deferred(),
      active = { value: true };
    const result = await runPagination(wait, active);
    active.value = false;
    rejected
      ? wait.reject(new Error("stale page"))
      : wait.resolve({ items: [{ secret: true }], next: null });
    await result.request;
    assert.equal(result.content, "");
    assert.equal(result.notice, "");
    assert.equal(result.button.disabled, true);
  }
  const freshPage = await runPagination(
    { promise: Promise.resolve({ items: [], next: null }) },
    { value: true },
  );
  await freshPage.request;
  assert.equal(freshPage.content, "private response results");

  const exportSource = source.slice(
    source.indexOf("function bindResponseExports("),
    source.indexOf(
      "\nfunction renderResponseResults",
      source.indexOf("function bindResponseExports("),
    ),
  );
  async function runExport(outcome, active) {
    let click,
      downloads = 0,
      notices = 0;
    const context = {
      api: { exportResponses: () => outcome.promise },
      document: {
        querySelector: () => ({
          addEventListener(_name, callback) {
            click = callback;
          },
        }),
        createElement: () => ({
          click() {
            downloads++;
          },
        }),
      },
      URL: { createObjectURL: () => "blob:test", revokeObjectURL() {} },
      isCurrent: () => active.value,
      toast: () => {
        notices++;
      },
      say: String,
    };
    vm.runInNewContext(`${exportSource}\nbindResponseExports`, context)(
      "review",
      context.isCurrent,
    );
    const request = click();
    return {
      request,
      get downloads() {
        return downloads;
      },
      get notices() {
        return notices;
      },
    };
  }
  for (const rejected of [false, true]) {
    const wait = deferred(),
      active = { value: true };
    const result = await runExport(wait, active);
    active.value = false;
    rejected
      ? wait.reject(new Error("stale export"))
      : wait.resolve({ blob: {}, filename: "responses.csv" });
    await result.request;
    assert.equal(result.downloads, 0);
    assert.equal(result.notices, 0);
  }
  const freshExport = await runExport(
    { promise: Promise.resolve({ blob: {}, filename: "responses.csv" }) },
    { value: true },
  );
  await freshExport.request;
  assert.equal(freshExport.downloads, 1);
  assert.equal(freshExport.notices, 1);
});

test("response-results retry preserves the originating load guard", async () => {
  const binding = source.slice(
    source.indexOf('  document\n    .querySelector("#retry-responses")'),
    source.indexOf(
      ";\n",
      source.indexOf('  document\n    .querySelector("#retry-responses")'),
    ) + 1,
  );
  let click,
    active = true,
    resolveFetch,
    rendered = 0;
  const pending = new Promise((resolve) => {
    resolveFetch = resolve;
  });
  const context = {
    document: {
      querySelector: () => ({
        addEventListener(_event, callback) {
          click = callback;
        },
      }),
    },
    id: "review",
    isCurrent: () => active,
    async renderReview(_id, _tab, isCurrent) {
      await pending;
      if (isCurrent()) rendered++;
    },
  };
  vm.runInNewContext(binding, context);
  const retry = click();
  active = false;
  resolveFetch();
  await retry;
  assert.equal(rendered, 0);
});

test("response routes reject query parameters and extra path segments before auth or review fetch", () => {
  const helper = source.slice(
    source.indexOf("const hasUnsupportedResponseRoute"),
    source.indexOf("function authHref("),
  );
  const unsupported = vm.runInNewContext(
    `${helper}\nhasUnsupportedResponseRoute`,
    {},
  );
  assert.equal(unsupported(["respond", "review"], "/respond/review"), false);
  assert.equal(
    unsupported(["respond", "review"], "/respond/review?extra=value"),
    true,
  );
  assert.equal(
    unsupported(["respond", "review", "extra"], "/respond/review/extra"),
    true,
  );
  const guard = source.slice(
    source.indexOf("async function load()"),
    source.indexOf("const hashParams", source.indexOf("async function load()")),
  );
  assert.match(
    guard,
    /hasUnsupportedResponseRoute\(route, respondHash\)[\s\S]*?Unsupported response link/,
  );
  assert.doesNotMatch(guard, /getSession|returnRoute\s*=/);
});

test("auth continuation preserves full invitation fragment through refresh and auth switches", () => {
  assert.match(
    source,
    /returnRoute\s*=\s*route\[0\]\s*===\s*"respond"\s*\?\s*routeHash\(\)/,
  );
  assert.match(
    source,
    /hashParams\.has\("next"\)[\s\S]*?returnRoute = hashParams\.get\("next"\)/,
  );
  assert.match(
    source,
    /function authHref\(mode\)[\s\S]*?encodeURIComponent\(returnRoute\)/,
  );
  assert.match(source, /go\(destination\);\s*load\(\);/);
});

test("same-hash auth continuation reloads route without waiting for hashchange", () => {
  const goSource = source.slice(
    source.indexOf("const go ="),
    source.indexOf("const say ="),
  );
  let loads = 0;
  let hash = "#/respond/review?next=value";
  const location = {
    get hash() {
      return hash;
    },
    set hash(value) {
      hash = value.startsWith("#") ? value : `#${value}`;
    },
  };
  const go = vm.runInNewContext(`${goSource}\ngo`, {
    location,
    load: () => {
      loads++;
    },
  });
  go("/respond/review?next=value");
  assert.equal(loads, 1);
  assert.equal(location.hash, "#/respond/review?next=value");
  go("/overview");
  assert.equal(location.hash, "#/overview");
  assert.equal(loads, 1);
});

test("review dashboard hides locked member metadata and aggregates creator-owned reviews only", () => {
  const dashboard = source.slice(
    source.indexOf("function renderHome()"),
    source.indexOf("async function loadMoreReviews("),
  );
  const helpers = source.slice(
    source.indexOf("function countText("),
    source.indexOf("function renderPendingResponses("),
  );
  const creator = {
    id: "creator",
    is_creator: true,
    status: "published",
    contentState: "unlocked",
    accepted_count: "4",
    issued_count: "7",
    title: "Creator review",
  };
  const member = {
    id: "member",
    is_creator: false,
    status: "published",
    contentState: "locked",
    title: "Secret title",
  };
  let rendered;
  const context = {
    reviews: [creator, member],
    currentOrg: { role: "reviewer", status: "approved" },
    reviewNext: null,
    pendingResponses: [],
    frame(markup) {
      rendered = markup;
    },
    head: () => "",
    renderPendingResponses: () => "",
    button: () => "",
    statusBadge: () => "Open",
    emptyCard: () => "",
    esc: String,
    encodeURIComponent,
    countText(value) {
      return String(value);
    },
    canCreateReviews: () => true,
    root: {
      querySelectorAll() {
        return [];
      },
    },
    document: {
      querySelectorAll() {
        return [];
      },
      querySelector() {
        return null;
      },
    },
  };
  vm.runInNewContext(`${helpers}\n${dashboard}\nrenderHome()`, context);
  assert.match(rendered, /Your reviews/);
  assert.match(rendered, /4 accepted/);
  assert.match(rendered, /7 issued/);
  assert.doesNotMatch(rendered, /Secret title|Unavailable accepted|0 accepted/);
  assert.match(source, /return r\.is_creator === true/);
  assert.doesNotMatch(source, /Anyone with this link/);
});

test("dashboard exposes local completion and response action for creators and members", () => {
  assert.match(source, /Completed on this browser/);
  assert.match(source, /No completion recorded here/);
  assert.match(source, /completedOnThisBrowser === true/);
  assert.match(source, /const respond =\s*r\.status === "published"/);
  assert.match(source, /\$\{mine \? button\("Manage"[\s\S]*?\$\{respond\}/);
  assert.match(
    source,
    /small>\$\{statusBadge\(r\.status\)\}\$\{mine \? metrics : ""\} \$\{esc\(detail\)\}/,
  );
  assert.match(source, /Review content could not be verified/);
  assert.match(
    source,
    /currently approved organization members access to the questions/,
  );
  assert.match(source, /Members approved later need a future review/);
  assert.doesNotMatch(source, /pending globally|not submitted/i);
});

test("UI source contains no middle-dot separators", () => {
  assert.doesNotMatch(source, /·|&middot;|&#183;|\\u00b7|\\u\{b7\}/i);
});

test("presentational UI copy uses sentence case without uppercase styling", () => {
  assert.doesNotMatch(styles, /text-transform\s*:\s*uppercase/i);
  assert.doesNotMatch(
    styles,
    /\.(?:eyebrow|verifier-step|members-context)\s*\{[^}]*letter-spacing:\s*0\./s,
  );
  assert.doesNotMatch(source, />\s*(?:SAVE THIS ONCE|ANONYMOUS FEEDBACK)\s*</);
  assert.match(source, />Save this once</);
  assert.match(source, />Anonymous feedback</);
});

test("member and empty-state copy avoids explaining its own headings", () => {
  assert.doesNotMatch(
    source,
    /Manage who belongs to this organization|Organizations bring verified members into one trusted space|Your reviews will appear here once you create one/,
  );
  assert.match(
    source,
    /This adds an existing account immediately\. New members can register first or join with an invite link\./,
  );
  assert.match(source, /Members approved later need a future review/);
  assert.match(
    source,
    /function emptyCard\(t, d, act = ""\)[\s\S]*?d \? esc\(d\) : ""/,
  );
});

test("page and section headings have deliberate breathing room", () => {
  assert.match(
    styles,
    /\.page-head h1 \+ \.subtitle,[\s\S]*?margin-top: var\(--space-3\);/,
  );
  assert.match(
    styles,
    /\.section-row \{[\s\S]*?margin: var\(--space-10\) 0 var\(--space-4\);/,
  );
  assert.match(
    styles,
    /\.auth-card > h1 \+ p \{[\s\S]*?margin-bottom: var\(--space-5\);/,
  );
});

test("redundant page copy is removed while user descriptions and intent context remain", () => {
  for (const copy of [
    "Review activity and manage responses.",
    "Manage password and recovery settings.",
    "Submitted responses will appear here once they are available to review.",
    "Invites and membership approvals will appear here.",
    "Your thoughtful answer can help make things better.",
    "Sign in to manage your organization.",
    "Create an account to join feedback spaces.",
    "A thoughtful space for feedback",
  ]) {
    assert.ok(!source.includes(copy), `redundant copy remains: ${copy}`);
  }
  assert.match(
    source,
    /r\.description \? `<p class="subtitle">\$\{esc\(r\.description\)\}<\/p>`/,
  );
  assert.match(source, /Sign in to continue to this response form/);
  assert.match(source, /Sign in to accept your invitation/);
  assert.match(
    source,
    /Create an organization, then invite people who can review responses/,
  );
  assert.match(source, /Replacing it disables your old phrase/);
});

test("workspace navigation keeps complete accessible names and responsive app navigation", () => {
  assert.doesNotMatch(source, /class="route-context"/);
  assert.match(
    source,
    /aria-label="Account and recovery"[^>]*>[\s\S]*?<span class="nav-item">[\s\S]*?<span class="nav-label"><span>Account<\/span><span class="nav-detail">&amp; recovery<\/span><\/span>/,
  );
  assert.match(source, /aria-current="page"/);
  assert.match(
    styles,
    /@media\s*\(max-width:\s*640px\)[\s\S]*?grid-template-columns:\s*repeat\(4,\s*minmax\(0,\s*1fr\)\)/,
  );
  assert.match(
    styles,
    /\.nav\s*\{\s*display:\s*grid;\s*grid-template-columns:\s*repeat\(4,\s*minmax\(0,\s*1fr\)\)/,
  );
  assert.match(
    styles,
    /\.nav a\.active\s*\{\s*box-shadow:\s*inset 0 -2px 0 var\(--blue\);?\s*\}/,
  );
  assert.match(source, /aria-label="Current workspace:/);
  assert.doesNotMatch(source, /<small>WORKSPACE<\/small>/);
  assert.match(styles, /\.site-header\s*\{\s*position:\s*sticky;\s*top:\s*0/);
  assert.match(styles, /inset: auto 0 0/);
  assert.match(styles, /env\(safe-area-inset-bottom\)/);
});

test("shared spacing tokens drive cards, forms, fields, and responsive layouts", () => {
  for (const token of [
    "--space-2",
    "--space-3",
    "--space-4",
    "--space-5",
    "--space-6",
  ]) {
    assert.match(
      styles,
      new RegExp(`\\bvar\\(${token}\\)`),
      `${token} must be used`,
    );
  }
  assert.match(styles, /\.card \{\s*padding:\s*var\(--space-6\)/);
  assert.match(styles, /\.field\s*\{[^}]*gap:\s*var\(--space-2\)/);
  assert.match(styles, /\.card\s*\{\s*padding:\s*var\(--space-5\)/);
  assert.match(
    styles,
    /\.form-card\s*,\s*\.auth-card\s*\{\s*padding:\s*var\(--space-5\)/,
  );
  assert.match(styles, /--radius-control:\s*10px/);
  assert.match(styles, /--radius-card:\s*16px/);
});

test("skip navigation retains a visible focus cue on the main content", () => {
  assert.match(
    styles,
    /\.main:focus-visible\s*\{\s*box-shadow:\s*inset 0 3px var\(--blue\);?\s*\}/,
  );
});

test("required fields share a visible and screen-reader label marker", () => {
  assert.match(
    source,
    /root\.querySelectorAll\("\.field label"\)\.forEach\(\(label\) => \{[\s\S]*?label\.control\?\.required[\s\S]*?required-indicator[\s\S]*?accessibleMarker\.textContent = " required"/,
  );
  assert.match(styles, /\.required-indicator\s*\{\s*color:\s*var\(--danger\)/);
  assert.match(source, /At least 12 characters\./);
});

test("browser theme metadata follows light and dark system preference", () => {
  assert.match(
    html,
    /theme-color"\s+content="#f4f7f9"\s+media="\(prefers-color-scheme: light\)"/,
  );
  assert.match(
    html,
    /theme-color"\s+content="#141318"\s+media="\(prefers-color-scheme: dark\)"/,
  );
});

test("successful mutations report success without duplicating password inline feedback", () => {
  for (const message of [
    "Organization created.",
    "Invitation created.",
    "Member approved.",
    "Membership revoked.",
    "Password updated.",
    "Review created.",
    "Review published.",
    "Review closed.",
    "Review draft saved.",
    "Recovery phrase download started.",
  ]) {
    assert.ok(
      source.includes(`toast("${message}", "success")`),
      `missing success feedback: ${message}`,
    );
  }
  assert.match(
    source,
    /toast\(\s*r\.reauthenticationRequired\s*\?\s*"Recovery phrase replaced\.[^"]*"\s*:\s*"Recovery phrase replaced\. Save your new phrase\.",\s*"success",?\s*\)/,
  );
  assert.match(
    source,
    /catch \(error\) \{\s*toast\(say\(error\)\);\s*button\.disabled = false;/,
  );
  assert.match(
    source,
    /document\.querySelector\("#password \.form-error"\)\.textContent = ""/,
  );
  assert.doesNotMatch(
    source,
    /#password \.form-error"\)\.textContent\s*=\s*"Password updated/,
  );
});

test("security copy stays concise and keeps network-correlation limit", () => {
  assert.match(
    source,
    /Your response is submitted without account credentials/,
  );
  assert.match(source, /cannot prevent network or timing correlation/);
  assert.match(source, /Anyone with this phrase may recover your account/);
  assert.match(source, /Replacing it disables your old phrase/);
  assert.doesNotMatch(
    source,
    /Create a replacement phrase\. Your old recovery phrase will no longer work/,
  );
});

test("shared responsive rules live with components rather than appended overrides", () => {
  assert.match(styles, /\.card \{\s*padding: var\(--space-6\)/);
  assert.match(styles, /\.simple-table\s*\{\s*min-width:\s*620px;?\s*\}/);
  assert.match(styles, /\.review-row \{[^}]*flex-wrap: wrap/);
  assert.match(
    styles,
    /@media\s*\(max-width:\s*640px\)[\s\S]*?\.stat:last-child:nth-child\(odd\)/,
  );
  assert.doesNotMatch(styles, /Shared rhythm and resilient layouts/);
});

test("organization rows group role and status while preserving Open action target", () => {
  assert.match(
    source,
    /class="review-row org-row"[\s\S]*?class="review-info org-info"[\s\S]*?class="org-meta"[\s\S]*?class="org-role"[\s\S]*?\$\{statusBadge\(o\.status \|\| "active"\)\}[\s\S]*?class="button secondary org-open" data-org="\$\{esc\(o\.id\)\}"/,
  );
  assert.match(styles, /\.org-row \.org-info strong \{[^}]*font-size: 15px/);
  assert.match(
    styles,
    /\.org-row \+ \.org-row \{[^}]*border-top: 1px solid var\(--line\)/,
  );
  assert.doesNotMatch(styles, /\.org-meta \.status-positive \.icon/);
  assert.match(styles, /\.org-open \{[^}]*min-height: 44px/);
  assert.match(
    styles,
    /\.org-row\s*>\s*\.org-open\s*\{\s*grid-column:\s*1 \/ -1;\s*width:\s*100%;\s*margin-inline-start:\s*0;\s*\}/,
  );
  assert.match(
    styles,
    /\.org-list\s+\.status-positive\s+\.icon\s*\{\s*filter:\s*var\(--accent-icon-filter\);?\s*\}/,
  );
  assert.match(
    styles,
    /\.org-list\.card\s*\{\s*padding:\s*var\(--space-2\);?\s*\}/,
  );
  assert.match(
    styles,
    /\.review-row\.org-row\s*\{\s*padding:\s*var\(--space-3\);?\s*\}/,
  );
  assert.match(styles, /\[hidden\]\s*\{\s*display:\s*none !important/);
  assert.match(
    styles,
    /@media\s*\(max-width:\s*640px\)[\s\S]*?\.nav\s*\{[^}]*grid-template-columns:\s*repeat\(4,\s*minmax\(0,\s*1fr\)\)/,
  );
  assert.doesNotMatch(
    styles,
    /\.nav\s*\{[^}]*grid-template-columns:\s*repeat\(2,/,
  );
});

test("mobile membership rows retain field labels when reflowing into cards", () => {
  for (const label of ["Email", "Role", "Status", "Actions"]) {
    assert.ok(source.includes(`data-label="${label}"`));
  }
  assert.match(
    styles,
    /@media\s*\(max-width:\s*640px\)[\s\S]*?\.simple-table tr\s*\{\s*display:\s*grid/,
  );
  assert.match(
    styles,
    /\.simple-table td::before\s*\{\s*content:\s*attr\(data-label\)/,
  );
});

test("question removal uses the shared icon system and keeps an accessible name", () => {
  assert.match(
    source,
    /data-remove aria-label="Remove question">\$\{icon\("trash-2"\)\}/,
  );
});

test("organization permissions require approved selected membership and full scope", () => {
  assert.match(
    source,
    /const isApprovedOrganization = \(organization\) =>[\s\S]*?=== "approved"/,
  );
  assert.match(
    source,
    /const canCreateReviews = \(organization\) =>[\s\S]*?isApprovedOrganization/,
  );
  assert.match(
    source,
    /session\?\.scope !== "full" \|\| !canCreateReviews\(currentOrg\)/,
  );
  assert.match(source, /findApprovedOrganization\(orgs, currentOrg\?\.id\)/);
  assert.match(
    source,
    /const selected = orgs\.find\(\(o\) => o\.id === b\.dataset\.org\);[\s\S]*?if \(!isApprovedOrganization\(selected\)\) return;[\s\S]*?resetOrganizationView\(\)/,
  );
  assert.match(
    source,
    /const canManageMemberships = \(organization\) =>[\s\S]*?\["owner", "admin"\]/,
  );
  assert.match(
    source,
    /orgs\.find\(\(organization\) => organization\.id === reviewOrgId\)/,
  );
  assert.doesNotMatch(source, /Math\.max\([^)]*role|roleRank|highestRole/i);
});

test("selected membership controls role affordances and excludes pending or revoked organizations", () => {
  const helpers = source.slice(
    source.indexOf("const canCreateReviews"),
    source.indexOf("const esc ="),
  );
  const context = {
    reviews: ["old review"],
    pendingResponses: ["old response"],
    reviewNext: "cursor",
  };
  const run = vm.runInNewContext(
    `${helpers}; ({ canCreateReviews, findApprovedOrganization, resetOrganizationView, loadMembersIfAllowed })`,
    context,
  );
  const memberships = [
    { id: "team-a", role: "owner", status: "approved" },
    { id: "team-b", role: "respondent", status: "approved" },
    { id: "team-c", role: "admin", status: "pending" },
    { id: "team-d", role: "owner", status: "revoked" },
    { id: "team-e", role: "admin", status: "approved" },
  ];
  const respondentOrg = run.findApprovedOrganization(memberships, "team-b");
  assert.equal(respondentOrg.role, "respondent");
  assert.equal(run.canCreateReviews(respondentOrg), false);
  assert.equal(
    run.canCreateReviews(run.findApprovedOrganization(memberships, "team-a")),
    true,
  );
  assert.equal(run.findApprovedOrganization(memberships, "team-c"), null);
  assert.equal(run.findApprovedOrganization(memberships, "team-d"), null);
  let rosterRequests = 0;
  for (const organization of memberships) {
    run.loadMembersIfAllowed(organization, () => rosterRequests++);
  }
  assert.equal(rosterRequests, 2);
  run.resetOrganizationView();
  assert.deepEqual(Array.from(context.reviews), []);
  assert.deepEqual(Array.from(context.pendingResponses), []);
  assert.equal(context.reviewNext, null);
});

test("review response controls remain creator-only for reviewer memberships", () => {
  assert.match(source, /const canReviewResponses = canManage/);
  assert.doesNotMatch(
    source,
    /canManage \|\| currentOrg\?\.role === "reviewer"/,
  );
  assert.doesNotMatch(source, /Not authorized/);
  const helpers = source.slice(
    source.indexOf("const isApprovedOrganization"),
    source.indexOf("const isWorkspaceRouteAllowed"),
  );
  const canManage = vm.runInNewContext(`${helpers}; canManageMemberships`);
  assert.equal(canManage({ role: "reviewer", status: "approved" }), false);
  assert.equal(canManage({ role: "owner", status: "pending" }), false);
});

test("stale route loads cannot render, and recovery scope routes back to account", () => {
  const helpers = source.slice(
    source.indexOf("const isWorkspaceRouteAllowed"),
    source.indexOf("const esc ="),
  );
  const current = vm.runInNewContext(
    `${helpers}; ({ isCurrentLoad, isWorkspaceRouteAllowed, isPermissionError })`,
  );
  assert.equal(
    current.isCurrentLoad({
      requestId: 1,
      requestedHash: "/",
      currentRequestId: 2,
      currentHash: "/orgs",
    }),
    false,
  );
  assert.equal(
    current.isCurrentLoad({
      requestId: 2,
      requestedHash: "/orgs",
      currentRequestId: 2,
      currentHash: "/orgs",
    }),
    true,
  );
  assert.equal(
    current.isCurrentLoad({
      requestId: 2,
      requestedHash: "/",
      currentRequestId: 2,
      currentHash: "/",
      requestedOrgId: "team-a",
      currentOrgId: "team-b",
    }),
    false,
  );
  assert.equal(
    current.isWorkspaceRouteAllowed({ scope: "recovery" }, "orgs"),
    false,
  );
  assert.equal(
    current.isWorkspaceRouteAllowed({ scope: "recovery" }, "review"),
    false,
  );
  assert.equal(
    current.isWorkspaceRouteAllowed({ scope: "recovery" }, "respond"),
    false,
  );
  assert.equal(
    current.isWorkspaceRouteAllowed({ scope: "recovery" }, "account"),
    true,
  );
  assert.equal(current.isPermissionError({ status: 403 }), true);
  assert.equal(current.isPermissionError({ code: "NETWORK_ERROR" }), false);
  assert.match(source, /button\("Account & recovery", "account"\)/);
  assert.match(source, /Organization access pending/);
});

test("JSON and CSV exports confirm that browser download started", async () => {
  const handlers = new Map();
  const notices = [];
  const clicks = [];
  let urlNumber = 0;
  const context = {
    api: {
      async exportResponses({ format }) {
        return { blob: { format }, filename: `responses.${format}` };
      },
    },
    document: {
      querySelector(selector) {
        return {
          addEventListener(_type, handler) {
            handlers.set(selector, handler);
          },
        };
      },
      createElement() {
        return {
          click() {
            clicks.push(this.download);
          },
        };
      },
    },
    URL: {
      createObjectURL() {
        return `blob:${++urlNumber}`;
      },
      revokeObjectURL() {},
    },
    toast: (message, type = "error") => notices.push({ message, type }),
    say: String,
    isCurrent: () => true,
  };
  const exportsSource = source.slice(
    source.indexOf("function bindResponseExports("),
    source.indexOf("function renderResponseResults("),
  );
  vm.runInNewContext(
    `${exportsSource}\nbindResponseExports("review-1", isCurrent);`,
    context,
  );
  await handlers.get("#export-json")();
  await handlers.get("#export-csv")();
  assert.deepEqual(clicks, ["responses.json", "responses.csv"]);
  assert.deepEqual(notices, [
    { message: "JSON export download started.", type: "success" },
    { message: "CSV export download started.", type: "success" },
  ]);
});

for (const [label, item, expected] of [
  [
    "Unix seconds",
    { acceptedAt: "1735689600" },
    new Date(1735689600 * 1000).toLocaleString(),
  ],
  ["epoch", { acceptedAt: "0" }, new Date(0).toLocaleString()],
  [
    "out-of-display-range uint64",
    { acceptedAt: "18446744073709551615" },
    "Unix time 18446744073709551615 (outside display range)",
  ],
  [
    "malformed timestamp",
    { acceptedAt: "not-a-time" },
    "Acceptance time unavailable",
  ],
  ["absent timestamp", {}, ""],
]) {
  test(`response results render ${label}`, () => {
    const formatterSource = source.slice(
      source.indexOf("function formatReceiptTime("),
      source.indexOf("function emptyCard("),
    );
    const resultsSource = source.slice(
      source.indexOf("function renderResponseResults("),
      source.indexOf("function questionHTML("),
    );
    const render = vm.runInNewContext(
      `${formatterSource}\n${resultsSource}\nrenderResponseResults`,
      { esc: String, Date },
    );
    const html = render({ items: [item] }, "", { questions: [] });
    assert.equal(
      html.match(/<span class="help">([^<]*)<\/span>/)?.[1],
      expected,
    );
  });
}

test("logout reports success or failure and restores button after failure", async () => {
  const button = { disabled: false };
  const notices = [];
  const navigations = [];
  let logoutFails = false;
  let phraseGuardAllows = true;
  let logoutCalls = 0;
  const context = {
    api: {
      async logout() {
        logoutCalls++;
        if (logoutFails) throw new Error("Logout failed.");
      },
    },
    document: {
      querySelector() {
        return button;
      },
    },
    session: { account_id: "acct" },
    protectRecoveryPhrase: () => phraseGuardAllows,
    go: (route) => navigations.push(route),
    toast: (message, type = "error") => notices.push({ message, type }),
    say: (error) => error.message,
  };
  const handler = source.match(
    /document\.querySelector\("#logout"\)\.onclick = async \(\) => \{([\s\S]*?)\n  \};/,
  );
  assert.ok(handler, "logout handler must remain testable");
  const logout = vm.runInNewContext(`(async () => {${handler[1]}\n})`, context);
  phraseGuardAllows = false;
  await logout();
  assert.equal(logoutCalls, 0);
  assert.equal(button.disabled, false);
  phraseGuardAllows = true;
  logoutFails = true;
  await logout();
  assert.equal(button.disabled, false);
  assert.deepEqual(notices[0], { message: "Logout failed.", type: "error" });
  assert.equal(context.session.account_id, "acct");
  assert.deepEqual(navigations, []);
  assert.equal(logoutCalls, 1);
  logoutFails = false;
  await logout();
  assert.equal(button.disabled, true);
  assert.equal(context.session, null);
  assert.deepEqual(navigations, ["/login"]);
  assert.deepEqual(notices[1], { message: "Signed out.", type: "success" });
});
