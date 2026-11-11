// SPDX-License-Identifier: AGPL-3.0-only
import * as api from "./app.js";
import { decodeReceiptPNG } from "./receipt-qr.bundle.js";
import { renderReceiptPNG } from "./receipt-card.js";

const root = document.querySelector("#app");
let session = null,
  orgs = [],
  reviews = [],
  currentOrg = null,
  phrase = null,
  returnRoute = null,
  review = null,
  pendingResponses = [],
  reviewNext = null,
  busy = false,
  loadGeneration = 0;
let acknowledgedPhraseHash = location.hash;
function protectRecoveryPhrase() {
  if (!phrase) {
    acknowledgedPhraseHash = location.hash;
    return true;
  }
  const discard = window.confirm(
    "You have not confirmed saving your new recovery phrase. Discarding it without a saved copy may prevent account recovery. Choose Cancel to keep it visible, or OK to discard it.",
  );
  if (discard) {
    phrase = null;
    acknowledgedPhraseHash = location.hash;
    return true;
  }
  return false;
}
window.addEventListener("beforeunload", (event) => {
  if (!phrase) return;
  event.preventDefault();
  event.returnValue = "";
});
window.addEventListener("hashchange", () => {
  if (phrase && !protectRecoveryPhrase()) {
    history.replaceState(null, "", acknowledgedPhraseHash);
    return;
  }
  acknowledgedPhraseHash = location.hash;
  load();
});
const canCreateReviews = (organization) =>
  isApprovedOrganization(organization) &&
  ["owner", "admin", "reviewer"].includes(organization?.role);
const isApprovedOrganization = (organization) =>
  String(organization?.status || "").toLowerCase() === "approved";
const canManageMemberships = (organization) =>
  isApprovedOrganization(organization) &&
  ["owner", "admin"].includes(organization?.role);
const loadMembersIfAllowed = (organization, load) => {
  if (canManageMemberships(organization)) load();
};
const isWorkspaceRouteAllowed = (account, route) =>
  account?.scope === "full" || ["account", "verify-receipt"].includes(route);
const isPermissionError = (error) =>
  error?.status === 403 ||
  ["forbidden", "FORBIDDEN", "recovery_scope", "RECOVERY_SCOPE"].includes(
    error?.code,
  );
const findApprovedOrganization = (memberships, id) =>
  (id
    ? memberships.find(
        (organization) =>
          organization.id === id && isApprovedOrganization(organization),
      )
    : memberships.find(isApprovedOrganization)) || null;
const isCurrentLoad = ({
  requestId,
  requestedHash,
  currentRequestId,
  currentHash,
  requestedOrgId,
  currentOrgId,
}) =>
  requestId === currentRequestId &&
  requestedHash === currentHash &&
  (requestedOrgId === undefined || requestedOrgId === currentOrgId);
const isCurrentLoadState = (requestId, requestedHash) =>
  isCurrentLoad({
    requestId,
    requestedHash,
    currentRequestId: loadGeneration,
    currentHash: routeHash(),
  });
const resetOrganizationView = () => {
  reviews = [];
  pendingResponses = [];
  reviewNext = null;
};
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const routeHash = () => location.hash.replace(/^#/, "");
const path = () =>
  routeHash().replace(/^\/?/, "").split(/[?]/, 1)[0].split("/").filter(Boolean);
const hasUnsupportedResponseRoute = (route, hash) =>
  route[0] === "respond" && (hash.includes("?") || route.length !== 2);
function authHref(mode) {
  return returnRoute
    ? `#/${mode}?next=${encodeURIComponent(returnRoute)}`
    : `#/${mode}`;
}
const go = (p) => {
  const next = "/" + String(p).replace(/^\/+/, "");
  if (location.hash === `#${next}`) {
    load();
    return;
  }
  location.hash = next;
};
const say = (e) =>
  typeof e === "string"
    ? e
    : typeof e?.message === "string"
      ? e.message
      : "Something went wrong. Please try again.";
function toast(message, type = "error") {
  let region = document.querySelector("#toast-region");
  if (!region) {
    region = document.createElement("div");
    region.id = "toast-region";
    region.className = "toast-region";
    region.setAttribute("aria-atomic", "true");
    document.body.appendChild(region);
  }
  region.setAttribute("aria-live", type === "error" ? "assertive" : "polite");
  region.setAttribute("role", type === "error" ? "alert" : "status");
  region.replaceChildren();
  const item = document.createElement("div");
  item.className = `toast toast-${type}`;
  const text = document.createElement("span");
  text.textContent = message;
  item.appendChild(text);
  const close = document.createElement("button");
  close.className = "toast-close";
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss notification");
  close.textContent = "×";
  close.onclick = () => item.remove();
  item.appendChild(close);
  region.appendChild(item);
  clearTimeout(region.dismissTimer);
  region.dismissTimer = setTimeout(() => item.remove(), 10000);
}
async function copyText(value, label = "Text") {
  try {
    if (!navigator.clipboard?.writeText)
      throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText(value);
    toast(`${label} copied.`, "success");
  } catch {
    toast(
      `Could not copy ${label.toLowerCase()}. Select and copy it manually.`,
      "error",
    );
  }
}
function receiptHTML(receipt) {
  const text = JSON.stringify(receipt, null, 2);
  const acceptedAt = formatReceiptTime(receipt?.accepted_at);
  const acceptedTime =
    acceptedAt === "Acceptance time unavailable"
      ? esc(acceptedAt)
      : `Accepted <time>${esc(acceptedAt)}</time>`;
  return `<section class="notice receipt-notice" aria-labelledby="receipt-heading"><h2 id="receipt-heading">Response accepted</h2><p class="receipt-status" role="status">Receipt signature verified</p><p>${acceptedTime}</p><p>Keep a copy of this receipt. It confirms acceptance, not what your response said.</p><div class="receipt-actions"><button type="button" class="button" data-receipt-download>Download receipt PNG</button><a class="button ghost" href="#/verify-receipt">Verify a receipt</a></div><details class="receipt-details"><summary>Technical details (JSON)</summary><button type="button" class="button secondary" data-receipt-copy>Copy receipt data</button><pre class="receipt-data">${esc(text)}</pre></details></section>`;
}
function bindReceiptTools(box, receipt) {
  const text = JSON.stringify(receipt, null, 2);
  box.querySelector("[data-receipt-copy]").onclick = () =>
    copyText(text, "Receipt");
  const download = box.querySelector("[data-receipt-download]");
  download.onclick = async () => {
    if (download.disabled || !download.isConnected) return;
    download.disabled = true;
    setButtonText(download, "Preparing PNG…");
    let url;
    try {
      const blob = await renderReceiptPNG({ receipt });
      if (!download.isConnected) return;
      url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "anonce-receipt.png";
      document.body.appendChild(link);
      link.click();
      link.remove();
      toast("Receipt PNG download started.", "success");
    } catch (error) {
      if (download.isConnected)
        toast(`Could not create receipt PNG. ${say(error)}`);
    } finally {
      if (url) URL.revokeObjectURL(url);
      if (download.isConnected) {
        download.disabled = false;
        setButtonText(download, "Download receipt PNG");
      }
    }
  };
}
function icon(name) {
  return `<img class="icon" src="./assets/icons/${name}.svg" alt="" aria-hidden="true">`;
}
const buttonIcons = [
  [/copy/i, "copy"],
  [/download|export/i, "download"],
  [/create|new|add/i, "plus"],
  [/remove|revoke/i, "trash-2"],
  [/sign in|accept|continue|send|save|approve|update/i, "check"],
  [/manage|open|respond|status|retry|back/i, "arrow-right"],
  [/rotate/i, "rotate-cw"],
  [/share/i, "share-2"],
  [/publish/i, "check"],
  [/close/i, "x"],
];
function renderButtonIcons(scope = root) {
  scope.querySelectorAll(".button").forEach((control) => {
    const existing = control.querySelector(".icon");
    if (existing) {
      control.dataset.icon ||= existing
        .getAttribute("src")
        ?.split("/")
        .at(-1)
        .replace(/\.svg$/, "");
      return;
    }
    const name =
      buttonIcons.find(([pattern]) => pattern.test(control.textContent))?.[1] ||
      "arrow-right";
    control.dataset.icon = name;
    control.insertAdjacentHTML("afterbegin", icon(name));
  });
}
function setButtonText(control, text) {
  const name = control.dataset.icon;
  control.textContent = text;
  if (name) control.insertAdjacentHTML("afterbegin", icon(name));
}
function frame(body, title = "Workspace") {
  root.setAttribute("aria-busy", "false");
  const sourceURL = esc(api.getSourceURL());
  const sourceLink = `<a class="source-link" href="${sourceURL}" target="_blank" rel="noopener noreferrer">${icon("arrow-up-right")} Source code</a>`;
  const active = path()[0];
  const workspaceLabel =
    session && currentOrg
      ? `<div class="workspace-label" aria-label="Current workspace: ${esc(currentOrg.name || "Organization")}"><span class="workspace-icon">${icon("building-2")}</span><strong>${esc(currentOrg.name || "Organization")}</strong></div>`
      : "";
  root.innerHTML = `<a class="skip-link" href="#main-content">Skip to main content</a><div class="shell"><header class="site-header"><a class="brand" href="#/"><span class="brand-mark" aria-hidden="true">A</span>Anonce</a>${workspaceLabel}<nav class="nav" aria-label="Workspace"><a href="#/" aria-label="Overview" ${!active ? 'aria-current="page"' : ""} class="${!active ? "active" : ""}"><span class="nav-item">${icon("house")}<span>Overview</span></span></a><a href="#/orgs" aria-label="Organizations" ${active === "orgs" ? 'aria-current="page"' : ""} class="${active === "orgs" ? "active" : ""}"><span class="nav-item">${icon("building-2")}<span>Organizations</span></span></a><a href="#/verify-receipt" aria-label="Verify receipt" ${active === "verify-receipt" ? 'aria-current="page"' : ""} class="${active === "verify-receipt" ? "active" : ""}"><span class="nav-item">${icon("check-circle-2")}<span>Verify receipt</span></span></a><a href="#/account" aria-label="Account and recovery" ${active === "account" ? 'aria-current="page"' : ""} class="${active === "account" ? "active" : ""}"><span class="nav-item">${icon("user-round")}<span class="nav-label"><span>Account</span><span class="nav-detail">&amp; recovery</span></span></span></a></nav><div class="header-account">${session ? esc(session.email || "Member") : '<a href="#/login">Sign in</a>'}</div></header><main class="main" id="main-content" tabindex="-1"><div class="content">${body}</div></main><footer class="site-footer"><p>Responses are designed to be anonymous. See your organization’s privacy policy for its trust assumptions.</p><a href="#/verify-receipt">Verify a receipt</a>${sourceLink}</footer></div>`;
  if (session?.scope !== "full")
    root
      .querySelectorAll('.nav a[href="#/"], .nav a[href="#/orgs"]')
      .forEach((link) => link.remove());
  renderButtonIcons();
  root.querySelector(".skip-link").addEventListener("click", (event) => {
    event.preventDefault();
    const main = root.querySelector("#main-content");
    main.focus();
    main.scrollIntoView({ block: "start" });
  });
  root.querySelectorAll("label:not([for])").forEach((label) => {
    if (label.querySelector("input,select,textarea")) return;
    const control = label.nextElementSibling?.matches("input,select,textarea")
      ? label.nextElementSibling
      : label.parentElement?.querySelector("input,select,textarea");
    if (!control) return;
    if (!control.id)
      control.id = `field-${Math.random().toString(36).slice(2)}`;
    label.htmlFor = control.id;
  });
}
function head(title, sub, action = "") {
  return `<div class="page-head"><div><h1>${esc(title)}</h1><p class="subtitle">${esc(sub)}</p></div>${action}</div>`;
}
function headWithBadge(title, badge, detail, action = "") {
  return `<div class="page-head"><div><h1>${esc(title)}</h1><p class="subtitle">${badge} · ${esc(detail)}</p></div>${action}</div>`;
}
function statusBadge(value) {
  const status = String(value || "active").toLowerCase();
  const known = {
    published: ["Open", "positive"],
    open: ["Open", "positive"],
    closed: ["Closed", "closed"],
    draft: ["Draft", "muted"],
    pending: ["Pending", "warning"],
    approved: ["Approved", "positive"],
    active: ["Active", "positive"],
    revoked: ["Revoked", "danger"],
    valid: ["Valid", "positive"],
    invalid: ["Unreadable", "danger"],
  };
  const [label, tone] = known[status] || [
    status.replace(/[-_]/g, " "),
    "muted",
  ];
  return `<span class="status-badge status-${tone}">${icon(tone === "positive" ? "check-circle-2" : tone === "warning" ? "clock-3" : tone === "danger" ? "ban" : "circle-dot")}<span>${esc(label)}</span></span>`;
}
function button(label, href, cls = "") {
  return `<a class="button ${cls}" href="#/${href}">${esc(label)}</a>`;
}
function recoveryPhrasePanel(words, prefix = "recovery") {
  return `<div class="word-grid">${words.map((w, i) => `<div class="word"><b>${String(i + 1).padStart(2, "0")}</b>${esc(w)}</div>`).join("")}</div><div class="recovery-actions"><button id="${prefix}-copy" class="button secondary" type="button">Copy phrase</button><button id="${prefix}-download" class="button secondary" type="button">Download .txt</button></div>`;
}
function bindRecoveryPhraseTools(words, prefix = "recovery") {
  const phraseText = words.join(" ");
  const copyButton = document.querySelector(`#${prefix}-copy`);
  const downloadButton = document.querySelector(`#${prefix}-download`);
  copyButton.onclick = async () => {
    if (!copyButton.isConnected || phrase !== words) return;
    try {
      await navigator.clipboard.writeText(phraseText);
      if (copyButton.isConnected && phrase === words)
        toast("Phrase copied.", "success");
    } catch {
      if (copyButton.isConnected && phrase === words)
        toast(
          "Could not copy recovery phrase. Select and copy the words above.",
        );
    }
  };
  downloadButton.onclick = () => {
    if (!downloadButton.isConnected || phrase !== words) return;
    const blob = new Blob([`${phraseText}\n`], {
      type: "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "anonce-recovery-phrase.txt";
    document.body.appendChild(link);
    try {
      link.click();
    } finally {
      link.remove();
      URL.revokeObjectURL(url);
    }
    toast("Recovery phrase download started.", "success");
  };
}
function bind(form, fn) {
  document.querySelector(form)?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    if (busy) return;
    busy = true;
    let b = form.querySelector("[type=submit]");
    if (b) {
      b.disabled = true;
      b.dataset.old = b.textContent;
      setButtonText(b, "Please wait…");
    }
    try {
      await fn(new FormData(form), form);
    } catch (err) {
      toast(say(err));
    } finally {
      busy = false;
      if (b) {
        b.disabled = false;
        setButtonText(b, b.dataset.old);
      }
    }
  });
}
async function load() {
  const requestId = ++loadGeneration,
    requestedHash = routeHash(),
    isCurrentLoad = () => isCurrentLoadState(requestId, requestedHash);
  const route = path();
  const respondHash = routeHash();
  if (hasUnsupportedResponseRoute(route, respondHash)) {
    frame(
      emptyCard(
        "Unsupported response link",
        "Open this review from your signed-in dashboard instead.",
      ),
      "Respond",
    );
    return;
  }
  const hashParams = new URLSearchParams(routeHash().split("?")[1] || "");
  if (
    ["login", "register", "recover"].includes(route[0]) &&
    hashParams.has("next")
  )
    returnRoute = hashParams.get("next");
  if (route[0] === "verify-receipt") {
    try {
      session = await api.getSessionStatus();
    } catch {
      session = null;
    }
    if (!isCurrentLoad()) return;
    return await renderReceiptVerifier();
  }
  try {
    const result = await api.getSession();
    if (!isCurrentLoad()) return;
    session = result;
  } catch {
    if (!isCurrentLoad()) return;
    session = null;
  }
  if (!session && (route[0] === "respond" || route[0] === "invite"))
    returnRoute =
      route[0] === "respond"
        ? routeHash()
        : `/${route[0]}/${encodeURIComponent(route[1] || "")}`;
  else if (session && (route[0] === "respond" || route[0] === "invite"))
    returnRoute = null;
  if (!session) {
    if (route[0] === "respond") return renderAuth("login", "respond");
    if (route[0] === "invite") return renderAuth("login", "invite");
    renderAuth(
      route[0] === "register"
        ? "register"
        : route[0] === "recover"
          ? "recover"
          : "login",
    );
    return;
  }
  if (!route[0]) {
    frame(
      `${head("Overview", "Review activity and manage responses.")}<section class="card empty overview-loading" role="status" aria-live="polite" aria-busy="true"><span class="loading-indicator" aria-hidden="true"></span><span>Loading your overview…</span></section>`,
      "Overview",
    );
  }
  if (!isWorkspaceRouteAllowed(session, route[0])) {
    frame(
      emptyCard(
        "Workspace unavailable",
        "Your account is in recovery mode. Return to account settings to finish recovery.",
        button("Account & recovery", "account"),
      ),
      "Workspace",
    );
    return;
  }
  if (route[0] === "respond") {
    renderRespond(route[1]);
    return;
  }
  let organizationError = "";
  try {
    const result = await api.listOrganizations();
    if (!isCurrentLoad()) return;
    orgs = result.items;
  } catch (e) {
    if (!isCurrentLoad()) return;
    orgs = [];
    organizationError = say(e);
  }
  if (!isCurrentLoad()) return;
  currentOrg =
    findApprovedOrganization(orgs, currentOrg?.id) ||
    findApprovedOrganization(orgs);
  const p = path();
  if (p[0] === "invite" && p[1]) {
    frame(
      `${head("You’re invited", "Accept this invitation to join an organization.")}<section class="card form-card"><button class="button" id="accept-invite">Accept invitation</button></section>`,
      "Invitation",
    );
    document.querySelector("#accept-invite").onclick = async () => {
      try {
        await api.acceptInvite({ token: p[1] });
        go("/orgs");
        load();
      } catch (e) {
        toast(say(e));
      }
    };
    return;
  }
  if (p[0] === "account") return renderAccount();
  if (p[0] === "orgs") return renderOrgs();
  if (p[0] === "review" && p[1]) return renderReview(p[1], p[2], isCurrentLoad);
  if (organizationError) {
    frame(
      `${head("Organizations unavailable", "We couldn’t load your organizations. Try again shortly.")}`,
      "Overview",
    );
    toast(organizationError);
    return;
  }
  if (!currentOrg) {
    const hasMemberships = orgs.length > 0;
    frame(
      hasMemberships
        ? `${head("Organization access pending", "Your organizations appear here when membership is approved.")}${emptyCard("No approved organization yet", "Pending or revoked memberships cannot open workspaces. Check membership status or contact an organization owner.", button("View membership status", "orgs"))}`
        : `${head("A thoughtful space for feedback", "Start by creating an organization, then invite the people who can review responses.")}${emptyCard("No organization yet", "Create an organization to build your first anonymous review.", button("Create organization", "orgs"))}`,
      "Overview",
    );
    return;
  }
  const orgId = currentOrg.id;
  const [reviewResult, pendingResult] = await Promise.allSettled([
    api.listReviews({ orgId }),
    api.listPendingResponses(),
  ]);
  if (!isCurrentLoad() || currentOrg?.id !== orgId) return;
  if (reviewResult.status === "rejected") {
    frame(
      `${head("Reviews unavailable", "We couldn’t load reviews. Try again shortly.")}`,
      "Overview",
    );
    toast(say(reviewResult.reason));
    return;
  }
  reviews = reviewResult.value.items;
  reviewNext = reviewResult.value.next;
  if (pendingResult.status === "fulfilled") {
    pendingResponses = pendingResult.value.items;
  } else {
    pendingResponses = null;
    toast(say(pendingResult.reason));
  }
  if (!isCurrentLoad() || currentOrg?.id !== orgId) return;
  renderHome();
}
async function renderReceiptVerifier() {
  let currentTrust = "";
  let trustAvailable = true;
  try {
    currentTrust = JSON.stringify(await api.loadReceiptTrust(), null, 2);
  } catch {
    trustAvailable = false;
  }
  if (path()[0] !== "verify-receipt") return;
  frame(
    `${head("Verify a receipt", "Public signing keys load once from this site. Image reading and signature checking happen locally.")}
    <section class="card form-card verifier-card">
      <div class="verifier-intro"><span class="verifier-step">A private, local check</span><p>Choose the receipt file you downloaded. You do not need to open or edit JSON.</p></div>
      <label class="field receipt-file-field"><span>Receipt card image</span><input id="verify-receipt-file" type="file" accept="image/png,.png" aria-describedby="receipt-limit receipt-file-status"><span id="receipt-file-status" class="help" aria-live="polite">Choose your Anonce receipt PNG.</span></label>
      <details class="verifier-paste"><summary>Paste receipt JSON instead</summary><label class="field" for="verify-receipt-text">Receipt JSON<textarea id="verify-receipt-text" rows="7" maxlength="65536" aria-describedby="receipt-limit"></textarea></label></details>
      <p id="receipt-limit" class="help">Receipt image up to 4 MiB. Verification starts only when you press the button.</p>
      <p class="notice verifier-trust-note">This check uses public signing keys published by this site unless you choose another configuration. A receipt cannot provide or replace its own trusted key; never trust a replacement key supplied with a receipt.</p>
      <details class="verify-trust"><summary>Choose which public signing keys to trust</summary><p class="help">${trustAvailable ? "This configuration uses keys published by this site. For an independent check, get a configuration from a source you trust." : "Could not load this site’s public signing keys. Choose an independently obtained configuration to continue."}</p>
        <label class="trust-choice"><input type="radio" name="trust-source" value="current" ${trustAvailable ? "checked" : "disabled"}> Use keys published by this site</label>
        <label class="trust-choice"><input type="radio" name="trust-source" value="import" ${trustAvailable ? "" : "checked"}> Use an independently obtained configuration</label>
        <label class="field">Configuration file<input id="verify-trust-file" type="file" accept="application/json,.json"></label>
        <label class="field" for="verify-trust-text">Configuration JSON<textarea id="verify-trust-text" rows="6" maxlength="65536" ${trustAvailable ? "disabled" : ""}>${esc(currentTrust)}</textarea></label>
        <button type="button" class="button secondary" id="download-trust" ${trustAvailable ? "" : "disabled"}>Download this site’s public configuration</button>
      </details>
      <button type="button" class="button verify-submit" id="verify-receipt">Verify receipt</button>
      <div id="verify-result" role="status" aria-live="polite"></div>
      <p class="help verifier-limit">A valid signature confirms only that listed acceptance details were signed. It does not prove response contents, storage, anonymity, or trusted time. This check still trusts code served by this site.</p>
    </section>`,
    "Verify a receipt",
  );
  const receiptText = document.querySelector("#verify-receipt-text");
  const receiptFile = document.querySelector("#verify-receipt-file");
  const trustText = document.querySelector("#verify-trust-text");
  trustText.disabled = trustAvailable;
  const trustFile = document.querySelector("#verify-trust-file");
  const result = document.querySelector("#verify-result");
  const verifyButton = document.querySelector("#verify-receipt");
  let generation = 0;
  let imageLoadToken = null;
  const receiptFileStatus = document.querySelector("#receipt-file-status");
  const clearResult = () => {
    if (imageLoadToken !== null)
      receiptFileStatus.textContent =
        "Image loading interrupted. Choose the PNG again.";
    imageLoadToken = null;
    generation++;
    result.replaceChildren();
    verifyButton.disabled = false;
    return generation;
  };
  const currentChoice = () =>
    document.querySelector('input[name="trust-source"]:checked')?.value ===
    "current";
  receiptText.addEventListener("input", () => {
    clearResult();
    receiptFileStatus.textContent = "Using pasted receipt JSON.";
  });
  trustText.addEventListener("input", clearResult);
  document.querySelectorAll('input[name="trust-source"]').forEach((radio) =>
    radio.addEventListener("change", () => {
      trustText.disabled = currentChoice();
      clearResult();
    }),
  );
  receiptFile.addEventListener("change", () => {
    const selectedFile = receiptFile.files[0];
    receiptText.value = "";
    const token = clearResult();
    receiptFileStatus.textContent = selectedFile
      ? "Reading receipt image…"
      : "Choose your Anonce receipt PNG.";
    if (!selectedFile) return;
    if (selectedFile.size > 4 * 1024 * 1024) {
      receiptFileStatus.textContent =
        "Image exceeds 4 MiB. Choose a smaller PNG.";
      return;
    }
    imageLoadToken = token;
    verifyButton.disabled = true;
    decodeReceiptPNG({ file: selectedFile })
      .then((decoded) => {
        if (
          token !== generation ||
          imageLoadToken !== token ||
          !receiptFile.isConnected
        )
          return;
        imageLoadToken = null;
        receiptText.value = decoded;
        receiptFileStatus.textContent =
          "Receipt image loaded. Ready to verify.";
        verifyButton.disabled = false;
      })
      .catch(() => {
        if (
          token !== generation ||
          imageLoadToken !== token ||
          !receiptFile.isConnected
        )
          return;
        imageLoadToken = null;
        receiptFileStatus.textContent =
          "Could not read receipt image. Choose another PNG.";
        result.textContent =
          "This image does not contain a readable receipt QR code.";
        verifyButton.disabled = false;
      });
  });
  trustFile.addEventListener("change", () => {
    document.querySelector(
      'input[name="trust-source"][value="import"]',
    ).checked = true;
    trustText.disabled = false;
    loadVerifierFile(
      trustFile.files[0],
      trustText,
      result,
      clearResult,
      (token) => token === generation,
    );
  });
  document.querySelector("#download-trust").onclick = () => {
    const data = currentTrust;
    const url = URL.createObjectURL(
      new Blob([`${data}\n`], { type: "application/json;charset=utf-8" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "anonce-receipt-trust.json";
    document.body.appendChild(link);
    try {
      link.click();
    } finally {
      link.remove();
      URL.revokeObjectURL(url);
    }
    toast("Public trust configuration download started.", "success");
  };
  verifyButton.onclick = async () => {
    clearResult();
    const check = generation;
    const inputText = receiptText.value;
    const selectedTrust = currentChoice() ? currentTrust : trustText.value;
    if (
      !inputText.trim() &&
      receiptFileStatus.textContent.startsWith("Could not read receipt image.")
    ) {
      result.textContent =
        "This image does not contain a readable receipt QR code.";
      return;
    }
    if (!inputText.trim() || !selectedTrust.trim()) {
      result.textContent = !inputText.trim()
        ? "Choose a receipt PNG or paste receipt JSON first."
        : "Choose or paste a public trust configuration.";
      return;
    }
    verifyButton.disabled = true;
    result.textContent = "Checking receipt signature…";
    try {
      const verified = await verifyReceiptLocally(inputText, selectedTrust);
      if (check !== generation) return;
      const accepted = formatReceiptTime(verified.receipt.accepted_at);
      result.innerHTML = `<section class="notice verifier-success"><strong>Receipt signature verified</strong><p>The signed receipt records acceptance at <time>${esc(accepted)}</time>.</p><p>This verifies the signature only. It does not match the receipt to your original response or prove what it contained.</p></section>`;
    } catch {
      if (check === generation)
        result.innerHTML =
          '<section class="notice verifier-failure"><strong>Receipt could not be verified</strong><p>Check that you selected the complete receipt and trusted public configuration. A failed check does not confirm acceptance.</p></section>';
    } finally {
      if (check === generation) verifyButton.disabled = false;
    }
  };
}
function formatReceiptTime(value) {
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value))
    return "Acceptance time unavailable";
  const seconds = BigInt(value);
  if (seconds > 8640000000000n)
    return `Unix time ${value} (outside display range)`;
  const date = new Date(Number(seconds) * 1000);
  return Number.isNaN(date.getTime())
    ? `Unix time ${value}`
    : date.toLocaleString();
}
async function verifyReceiptLocally(receiptText, trustText) {
  const byteLength = (value) => new TextEncoder().encode(value).byteLength;
  if (byteLength(receiptText) > 65536 || byteLength(trustText) > 65536)
    throw new Error(
      "Receipt and trust configuration must each be 64 KiB or smaller.",
    );
  return api.verifySavedReceipt({ receiptText, trustText });
}
async function loadVerifierFile(
  file,
  target,
  result,
  clearResult,
  isCurrent,
  status = null,
) {
  const token = clearResult();
  target.value = "";
  if (status)
    status.textContent = file
      ? "Reading file…"
      : "Choose your Anonce receipt PNG.";
  if (!file) return;
  if (file.size > 65536) {
    if (isCurrent(token)) {
      result.textContent = "File exceeds 64 KiB. Choose a smaller JSON file.";
      if (status)
        status.textContent = "File is too large. Choose a file up to 64 KiB.";
    }
    return;
  }
  try {
    const text = await file.text();
    if (!isCurrent(token)) return;
    if (!text.trim()) {
      result.textContent =
        "This file is empty. Choose another receipt or paste its JSON.";
      if (status)
        status.textContent = "File is empty. Choose another or paste its JSON.";
      return;
    }
    clearResult();
    target.value = text;
    if (status) status.textContent = "Receipt loaded. Ready to verify.";
  } catch {
    if (isCurrent(token)) {
      result.textContent =
        "Could not read file. Choose another file or paste its JSON.";
      if (status)
        status.textContent =
          "Could not read file. Choose another or paste its JSON.";
    }
  }
}
function emptyCard(t, d, act = "") {
  return `<section class="card empty"><strong>${esc(t)}</strong>${esc(d)}<div class="empty-action">${act}</div></section>`;
}
function renderHome() {
  const creatorReviews = reviews.filter(isReviewOwner);
  const canCreate = canCreateReviews(currentOrg);
  frame(
    `${head("Overview", "Review activity and manage responses.", canCreate ? button("New review", "review/new") : "")}${renderPendingResponses()}${canCreate ? `<div class="stat-grid"><div class="card stat"><div class="stat-label">Your reviews shown</div><div class="stat-value">${creatorReviews.length}</div></div><div class="card stat"><div class="stat-label">Accepted responses</div><div class="stat-value">${aggregateCount("accepted_count", creatorReviews)}</div></div><div class="card stat"><div class="stat-label">Issued authorizations</div><div class="stat-value">${aggregateCount("issued_count", creatorReviews)}</div></div></div>` : ""}<div class="section-row"><h2 class="section-title" id="reviews-heading" tabindex="-1">${canCreate ? "Your reviews" : "Reviews to respond to"}</h2><a class="top-link" href="#/orgs">Organizations</a></div>${
      reviews.length
        ? `<div class="review-list">${reviews
            .map((r) => {
              const mine = isReviewOwner(r);
              const metrics =
                mine && r.contentState !== "locked"
                  ? ` · <span aria-label="Accepted responses">${countText(r.accepted_count)} accepted</span> · <span aria-label="Issued authorizations">${countText(r.issued_count)} issued</span>`
                  : "";
              const completion =
                r.completedOnThisBrowser === true
                  ? "Completed on this browser"
                  : "No completion recorded here";
              const detail =
                r.contentState === "locked"
                  ? "Review content is unavailable on this browser."
                  : r.contentState === "corrupt"
                    ? "Review content could not be verified."
                    : completion;
              const respond =
                r.status === "published" &&
                r.contentState !== "locked" &&
                r.contentState !== "corrupt"
                  ? button(
                      "Respond",
                      `respond/${encodeURIComponent(r.id)}`,
                      "secondary small",
                    )
                  : "";
              return `<article class="card review-row"><div class="review-info"><strong>${esc(r.contentState === "locked" || r.contentState === "corrupt" ? "Encrypted review" : r.title || "Untitled review")}</strong><small>${statusBadge(r.status)}${mine ? metrics : ""} · ${esc(detail)}</small></div>${mine ? button("Manage", `review/${encodeURIComponent(r.id)}`, "secondary small") : ""}${respond}</article>`;
            })
            .join(
              "",
            )}</div>${reviewNext ? `<button class="button secondary load-more" id="load-more-reviews">Load more reviews</button>` : ""}`
        : emptyCard(
            canCreate ? "Nothing here yet" : "No open reviews",
            canCreate
              ? "Your reviews will appear here once you create one."
              : "Open reviews will appear here when your organization shares them.",
            canCreate ? button("Create your first review", "review/new") : "",
          )
    }`,
    "Overview",
  );
  root
    .querySelectorAll("[data-pending]")
    .forEach((button) =>
      button.addEventListener("click", () =>
        resumePending(button.dataset.pending, button),
      ),
    );
  document
    .querySelector("#load-more-reviews")
    ?.addEventListener("click", loadMoreReviews);
}
async function loadMoreReviews(event) {
  const button = event.currentTarget;
  const orgId = currentOrg.id,
    requestId = loadGeneration,
    requestedHash = routeHash();
  const isCurrent = () =>
    isCurrentLoad({
      requestId,
      requestedHash,
      currentRequestId: loadGeneration,
      currentHash: routeHash(),
      requestedOrgId: orgId,
      currentOrgId: currentOrg?.id,
    });
  button.disabled = true;
  setButtonText(button, "Loading…");
  try {
    const result = await api.listReviews({
      orgId,
      after: reviewNext,
    });
    if (!isCurrent()) return;
    reviews = [...reviews, ...result.items];
    reviewNext = result.next;
    renderHome();
    (
      document.querySelector("#load-more-reviews") ||
      document.querySelector("#reviews-heading")
    )?.focus();
  } catch (error) {
    if (!isCurrent()) return;
    toast(say(error));
    button.disabled = false;
    setButtonText(button, "Load more reviews");
  }
}
function countText(value) {
  if (typeof value === "string" && /^(0|[1-9]\d*)$/.test(value)) return value;
  return Number.isSafeInteger(value) && value >= 0
    ? String(value)
    : "Unavailable";
}
function aggregateCount(key, rows = reviews) {
  if (reviewNext) return "Unavailable";
  let total = 0n;
  for (const row of rows) {
    const value = row[key];
    if (typeof value === "string" && /^(0|[1-9]\d*)$/.test(value)) {
      total += BigInt(value);
    } else if (Number.isSafeInteger(value) && value >= 0) {
      total += BigInt(value);
    } else {
      return "Unavailable";
    }
  }
  return String(total);
}
function isReviewOwner(r) {
  return r.is_creator === true;
}
function renderPendingResponses() {
  if (pendingResponses === null) return "";
  if (!pendingResponses.length) return "";
  return `<section class="section-row"><h2 class="section-title">Responses to finish</h2></section><div class="review-list">${pendingResponses.map((item) => `<article class="card review-row"><div class="review-info"><strong>${esc(item.title || "Anonymous response")}</strong><small>Submission still processing</small></div><button class="button secondary small" data-pending="${esc(item.pendingId)}">Check status</button></article>`).join("")}</div>`;
}
async function resumePending(pendingId, button) {
  const old = button.textContent;
  button.disabled = true;
  setButtonText(button, "Checking…");
  try {
    let result = await api.lookupReceipt({ pendingId });
    if (result.status !== "accepted")
      result = await api.submitResponse({ pendingId });
    if (result.status === "accepted") {
      pendingResponses = pendingResponses.filter(
        (item) => item.pendingId !== pendingId,
      );
      renderHome();
    } else {
      setButtonText(button, "Still processing");
      setTimeout(() => {
        if (button.isConnected) {
          button.disabled = false;
          setButtonText(button, old);
        }
      }, 1800);
    }
  } catch (e) {
    toast(say(e));
    setButtonText(button, old);
    button.disabled = false;
  }
}
function renderAuth(mode, intent = "") {
  let words = phrase;
  let title =
    mode === "register"
      ? "Create your account"
      : mode === "recover"
        ? "Recover your account"
        : "Welcome back";
  let body =
    mode === "recover"
      ? `<form id="auth" class="form-card auth-inner-form"><div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" maxlength="254" required autocomplete="email"></div><div class="field"><label for="words">12-word recovery phrase</label><textarea id="words" name="words" required autocomplete="off" placeholder="Enter all 12 words in order"></textarea></div><div class="field"><label for="password">New password</label><input id="password" name="newPassword" type="password" minlength="12" required autocomplete="new-password"><p class="help">At least 12 characters.</p></div><p class="form-error"></p><button class="button" type="submit">Recover account</button></form>`
      : `<form id="auth" class="form-card auth-inner-form"><div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" maxlength="254" required autocomplete="email" placeholder="you@organization.org"></div><div class="field"><label for="password">Password</label><input id="password" name="password" type="password" minlength="12" required autocomplete="${mode === "register" ? "new-password" : "current-password"}"></div><p class="form-error"></p><button class="button" type="submit">${mode === "register" ? "Create account" : "Sign in"}</button></form>`;
  frame(
    `<div class="auth-wrap"><section class="card auth-card">${words ? `<p class="eyebrow">SAVE THIS ONCE</p><h1>Your recovery phrase</h1><p>Write these 12 words down somewhere private. You cannot view them again.</p><div class="alert"><strong>Keep it secret.</strong> Anyone with this phrase may recover your account. Downloaded copies are sensitive credentials.</div>${recoveryPhrasePanel(words)}<label class="check"><input id="saved" type="checkbox"> I saved my 12-word phrase somewhere safe.</label><button id="continue" class="button" disabled>Continue to Anonce</button>` : `<h1>${title}</h1><p>${intent === "respond" ? "Sign in to continue to this response form." : intent === "invite" ? "Sign in to accept your invitation." : mode === "register" ? "Create an account to join feedback spaces." : "Sign in to manage your organization."}</p>${body}<div class="divider"></div><p class="help">${mode === "register" ? `Already have an account? <a href="${authHref("login")}">Sign in</a>` : `New to Anonce? <a href="${authHref("register")}">Create an account</a> · <a href="${authHref("recover")}">Recover account</a>`}</p>`}</section></div>`,
    title,
  );
  if (words) {
    bindRecoveryPhraseTools(words);
    document.querySelector("#saved").onchange = (e) =>
      (document.querySelector("#continue").disabled = !e.target.checked);
    document.querySelector("#continue").onclick = () => {
      phrase = null;
      const destination = session ? returnRoute || "/" : "/login";
      returnRoute = null;
      go(destination);
      load();
    };
    return;
  }
  bind("#auth", async (fd) => {
    if (mode === "register") {
      let result = await api.register({
        email: fd.get("email").trim(),
        password: fd.get("password"),
      });
      phrase = result.recoveryWords;
      session = result.session;
      renderAuth("register");
    } else if (mode === "recover") {
      const result = await api.recover({
        email: fd.get("email").trim(),
        words: fd.get("words"),
        newPassword: fd.get("newPassword"),
      });
      phrase = result.recoveryWords;
      session = result.session;
      if (result.reauthenticationRequired)
        toast(
          "Account recovery is complete. Save your new phrase, then sign in with your new password.",
          "success",
        );
      renderAuth("recover");
    } else {
      session = await api.login({
        email: fd.get("email").trim(),
        password: fd.get("password"),
      });
      const destination = returnRoute || "/";
      returnRoute = null;
      go(destination);
    }
  });
}
function renderOrgs() {
  const canManage = canManageMemberships(currentOrg);
  const roleOptions = (includeAdmin) =>
    `${includeAdmin ? '<option value="admin">Admin</option>' : ""}<option value="reviewer">Reviewer</option><option value="respondent">Respondent</option>`;
  frame(
    `${head("Organizations", "Manage your teams, memberships, and invitations.", `<button class="button" id="new-org">${icon("plus")} New organization</button>`)}<div class="card org-list">${orgs.length ? orgs.map((o) => `<div class="review-row org-row"><div class="avatar org-avatar">${icon("building-2")}</div><div class="review-info org-info"><strong>${esc(o.name)}</strong><div class="org-meta"><span class="org-role">${esc(o.role || "Member")}</span>${statusBadge(o.status || "active")}</div></div><button class="button secondary org-open" data-org="${esc(o.id)}">${icon("arrow-right")} Open</button></div>`).join("") : emptyCard("Your people, together", "Organizations bring verified members into one trusted space.")}</div><div id="org-form" class="card form-card hidden org-form-spaced"><form id="create-org"><div class="field"><label for="orgname">Organization name</label><input id="orgname" name="name" required maxlength="100"></div><p class="form-error"></p><button class="button" type="submit">Create organization</button></form></div>${currentOrg && canManage ? `<div class="section-row"><h2 class="section-title">${esc(currentOrg.name)} · members</h2><div class="toolbar"><button class="button secondary small" id="add-toggle">${icon("user-plus")} Add by email</button><button class="button ghost small" id="invite-toggle">${icon("link-2")} Invite link</button></div></div><div class="member-help">Add existing accounts directly by email. For people without an account, create an invite link.</div><div id="add-area" class="card form-card hidden"><form id="add-member"><div class="inline"><div class="field"><label for="member-email">Member email</label><input id="member-email" name="email" type="email" maxlength="254" required autocomplete="email" placeholder="person@organization.org"></div><div class="field"><label for="member-role">Role</label><select id="member-role" name="role">${roleOptions(currentOrg.role === "owner")}</select></div></div><p class="form-error"></p><button class="button" type="submit">${icon("user-plus")} Add member</button><p class="help">This adds an existing account immediately. New members can register first or join with an invite link.</p></form></div><div id="invite-area" class="card form-card hidden"><form id="invite"><div class="inline"><div class="field"><label for="invite-role">Role</label><select id="invite-role" name="role"><option value="reviewer">Reviewer</option><option value="respondent">Respondent</option></select></div><div class="field"><label for="invite-expires">Invite expires</label><input id="invite-expires" name="expiresAt" type="datetime-local" required></div></div><p class="form-error"></p><button class="button" type="submit">${icon("link-2")} Create invite</button><div id="invite-result"></div></form></div><div id="member-area" class="card empty">Loading membership…</div>` : ""}`,
    "Organizations",
  );
  document.querySelectorAll("[data-org]").forEach((button) => {
    if (
      !isApprovedOrganization(orgs.find((org) => org.id === button.dataset.org))
    )
      button.hidden = true;
  });
  document.querySelector("#new-org").onclick = () =>
    document.querySelector("#org-form").classList.toggle("hidden");
  document.querySelector("#create-org") &&
    bind("#create-org", async (fd) => {
      await api.createOrganization({ name: fd.get("name") });
      toast("Organization created.", "success");
      load();
    });
  document.querySelectorAll("[data-org]").forEach(
    (b) =>
      (b.onclick = () => {
        const selected = orgs.find((o) => o.id === b.dataset.org);
        if (!isApprovedOrganization(selected)) return;
        currentOrg = selected;
        resetOrganizationView();
        renderOrgs();
      }),
  );
  if (currentOrg && canManage) {
    document
      .querySelector("#add-toggle")
      ?.addEventListener("click", () =>
        document.querySelector("#add-area").classList.toggle("hidden"),
      );
    document
      .querySelector("#invite-toggle")
      ?.addEventListener("click", () =>
        document.querySelector("#invite-area").classList.toggle("hidden"),
      );
    bind("#add-member", async (fd) => {
      await api.addMember({
        orgId: currentOrg.id,
        email: fd.get("email").trim(),
        role: fd.get("role"),
      });
      toast("Member added.", "success");
      document.querySelector("#add-member").reset();
      loadMembers();
    });
    bind("#invite", async (fd) => {
      const expiresAt = new Date(fd.get("expiresAt")).toISOString(),
        r = await api.createInvite({
          orgId: currentOrg.id,
          role: fd.get("role"),
          expiresAt,
        });
      toast("Invitation created.", "success");
      document.querySelector("#invite-result").innerHTML =
        `<div class="notice">Invite created. Share this link with the member:<div class="share-box"><input readonly value="${esc(location.origin + location.pathname + "#/invite/" + r.token)}" aria-label="Invitation link"><button class="button small" type="button" id="copy">Copy</button></div></div>`;
      renderButtonIcons(document.querySelector("#invite-result"));
      document.querySelector("#copy").onclick = () =>
        copyText(
          location.origin + location.pathname + "#/invite/" + r.token,
          "Invitation link",
        );
    });
    loadMembersIfAllowed(currentOrg, loadMembers);
  }
}
async function loadMembers() {
  const organization = currentOrg,
    orgId = organization.id;
  let box = document.querySelector("#member-area");
  try {
    const rows = (await api.listMembers({ orgId })).items;
    if (!box.isConnected || currentOrg?.id !== orgId) return;
    const owner = organization.role === "owner";
    const admin = organization.role === "admin";
    box.innerHTML = rows.length
      ? `<div class="table-wrap"><table class="simple-table"><thead><tr><th>Email</th><th>Role</th><th>Status</th>${owner || admin ? "<th>Actions</th>" : ""}</tr></thead><tbody>${rows
          .map((m) => {
            const memberId = m.id || m.memberId;
            const memberRole = String(m.role || "member").toLowerCase();
            const memberStatus = String(
              m.status || m.state || "active",
            ).toLowerCase();
            const manageable = owner
              ? memberRole !== "owner"
              : admin && !["owner", "admin"].includes(memberRole);
            const editableRole =
              owner && memberRole !== "owner" && memberStatus === "approved";
            const canRevoke = manageable && memberStatus !== "revoked";
            return `<tr><td><span class="member-email">${icon("mail")}<span>${esc(m.email || "Email unavailable")}</span></span></td><td>${editableRole ? `<label class="sr-only" for="role-${esc(memberId)}">Role for ${esc(m.email || "member")}</label><select id="role-${esc(memberId)}" data-role="${esc(memberId)}" aria-label="Role for ${esc(m.email || "member")}">${owner ? `<option value="admin" ${memberRole === "admin" ? "selected" : ""}>Admin</option>` : ""}<option value="reviewer" ${memberRole === "reviewer" ? "selected" : ""}>Reviewer</option><option value="respondent" ${memberRole === "respondent" ? "selected" : ""}>Respondent</option></select>` : esc(m.role || "Member")}</td><td>${statusBadge(memberStatus)}</td>${owner || admin ? `<td class="member-actions">${manageable && memberStatus === "pending" ? `<button class="icon-btn" data-approve="${esc(memberId)}" aria-label="Approve ${esc(m.email || "member")}" title="Approve">${icon("check")}</button>` : ""}${canRevoke ? `<button class="icon-btn danger-icon" data-revoke="${esc(memberId)}" aria-label="Revoke ${esc(m.email || "member")}" title="Revoke">${icon("trash-2")}</button>` : ""}</td>` : ""}</tr>`;
          })
          .join("")}</tbody></table></div>`
      : emptyCard(
          "No members yet",
          "Invites and membership approvals will appear here.",
        );
    box.querySelectorAll("[data-role]").forEach((select) =>
      select.addEventListener("change", async () => {
        try {
          await api.changeMemberRole({
            orgId,
            memberId: select.dataset.role,
            role: select.value,
          });
          toast("Member role updated.", "success");
          loadMembers();
        } catch (e) {
          toast(say(e));
          loadMembers();
        }
      }),
    );
    box.querySelectorAll("[data-approve]").forEach(
      (b) =>
        (b.onclick = async () => {
          try {
            await api.approveMember({
              orgId,
              memberId: b.dataset.approve,
            });
            toast("Member approved.", "success");
            loadMembers();
          } catch (e) {
            toast(say(e));
          }
        }),
    );
    box.querySelectorAll("[data-revoke]").forEach(
      (b) =>
        (b.onclick = async () => {
          if (confirm("Revoke this membership?"))
            try {
              await api.revokeMember({
                orgId,
                memberId: b.dataset.revoke,
              });
              toast("Membership revoked.", "success");
              loadMembers();
            } catch (e) {
              toast(say(e));
            }
        }),
    );
  } catch (e) {
    if (!box.isConnected || currentOrg?.id !== orgId) return;
    box.textContent = "Membership could not be loaded.";
    toast(say(e));
  }
}
async function renderAccount() {
  frame(
    `${head("Account & recovery", "Manage password and recovery settings.")}<section class="card form-card"><h2 class="section-title">Change password</h2><form id="password" class="form-spaced"><div class="field"><label>Current password</label><input type="password" name="currentPassword" required autocomplete="current-password"></div><div class="field"><label>New password</label><input type="password" name="newPassword" minlength="12" required autocomplete="new-password"></div><p class="form-error"></p><button class="button" type="submit">Update password</button></form><div class="divider"></div><h2 class="section-title">Recovery phrase</h2><p class="subtitle">Replacing it disables your old phrase.</p><form id="rotate" class="form-spaced"><div class="field"><label>Confirm with current password</label><input type="password" name="currentPassword" required autocomplete="current-password"></div><p class="form-error"></p><button class="button secondary" type="submit">Rotate recovery phrase</button></form><div id="new-phrase"></div><div class="divider"></div><button id="logout" class="button ghost">Sign out</button></section>`,
    "Account",
  );
  bind("#password", async (fd) => {
    const result = await api.changePassword({
      currentPassword: fd.get("currentPassword"),
      newPassword: fd.get("newPassword"),
    });
    if (result?.reauthenticationRequired) {
      toast(
        "Password changed. Sign in again with your new password.",
        "success",
      );
      session = null;
      go("/login");
      return;
    }
    document.querySelector("#password").reset();
    document.querySelector("#password .form-error").textContent = "";
    toast("Password updated.", "success");
  });
  bind("#rotate", async (fd) => {
    if (phrase && !protectRecoveryPhrase()) return;
    const r = await api.rotateRecovery({
      currentPassword: fd.get("currentPassword"),
    });
    session = r.session;
    phrase = r.recoveryWords;
    toast(
      r.reauthenticationRequired
        ? "Recovery phrase replaced. Save it now, then sign in again with your current password."
        : "Recovery phrase replaced. Save your new phrase.",
      "success",
    );
    document.querySelector("#new-phrase").innerHTML =
      `<div class="alert"><strong>Save your new phrase now.</strong> The old phrase is replaced. Copies and downloaded files are sensitive recovery credentials.</div>${recoveryPhrasePanel(phrase, "rotated-recovery")}<label class="check"><input id="rotated-saved" type="checkbox"> I saved the new phrase</label>`;
    renderButtonIcons(document.querySelector("#new-phrase"));
    bindRecoveryPhraseTools(phrase, "rotated-recovery");
    document.querySelector("#rotated-saved").onchange = (e) => {
      if (e.target.checked && e.target.isConnected && phrase) {
        phrase = null;
        document.querySelector("#new-phrase").innerHTML =
          '<div class="notice">Phrase hidden. Keep your saved copy private.</div>';
        if (!r.session) {
          toast("Sign in with your current password to continue.", "success");
          go("/login");
        }
      }
    };
  });
  document.querySelector("#logout").onclick = async () => {
    if (!protectRecoveryPhrase()) return;
    const button = document.querySelector("#logout");
    button.disabled = true;
    try {
      await api.logout();
      session = null;
      toast("Signed out.", "success");
      go("/login");
    } catch (error) {
      toast(say(error));
      button.disabled = false;
    }
  };
}
async function renderReview(id, tab, isCurrent = () => true) {
  if (id === "new") {
    if (session?.scope !== "full" || !canCreateReviews(currentOrg)) {
      go("/");
      return;
    }
    frame(
      `${head("Start a new review", "Set a title and response limit. Add questions before publishing.")}<section class="card form-card"><form id="new-review"><div class="field"><label>Review title</label><input name="title" required maxlength="160" placeholder="What would you like to learn?"></div><div class="field"><label>Responses per member</label><input name="maxResponses" type="number" min="1" value="1" required></div><p class="form-error"></p><button class="button" type="submit">Create draft</button></form></section>`,
      "New review",
    );
    bind("#new-review", async (fd) => {
      let r = await api.createReview({
        orgId: currentOrg.id,
        title: fd.get("title"),
        maxResponses: Number(fd.get("maxResponses")),
      });
      toast("Review draft created.", "success");
      go(`/review/${encodeURIComponent(r.id)}/edit`);
    });
    return;
  }
  try {
    const loadedReview = await api.getReview({ reviewId: id });
    if (!isCurrent()) return;
    review = loadedReview;
  } catch (e) {
    if (!isCurrent()) return;
    if (isPermissionError(e)) {
      go("/");
      return;
    }
    frame(
      `${head("Encrypted review", "Review content is unavailable or cannot be decrypted.")}${button("Back to reviews", "", "secondary")}`,
      "Review",
    );
    return;
  }
  if (!isCurrent()) return;
  if (review.contentState === "locked") {
    go("/");
    return;
  }
  const reviewOrgId = review.org_id || review.orgId;
  currentOrg =
    orgs.find((organization) => organization.id === reviewOrgId) || null;
  if (
    !currentOrg ||
    session?.scope !== "full" ||
    !isApprovedOrganization(currentOrg)
  ) {
    go("/");
    return;
  }
  const canManage = isReviewOwner(review);
  const canReviewResponses = canManage;
  if (!canManage && !canReviewResponses) {
    if (review.status === "published" || review.status === "open") {
      go(`/respond/${encodeURIComponent(id)}`);
      renderRespond(id);
    } else go("/");
    return;
  }
  let status = review.status || "draft";
  let responseResult = null,
    responseError = "";
  if (tab === "results") {
    try {
      responseResult = await api.listResponses({ reviewId: id });
    } catch (e) {
      if (!isCurrent()) return;
      responseError = say(e);
    }
  }
  if (!isCurrent()) return;
  frame(
    `${headWithBadge(review.title || "Untitled review", statusBadge(status), review.revision !== undefined ? "Revision " + review.revision : "Review workspace", `<div class="toolbar">${canManage ? (status === "draft" ? '<button class="button" id="publish">Publish review</button>' : '<button class="button secondary" id="close">Close review</button>') : ""}</div>`)}${canManage && status === "draft" ? '<p class="member-help">Publishing gives all currently approved organization members access to the questions. Members approved later need a future review.</p>' : ""}<div class="tabs">${canManage ? `<a href="#/review/${encodeURIComponent(id)}/edit" class="${tab === "edit" ? "active" : ""}">Build</a>` : ""}${canReviewResponses ? `<a href="#/review/${encodeURIComponent(id)}/results" class="${tab === "results" ? "active" : ""}">Responses</a>` : ""}</div>${tab === "results" && canReviewResponses ? `<div id="response-results" aria-live="polite" tabindex="-1">${renderResponseResults(responseResult, responseError, review)}</div>` : canManage ? `<section class="card form-card"><form id="edit-review"><div class="field"><label>Title</label><input name="title" required maxlength="160" value="${esc(review.title)}"></div><div class="field"><label>Description</label><textarea name="description" maxlength="2000">${esc(review.description)}</textarea></div><div class="field"><label>Responses per member</label><input name="maxResponses" type="number" min="1" value="${esc(review.maxResponses || 1)}" required></div><div class="inline"><div class="field"><label>Opens</label><input type="datetime-local" name="opensAt" value="${dt(review.opensAt)}"></div><div class="field"><label>Closes</label><input type="datetime-local" name="closesAt" value="${dt(review.closesAt)}"></div></div><div class="section-row"><h2 class="section-title">Questions</h2><button type="button" class="button secondary small" id="add-question">Add question</button></div><div id="questions">${(review.questions || []).map(questionHTML).join("")}</div><p class="form-error"></p><div class="toolbar"><button class="button" type="submit">Save draft</button><button class="button secondary" type="button" id="preview">Preview</button></div></form></section><div id="preview-area"></div><div class="footnote">Draft changes are saved to this review only when you select Save draft.</div>` : ""}`,
    "Review",
  );
  if (responseError) toast(responseError);
  document
    .querySelector("#retry-responses")
    ?.addEventListener("click", () => renderReview(id, "results"));
  const loadMoreResponses = async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    setButtonText(button, "Loading…");
    try {
      const page = await api.listResponses({
        reviewId: id,
        after: responseResult.next,
      });
      responseResult = {
        items: [...responseResult.items, ...page.items],
        next: page.next,
      };
      const panel = document.querySelector("#response-results");
      panel.innerHTML = renderResponseResults(responseResult, "", review);
      bindResponseExports(id);
      panel
        .querySelector("#load-more-responses")
        ?.addEventListener("click", loadMoreResponses);
    } catch (e) {
      toast(say(e));
      button.disabled = false;
      setButtonText(button, "Load more responses");
    }
  };
  document
    .querySelector("#load-more-responses")
    ?.addEventListener("click", loadMoreResponses);
  document.querySelector("#publish")?.addEventListener("click", async () => {
    try {
      await api.publishReview({
        reviewId: id,
        expectedRevision: review.revision,
      });
      toast("Review published.", "success");
      load();
    } catch (e) {
      toast(say(e));
    }
  });
  document.querySelector("#close")?.addEventListener("click", async () => {
    if (confirm("Close this review to new responses?"))
      try {
        await api.closeReview({
          reviewId: id,
          expectedRevision: review.revision,
        });
        toast("Review closed.", "success");
        load();
      } catch (e) {
        toast(say(e));
      }
  });
  bind("#edit-review", async (fd) => {
    const questions = [...document.querySelectorAll(".question")].map((q) => ({
      text: q.querySelector("[name=qtext]").value,
      type: q.querySelector("[name=qtype]").value,
      required: q.querySelector("[name=qrequired]").checked,
      options: q
        .querySelector("[name=qoptions]")
        .value.split("\n")
        .map((x) => x.trim())
        .filter(Boolean),
    }));
    await api.updateReview({
      reviewId: id,
      expectedRevision: review.revision,
      title: fd.get("title"),
      description: fd.get("description"),
      maxResponses: Number(fd.get("maxResponses")),
      opensAt: fd.get("opensAt")
        ? new Date(fd.get("opensAt")).toISOString()
        : null,
      closesAt: fd.get("closesAt")
        ? new Date(fd.get("closesAt")).toISOString()
        : null,
      questions,
    });
    toast("Review draft saved.", "success");
    load();
  });
  document.querySelector("#add-question")?.addEventListener("click", () => {
    document
      .querySelector("#questions")
      .insertAdjacentHTML(
        "beforeend",
        questionHTML({ text: "", type: "text", required: false, options: [] }),
      );
  });
  document.querySelector("#questions")?.addEventListener("click", (e) => {
    if (e.target.matches("[data-remove]"))
      e.target.closest(".question").remove();
  });
  document.querySelector("#preview")?.addEventListener("click", () => {
    let f = document.querySelector("#edit-review"),
      data = new FormData(f),
      qs = [...document.querySelectorAll(".question")].map((q) => ({
        text: q.querySelector("[name=qtext]").value,
        type: q.querySelector("[name=qtype]").value,
        required: q.querySelector("[name=qrequired]").checked,
        options: q
          .querySelector("[name=qoptions]")
          .value.split("\n")
          .filter(Boolean),
      }));
    document.querySelector("#preview-area").innerHTML =
      `<div class="section-row"><h2 class="section-title">Preview</h2></div><div class="card response-card"><h2>${esc(data.get("title"))}</h2><p>${esc(data.get("description"))}</p>${qs.map((q) => `<div class="question-preview"><strong>${esc(q.text || "Question")}</strong><div>${q.type === "text" ? '<textarea aria-label="Answer preview" disabled></textarea>' : q.options.map((o) => `<label class="answer-option"><input type="${q.type === "multiple" ? "checkbox" : "radio"}" disabled> ${esc(o)}</label>`).join("")}</div></div>`).join("")}</div>`;
  });
  bindResponseExports(id);
}
function bindResponseExports(id) {
  for (const [fmt, idbtn] of [
    ["json", "export-json"],
    ["csv", "export-csv"],
  ])
    document.querySelector("#" + idbtn)?.addEventListener("click", async () => {
      try {
        const f = await api.exportResponses({ reviewId: id, format: fmt }),
          url = URL.createObjectURL(f.blob),
          a = document.createElement("a");
        a.href = url;
        a.download = f.filename;
        a.click();
        URL.revokeObjectURL(url);
        toast(`${fmt.toUpperCase()} export download started.`, "success");
      } catch (e) {
        toast(say(e));
      }
    });
}
function renderResponseResults(result, error, r) {
  if (error)
    return `<section class="card empty"><strong>Could not load responses</strong>Try again shortly.<button class="button secondary retry-button" id="retry-responses">Try again</button></section>`;
  if (!result)
    return `<section class="card form-card"><div class="skeleton" aria-label="Loading responses"></div></section>`;
  const items = Array.isArray(result.items) ? result.items : [],
    questions = r.questions || [];
  if (!items.length)
    return `<section class="card empty"><strong>No responses yet</strong>Submitted responses will appear here once they are available to review.</section>${result.next ? '<button class="button secondary load-more" id="load-more-responses">Load more responses</button>' : ""}<div class="toolbar export-toolbar"><button class="button secondary" id="export-json">Export JSON</button><button class="button secondary" id="export-csv">Export CSV</button></div>`;
  return `<div class="section-row"><div><h2 class="section-title">Responses</h2><p class="subtitle">${items.length} ${items.length === 1 ? "response" : "responses"} loaded${result.next ? " · more responses available" : ""}</p></div></div><div class="review-list">${items
    .map(
      (item, index) =>
        `<article class="card form-card response-content-card"><div class="question-top"><strong>Response ${index + 1}</strong><span class="help">${item.acceptedAt ? esc(formatReceiptTime(item.acceptedAt)) : ""}</span></div>${
          item.status === "invalid"
            ? '<p class="alert" role="status">This response could not be decrypted or validated.</p>'
            : questions
                .map((q) => {
                  const answer = (item.answers || []).find(
                      (a) => a.questionId === q.id,
                    ),
                    value = answer?.value;
                  return `<div class="question-preview"><strong>${esc(q.text || "Question")}</strong><p class="answer-copy">${value === undefined || value === null ? "No answer" : esc(Array.isArray(value) ? value.join(", ") : value)}</p></div>`;
                })
                .join("")
        }${(item.answers || [])
          .filter((a) => !questions.some((q) => q.id === a.questionId))
          .map(
            (a) =>
              `<div class="question-preview"><strong>Answer</strong><p class="answer-copy">${esc(Array.isArray(a.value) ? a.value.join(", ") : (a.value ?? ""))}</p></div>`,
          )
          .join("")}</article>`,
    )
    .join(
      "",
    )}</div>${result.next ? '<button class="button secondary load-more" id="load-more-responses">Load more responses</button>' : ""}<div class="toolbar export-toolbar"><button class="button secondary" id="export-json">Export JSON</button><button class="button secondary" id="export-csv">Export CSV</button></div>`;
}
function questionHTML(q = {}) {
  return `<div class="question"><div class="question-top"><strong>Question</strong><button class="icon-btn" type="button" data-remove aria-label="Remove question">${icon("trash-2")}</button></div><div class="field"><label>Question text</label><input name="qtext" required maxlength="500" value="${esc(q.text)}"></div><div class="inline"><div class="field"><label>Answer type</label><select name="qtype"><option value="text" ${q.type === "text" ? "selected" : ""}>Text</option><option value="single" ${q.type === "single" ? "selected" : ""}>Choose one</option><option value="multiple" ${q.type === "multiple" ? "selected" : ""}>Choose multiple</option></select></div><label class="check"><input name="qrequired" type="checkbox" ${q.required ? "checked" : ""}> Required</label></div><div class="field"><label>Choices <span class="help">(one per line, for choice questions)</span></label><textarea name="qoptions">${esc((q.options || []).join("\n"))}</textarea></div></div>`;
}
function dt(v) {
  if (!v) return "";
  let d = new Date(v);
  return isNaN(d)
    ? ""
    : new Date(d.getTime() - d.getTimezoneOffset() * 60000)
        .toISOString()
        .slice(0, 16);
}
async function renderRespond(id) {
  let r;
  try {
    r = await api.getReview({ reviewId: id });
  } catch (e) {
    frame(
      `${head("This review is unavailable", "We couldn’t load this review. Try again shortly.")}`,
      "Respond",
    );
    toast(say(e));
    return;
  }
  if (r.contentState === "locked" || !Array.isArray(r.questions)) {
    frame(
      emptyCard(
        "This invitation could not be read",
        "This review’s content is locked or could not be verified for this membership.",
      ),
      "Respond",
    );
    return;
  }
  const questions = r.questions || [];
  frame(
    `<section class="card response-card"><p class="eyebrow">ANONYMOUS FEEDBACK</p><h1>${esc(r.title || "Share your thoughts")}</h1><p class="subtitle">${esc(r.description || "Your thoughtful answer can help make things better.")}</p><div class="alert">Your response is submitted without account credentials. Availability follows review status and limits.</div><form id="respond">${questions.map((q, i) => `<fieldset class="question-preview answer-group"><legend class="label">${esc(q.text)}${q.required ? ' <span aria-label="required">*</span>' : ""}</legend>${q.type === "text" ? `<textarea id="answer-${i}" name="q-${i}" aria-label="${esc(q.text)}" ${q.required ? "required" : ""} maxlength="5000"></textarea>` : (q.options || []).map((o, j) => `<label class="answer-option"><input name="q-${i}" type="${q.type === "multiple" ? "checkbox" : "radio"}" value="${esc(o)}" ${q.required && q.type === "single" && j === 0 ? "required" : ""}> ${esc(o)}</label>`).join("")}</fieldset>`).join("")}<p class="form-error"></p><button class="button" type="submit">Send response</button></form><div id="receipt"></div><p class="footnote">Anonce cannot prevent network or timing correlation. Avoid identifying details in answers.</p></section>`,
    "Respond",
  );
  document.querySelectorAll("#respond input[type=checkbox]").forEach((input) =>
    input.addEventListener("change", () => {
      const group = document.querySelectorAll(
        `#respond input[name="${input.name}"]`,
      );
      group[0]?.setCustomValidity(
        [...group].some((x) => x.checked) ? "" : "Choose at least one answer.",
      );
    }),
  );
  document.querySelector("#respond").addEventListener("submit", (e) => {
    for (const q of questions) {
      if (q.required && q.type === "multiple") {
        const group = [
          ...document.querySelectorAll(
            `#respond input[name="q-${questions.indexOf(q)}"]`,
          ),
        ];
        group[0]?.setCustomValidity(
          group.some((x) => x.checked) ? "" : "Choose at least one answer.",
        );
      }
    }
    if (!e.currentTarget.reportValidity()) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  });
  bind("#respond", async (fd) => {
    const answers = questions.map((q, i) => ({
      questionId: q.id,
      index: i,
      value: q.type === "multiple" ? fd.getAll(`q-${i}`) : fd.get(`q-${i}`),
    }));
    let p = await api.prepareResponse({
      reviewId: id,
      answers,
    });
    let result = await api.submitResponse({ pendingId: p.pendingId });
    const box = document.querySelector("#receipt");
    if (result.status === "pending") {
      const pendingId = result.pendingId || p.pendingId;
      box.innerHTML = `<div class="alert"><p>Your response is still processing. You can return to this signed-in browser later and check its status.</p><p><button type="button" class="button secondary" id="retry">Check status</button> <span id="pending-state" role="status"></span></p></div>`;
      renderButtonIcons(box);
      document.querySelector("#respond").classList.add("hidden");
      document.querySelector("#retry").onclick = async () => {
        const btn = document.querySelector("#retry"),
          state = document.querySelector("#pending-state");
        btn.disabled = true;
        try {
          let x = await api.lookupReceipt({ pendingId });
          if (x.status !== "accepted")
            x = await api.submitResponse({ pendingId });
          if (x.status === "accepted") {
            box.innerHTML = receiptHTML(x.receipt);
            renderButtonIcons(box);
            bindReceiptTools(box, x.receipt);
          } else
            state.textContent =
              "Still processing. You can check again shortly.";
        } catch (e) {
          toast(say(e));
        } finally {
          if (document.querySelector("#retry"))
            document.querySelector("#retry").disabled = false;
        }
      };
    } else {
      document.querySelector("#respond").classList.add("hidden");
      box.innerHTML = receiptHTML(result.receipt);
      renderButtonIcons(box);
      bindReceiptTools(box, result.receipt);
    }
  });
}
load();
