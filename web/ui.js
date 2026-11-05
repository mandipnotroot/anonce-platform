// SPDX-License-Identifier: AGPL-3.0-only
import * as api from "./app.js";

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
  reviewPageError = "",
  busy = false;
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const path = () =>
  location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
const go = (p) => {
  location.hash = "/" + String(p).replace(/^\/+/, "");
};
const say = (e) => e?.message || "Something went wrong. Please try again.";
function icon(name) {
  return `<img class="icon" src="./assets/icons/${name}.svg" alt="" aria-hidden="true">`;
}
function frame(body, title = "Workspace") {
  root.setAttribute("aria-busy", "false");
  const sourceURL = esc(api.getSourceURL());
  const sourceLink = `<a class="source-link" href="${sourceURL}" target="_blank" rel="noopener noreferrer">${icon("arrow-up-right")} Source code</a>`;
  root.innerHTML = `<a class="skip-link" href="#main-content">Skip to main content</a><div class="shell"><aside class="side"><a class="brand" href="#/"><span class="brand-mark" aria-hidden="true">A</span> Anonce</a><div class="nav-label">Workspace</div><nav class="nav" aria-label="Workspace"><a href="#/" class="${path().length === 0 ? "active" : ""}">${icon("house")}<span>Overview</span></a><a href="#/orgs" class="${path()[0] === "orgs" ? "active" : ""}">${icon("building-2")}<span>Organizations</span></a><a href="#/account" class="${path()[0] === "account" ? "active" : ""}">${icon("user-round")}<span>Account &amp; recovery</span></a></nav><div class="side-bottom"><p class="privacy-note">Responses are designed to be anonymous. See your organization’s privacy policy for its trust assumptions.</p>${sourceLink}<div class="user-chip"><div class="avatar">${session ? esc((session.login || "A").slice(0, 1).toUpperCase()) : "A"}</div><div><div class="user-name">${session ? esc(session.login || "Member") : "Your workspace"}</div><div class="user-state">${session ? "Signed in" : "Private feedback"}</div></div></div></div></aside><main class="main" id="main-content" tabindex="-1"><header class="topbar"><div class="crumb">Anonce <span aria-hidden="true">/</span> ${esc(title)}</div><div class="top-actions">${session ? '<a href="#/account" class="top-link">Account</a>' : '<a href="#/login" class="top-link">Sign in</a>'}</div></header><div class="content">${body}</div></main><nav class="mobile-head" aria-label="Main navigation"><a href="#/">${icon("house")}<span class="mobile-label">Home</span></a><a href="#/orgs">${icon("building-2")}<span class="mobile-label">Teams</span></a><a href="#/account">${icon("user-round")}<span class="mobile-label">Account</span></a>${sourceLink}</nav></div>`;
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
function button(label, href, cls = "") {
  return `<a class="button ${cls}" href="#/${href}">${esc(label)}</a>`;
}
function errorBox(message) {
  return `<p class="form-error" role="alert">${esc(message)}</p>`;
}
function recoveryPhrasePanel(words, prefix = "recovery") {
  return `<div class="word-grid">${words.map((w, i) => `<div class="word"><b>${String(i + 1).padStart(2, "0")}</b>${esc(w)}</div>`).join("")}</div><div class="recovery-actions"><button id="${prefix}-copy" class="button secondary" type="button">Copy phrase</button><button id="${prefix}-download" class="button secondary" type="button">Download .txt</button><span id="${prefix}-feedback" role="status" aria-live="polite"></span></div>`;
}
function bindRecoveryPhraseTools(words, prefix = "recovery") {
  const phraseText = words.join(" ");
  const copyButton = document.querySelector(`#${prefix}-copy`);
  const downloadButton = document.querySelector(`#${prefix}-download`);
  const feedback = document.querySelector(`#${prefix}-feedback`);
  copyButton.onclick = async () => {
    if (!copyButton.isConnected || phrase !== words) return;
    try {
      await navigator.clipboard.writeText(phraseText);
      if (copyButton.isConnected && phrase === words) feedback.textContent = "Phrase copied.";
    } catch {
      if (copyButton.isConnected && phrase === words) feedback.textContent = "Copy failed. Select and copy the words above.";
    }
  };
  downloadButton.onclick = () => {
    if (!downloadButton.isConnected || phrase !== words) return;
    const blob = new Blob([`${phraseText}\n`], { type: "text/plain;charset=utf-8" });
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
    feedback.textContent = "Text file downloaded.";
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
      b.textContent = "Please wait…";
    }
    try {
      await fn(new FormData(form), form);
    } catch (err) {
      let box = form.querySelector(".form-error");
      if (box) box.textContent = say(err);
      else form.insertAdjacentHTML("afterbegin", errorBox(say(err)));
    } finally {
      busy = false;
      if (b) {
        b.disabled = false;
        b.textContent = b.dataset.old;
      }
    }
  });
}
async function load() {
  try {
    session = await api.getSession();
  } catch {
    session = null;
  }
  const route = path();
  if (!session && (route[0] === "respond" || route[0] === "invite"))
    returnRoute = `/${route[0]}/${encodeURIComponent(route[1] || "")}`;
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
  if (route[0] === "respond") {
    renderRespond(route[1]);
    return;
  }
  let organizationError = "";
  try {
    orgs = (await api.listOrganizations()).items;
  } catch (e) {
    orgs = [];
    organizationError = say(e);
  }
  currentOrg = orgs.find((o) => o.id === currentOrg?.id) || orgs[0] || null;
  const p = path();
  if (p[0] === "invite" && p[1]) {
    frame(
      `${head("You’re invited", "Accept this invitation to join an organization.")}<section class="card form-card"><p class="form-error" id="invite-error"></p><button class="button" id="accept-invite">Accept invitation</button></section>`,
      "Invitation",
    );
    document.querySelector("#accept-invite").onclick = async () => {
      try {
        await api.acceptInvite({ token: p[1] });
        go("/orgs");
        load();
      } catch (e) {
        document.querySelector("#invite-error").textContent = say(e);
      }
    };
    return;
  }
  if (p[0] === "account") return renderAccount();
  if (p[0] === "orgs") return renderOrgs();
  if (p[0] === "review" && p[1]) return renderReview(p[1], p[2]);
  if (organizationError) {
    frame(
      `${head("Organizations unavailable", organizationError)}`,
      "Overview",
    );
    return;
  }
  if (!currentOrg) {
    frame(
      `${head("A thoughtful space for feedback", "Start by creating an organization, then invite the people who can review responses.")}${emptyCard("No organization yet", "Create an organization to build your first anonymous review.", button("Create organization", "orgs"))}`,
      "Overview",
    );
    return;
  }
  try {
    const result = await api.listReviews({ orgId: currentOrg.id });
    reviews = result.items;
    reviewNext = result.next;
    reviewPageError = "";
    try {
      pendingResponses = (await api.listPendingResponses()).items;
    } catch (e) {
      pendingResponses = null;
    }
    renderHome();
  } catch (e) {
    frame(`${head("Reviews unavailable", say(e))}`, "Overview");
  }
}
function emptyCard(t, d, act = "") {
  return `<section class="card empty"><strong>${esc(t)}</strong>${esc(d)}<div class="empty-action">${act}</div></section>`;
}
function renderHome() {
  frame(
    `${head("Overview", `Workspace for ${currentOrg.name || "your organization"}.`, button("New review", "review/new"))}${renderPendingResponses()}<div class="stat-grid"><div class="card stat"><div class="stat-label">${reviewNext ? "Reviews shown" : "Reviews"}</div><div class="stat-value">${reviews.length}</div></div><div class="card stat"><div class="stat-label">Accepted responses</div><div class="stat-value">${aggregateCount("accepted_count")}</div></div><div class="card stat"><div class="stat-label">Issued authorizations</div><div class="stat-value">${aggregateCount("issued_count")}</div></div></div><div class="section-row"><h2 class="section-title" id="reviews-heading" tabindex="-1">Your reviews</h2><a class="top-link" href="#/orgs">Manage organization</a></div>${
      reviews.length
        ? `<div class="review-list">${reviews
            .map((r) => {
              const mine = isReviewOwner(r);
              const accepted = countText(r.accepted_count);
              const issued = countText(r.issued_count);
              return `<article class="card review-row"><span class="review-dot"></span><div class="review-info"><strong>${esc(r.title || "Untitled review")}</strong><small>${esc(r.status || "Draft")} · <span aria-label="Accepted responses">${accepted} accepted</span> · <span aria-label="Issued authorizations">${issued} issued</span></small></div>${mine ? button("Manage", `review/${encodeURIComponent(r.id)}`, "secondary small") : r.status === "published" ? button("Respond", `respond/${encodeURIComponent(r.id)}`, "secondary small") : ""}</article>`;
            })
            .join(
              "",
            )}</div>${reviewNext ? `<button class="button secondary load-more" id="load-more-reviews">Load more reviews</button>` : ""}${reviewPageError ? errorBox(reviewPageError) : ""}`
        : emptyCard(
            "Nothing here yet",
            "Your reviews will appear here once you create one.",
            button("Create your first review", "review/new"),
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
  button.disabled = true;
  button.textContent = "Loading…";
  try {
    const result = await api.listReviews({
      orgId: currentOrg.id,
      after: reviewNext,
    });
    reviews = [...reviews, ...result.items];
    reviewNext = result.next;
    reviewPageError = "";
    renderHome();
    (
      document.querySelector("#load-more-reviews") ||
      document.querySelector("#reviews-heading")
    )?.focus();
  } catch (error) {
    reviewPageError = say(error);
    renderHome();
  }
}
function countText(value) {
  if (typeof value === "string" && /^(0|[1-9]\d*)$/.test(value))
    return value;
  return Number.isSafeInteger(value) && value >= 0
    ? String(value)
    : "Unavailable";
}
function aggregateCount(key) {
  if (reviewNext) return "Unavailable";
  let total = 0n;
  for (const row of reviews) {
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
  const accountId = session?.account_id || session?.accountId;
  return Boolean(
    accountId && r.creator_account_id && accountId === r.creator_account_id,
  );
}
function renderPendingResponses() {
  if (pendingResponses === null)
    return `<section class="card empty" role="status"><strong>Pending responses unavailable</strong>We couldn’t check saved submissions right now.</section>`;
  if (!pendingResponses.length) return "";
  return `<section class="section-row"><h2 class="section-title">Responses to finish</h2></section><div class="review-list">${pendingResponses.map((item) => `<article class="card review-row"><div class="review-info"><strong>${esc(item.title || "Anonymous response")}</strong><small>Submission still processing</small></div><button class="button secondary small" data-pending="${esc(item.pendingId)}">Check status</button></article>`).join("")}</div><p class="form-error" id="pending-error" role="status"></p>`;
}
async function resumePending(pendingId, button) {
  const old = button.textContent;
  button.disabled = true;
  button.textContent = "Checking…";
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
      button.textContent = "Still processing";
      setTimeout(() => {
        if (button.isConnected) {
          button.disabled = false;
          button.textContent = old;
        }
      }, 1800);
    }
  } catch (e) {
    const error = document.querySelector("#pending-error");
    if (error) error.textContent = say(e);
    button.textContent = old;
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
      ? `<form id="auth" class="form-card auth-inner-form"><div class="field"><label for="login">Login</label><input id="login" name="login" required autocomplete="username"></div><div class="field"><label for="words">12-word recovery phrase</label><textarea id="words" name="words" required autocomplete="off" placeholder="Enter all 12 words in order"></textarea></div><div class="field"><label for="password">New password</label><input id="password" name="newPassword" type="password" minlength="12" required autocomplete="new-password"><p class="help">Use at least 12 characters.</p></div><p class="form-error"></p><button class="button" type="submit">Recover account</button></form>`
      : `<form id="auth" class="form-card auth-inner-form"><div class="field"><label for="login">Login</label><input id="login" name="login" required autocomplete="username"></div><div class="field"><label for="password">Password</label><input id="password" name="password" type="password" minlength="12" required autocomplete="${mode === "register" ? "new-password" : "current-password"}"></div><p class="form-error"></p><button class="button" type="submit">${mode === "register" ? "Create account" : "Sign in"}</button></form>`;
  frame(
    `<div class="auth-wrap"><section class="card auth-card">${words ? `<p class="eyebrow">SAVE THIS ONCE</p><h1>Your recovery phrase</h1><p>Write these 12 words down and keep them somewhere private. They will not be shown again.</p><div class="alert"><strong>Keep it secret.</strong> Anyone with this phrase may be able to recover your account. Copies and downloaded files are sensitive recovery credentials.</div>${recoveryPhrasePanel(words)}<label class="check"><input id="saved" type="checkbox"> I have saved my 12-word phrase somewhere safe.</label><button id="continue" class="button" disabled>Continue to Anonce</button>` : `<h1>${title}</h1><p>${intent === "respond" ? "Sign in first to continue to this anonymous response form." : intent === "invite" ? "Sign in to accept your organization invitation." : mode === "register" ? "Create a secure account to take part in trusted feedback spaces." : "Sign in to manage feedback and your organization."}</p>${body}<div class="divider"></div><p class="help">${mode === "register" ? `Already have an account? <a href="#/login">Sign in</a>` : `New to Anonce? <a href="#/register">Create an account</a> · <a href="#/recover">Recover account</a>`}</p>`}</section></div>`,
    title,
  );
  if (words) {
    bindRecoveryPhraseTools(words);
    document.querySelector("#saved").onchange = (e) =>
      (document.querySelector("#continue").disabled = !e.target.checked);
    document.querySelector("#continue").onclick = () => {
      phrase = null;
      const destination = returnRoute || "/";
      returnRoute = null;
      go(destination);
      load();
    };
    return;
  }
  bind("#auth", async (fd) => {
    if (mode === "register") {
      let result = await api.register({
        login: fd.get("login"),
        password: fd.get("password"),
      });
      phrase = result.recoveryWords;
      session = result.session;
      renderAuth("register");
    } else if (mode === "recover") {
      const result = await api.recover({
        login: fd.get("login"),
        words: fd.get("words"),
        newPassword: fd.get("newPassword"),
      });
      phrase = result.recoveryWords;
      session = result.session;
      renderAuth("recover");
    } else {
      session = await api.login({
        login: fd.get("login"),
        password: fd.get("password"),
      });
      const destination = returnRoute || "/";
      returnRoute = null;
      go(destination);
    }
  });
}
function renderOrgs() {
  frame(
    `${head("Organizations", "Manage your teams, memberships, and invitations.", `<button class="button" id="new-org">New organization</button>`)}<div class="card">${orgs.length ? orgs.map((o) => `<div class="review-row"><div class="avatar">${esc((o.name || "O")[0])}</div><div class="review-info"><strong>${esc(o.name)}</strong><small>${esc(o.role || "Member")} · ${o.status === "pending" ? "Approval pending" : "Organization"}</small></div><button class="button secondary small" data-org="${esc(o.id)}">Open</button></div>`).join("") : emptyCard("Your people, together", "Organizations bring verified members into one trusted space.")}</div><div id="org-form" class="card form-card hidden org-form-spaced"><form id="create-org"><div class="field"><label for="orgname">Organization name</label><input id="orgname" name="name" required maxlength="100"></div><p class="form-error"></p><button class="button" type="submit">Create organization</button></form></div>${currentOrg ? `<div class="section-row"><h2 class="section-title">${esc(currentOrg.name)} · members</h2><button class="button secondary small" id="invite-toggle">Invite a member</button></div><div id="member-area" class="card empty">Loading membership…</div><div id="invite-area" class="card form-card hidden"><form id="invite"><div class="inline"><div class="field"><label>Role</label><select name="role"><option value="reviewer">Reviewer</option><option value="respondent">Respondent</option></select></div><div class="field"><label>Invite expires</label><input name="expiresAt" type="datetime-local" required></div></div><p class="form-error"></p><button class="button" type="submit">Create invite</button><div id="invite-result"></div></form></div>` : ""}`,
    "Organizations",
  );
  document.querySelector("#new-org").onclick = () =>
    document.querySelector("#org-form").classList.toggle("hidden");
  document.querySelector("#create-org") &&
    bind("#create-org", async (fd) => {
      await api.createOrganization({ name: fd.get("name") });
      load();
    });
  document.querySelectorAll("[data-org]").forEach(
    (b) =>
      (b.onclick = () => {
        currentOrg = orgs.find((o) => o.id === b.dataset.org);
        renderOrgs();
      }),
  );
  if (currentOrg) {
    document.querySelector("#invite-toggle").onclick = () =>
      document.querySelector("#invite-area").classList.toggle("hidden");
    bind("#invite", async (fd) => {
      const expiresAt = new Date(fd.get("expiresAt")).toISOString(),
        r = await api.createInvite({
          orgId: currentOrg.id,
          role: fd.get("role"),
          expiresAt,
        });
      document.querySelector("#invite-result").innerHTML =
        `<div class="notice">Invite created. Share this link with the member:<div class="share-box"><input readonly value="${esc(location.origin + location.pathname + "#/invite/" + r.token)}" aria-label="Invitation link"><button class="button small" type="button" id="copy">Copy</button></div></div>`;
      document.querySelector("#copy").onclick = () =>
        navigator.clipboard?.writeText(
          location.origin + location.pathname + "#/invite/" + r.token,
        );
    });
    loadMembers();
  }
}
async function loadMembers() {
  let box = document.querySelector("#member-area");
  try {
    const rows = (await api.listMembers({ orgId: currentOrg.id })).items;
    box.innerHTML = rows.length
      ? `<div class="table-wrap"><table class="simple-table"><thead><tr><th>Member</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows.map((m) => `<tr><td>${esc(m.login || m.memberId || "Member")}</td><td>${esc(m.role || "Member")}</td><td>${esc(m.status || "Active")}</td><td>${m.status === "pending" ? `<button class="button small" data-approve="${esc(m.id || m.memberId)}">Approve</button>` : ""}<button class="button danger small" data-revoke="${esc(m.id || m.memberId)}">Revoke</button></td></tr>`).join("")}</tbody></table></div>`
      : emptyCard(
          "No members yet",
          "Invites and membership approvals will appear here.",
        );
    box.querySelectorAll("[data-approve]").forEach(
      (b) =>
        (b.onclick = async () => {
          try {
            await api.approveMember({
              orgId: currentOrg.id,
              memberId: b.dataset.approve,
            });
            loadMembers();
          } catch (e) {
            alert(say(e));
          }
        }),
    );
    box.querySelectorAll("[data-revoke]").forEach(
      (b) =>
        (b.onclick = async () => {
          if (confirm("Revoke this membership?"))
            try {
              await api.revokeMember({
                orgId: currentOrg.id,
                memberId: b.dataset.revoke,
              });
              loadMembers();
            } catch (e) {
              alert(say(e));
            }
        }),
    );
  } catch (e) {
    box.textContent = say(e);
  }
}
async function renderAccount() {
  frame(
    `${head("Account & recovery", "Update your password, rotate recovery access, or sign out.")}<section class="card form-card"><h2 class="section-title">Change password</h2><form id="password" class="form-spaced"><div class="field"><label>Current password</label><input type="password" name="currentPassword" required autocomplete="current-password"></div><div class="field"><label>New password</label><input type="password" name="newPassword" minlength="12" required autocomplete="new-password"></div><p class="form-error"></p><button class="button" type="submit">Update password</button></form><div class="divider"></div><h2 class="section-title">Recovery phrase</h2><p class="subtitle">Create a replacement phrase. Your old recovery phrase will no longer work.</p><form id="rotate" class="form-spaced"><div class="field"><label>Confirm with current password</label><input type="password" name="currentPassword" required autocomplete="current-password"></div><p class="form-error"></p><button class="button secondary" type="submit">Rotate recovery phrase</button></form><div id="new-phrase"></div><div class="divider"></div><button id="logout" class="button ghost">Sign out</button></section>`,
    "Account",
  );
  bind("#password", async (fd) => {
    await api.changePassword({
      currentPassword: fd.get("currentPassword"),
      newPassword: fd.get("newPassword"),
    });
    document.querySelector("#password").reset();
    document.querySelector("#password .form-error").textContent =
      "Password updated.";
  });
  bind("#rotate", async (fd) => {
    const r = await api.rotateRecovery({
      currentPassword: fd.get("currentPassword"),
    });
    phrase = r.recoveryWords;
    document.querySelector("#new-phrase").innerHTML =
      `<div class="alert"><strong>Save your new phrase now.</strong> The old phrase is replaced. Copies and downloaded files are sensitive recovery credentials.</div>${recoveryPhrasePanel(phrase, "rotated-recovery")}<label class="check"><input id="rotated-saved" type="checkbox"> I saved the new phrase</label>`;
    bindRecoveryPhraseTools(phrase, "rotated-recovery");
    document.querySelector("#rotated-saved").onchange = (e) => {
        if (e.target.checked && e.target.isConnected && phrase) {
        phrase = null;
        document.querySelector("#new-phrase").innerHTML =
          '<div class="notice">Recovery phrase updated.</div>';
      }
    };
  });
  document.querySelector("#logout").onclick = async () => {
    await api.logout();
    session = null;
    go("/login");
  };
}
async function renderReview(id, tab) {
  if (id === "new") {
    frame(
      `${head("Start a new review", "Set up the basics. You can add questions and preview before publishing.")}<section class="card form-card"><form id="new-review"><div class="field"><label>Review title</label><input name="title" required maxlength="160" placeholder="What would you like to learn?"></div><div class="field"><label>Responses per member</label><input name="maxResponses" type="number" min="1" value="1" required></div><p class="form-error"></p><button class="button" type="submit">Create draft</button></form></section>`,
      "New review",
    );
    bind("#new-review", async (fd) => {
      let r = await api.createReview({
        orgId: currentOrg.id,
        title: fd.get("title"),
        maxResponses: Number(fd.get("maxResponses")),
      });
      go(`/review/${encodeURIComponent(r.id)}/edit`);
    });
    return;
  }
  try {
    review = await api.getReview({ reviewId: id });
  } catch (e) {
    frame(
      `${head("Review unavailable", say(e))}${button("Back to reviews", "", "secondary")}`,
      "Review",
    );
    return;
  }
  const canManage = isReviewOwner(review);
  const canReviewResponses = canManage || currentOrg?.role === "reviewer";
  if (!canManage && !canReviewResponses) {
    if (review.status === "published" || review.status === "open") {
      go(`/respond/${encodeURIComponent(id)}`);
      renderRespond(id);
    } else {
      frame(
        `${head("Review not available", "Only the person who created this draft can manage it.")}${button("Back to workspace", "", "secondary")}`,
        "Review",
      );
    }
    return;
  }
  let status = review.status || "draft";
  let responseResult = null,
    responseError = "";
  if (tab === "results") {
    try {
      responseResult = await api.listResponses({ reviewId: id });
    } catch (e) {
      responseError = say(e);
    }
  }
  frame(
    `${head(review.title || "Untitled review", `${status} · ${review.revision !== undefined ? "Revision " + review.revision : "Review workspace"}`, `<div class="toolbar">${canManage ? (status === "draft" ? '<button class="button" id="publish">Publish review</button>' : '<button class="button secondary" id="close">Close review</button>') : ""}${canManage ? '<button class="button secondary" id="share">Share</button>' : ""}</div>`)}<div class="tabs">${canManage ? `<a href="#/review/${encodeURIComponent(id)}/edit" class="${tab === "edit" ? "active" : ""}">Build</a>` : ""}${canReviewResponses ? `<a href="#/review/${encodeURIComponent(id)}/results" class="${tab === "results" ? "active" : ""}">Responses</a>` : ""}</div>${tab === "results" && canReviewResponses ? `<div id="response-results" aria-live="polite" tabindex="-1">${renderResponseResults(responseResult, responseError, review)}</div>` : canManage ? `<section class="card form-card"><form id="edit-review"><div class="field"><label>Title</label><input name="title" required maxlength="160" value="${esc(review.title)}"></div><div class="field"><label>Description</label><textarea name="description" maxlength="2000">${esc(review.description)}</textarea></div><div class="field"><label>Responses per member</label><input name="maxResponses" type="number" min="1" value="${esc(review.maxResponses || 1)}" required></div><div class="inline"><div class="field"><label>Opens</label><input type="datetime-local" name="opensAt" value="${dt(review.opensAt)}"></div><div class="field"><label>Closes</label><input type="datetime-local" name="closesAt" value="${dt(review.closesAt)}"></div></div><div class="section-row"><h2 class="section-title">Questions</h2><button type="button" class="button secondary small" id="add-question">Add question</button></div><div id="questions">${(review.questions || []).map(questionHTML).join("")}</div><p class="form-error"></p><div class="toolbar"><button class="button" type="submit">Save draft</button><button class="button secondary" type="button" id="preview">Preview</button></div></form></section><div id="preview-area"></div><div class="footnote">Draft changes are saved to this review only when you select Save draft.</div>` : `<section class="card empty"><strong>Not authorized</strong>Your organization role does not allow response review.</section>`}`,
    "Review",
  );
  document
    .querySelector("#retry-responses")
    ?.addEventListener("click", () => renderReview(id, "results"));
  const loadMoreResponses = async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = "Loading…";
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
      const error = document.querySelector("#response-page-error");
      if (error) error.textContent = say(e);
      button.disabled = false;
      button.textContent = "Load more responses";
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
      load();
    } catch (e) {
      alert(say(e));
    }
  });
  document.querySelector("#close")?.addEventListener("click", async () => {
    if (confirm("Close this review to new responses?"))
      try {
        await api.closeReview({
          reviewId: id,
          expectedRevision: review.revision,
        });
        load();
      } catch (e) {
        alert(say(e));
      }
  });
  document.querySelector("#share")?.addEventListener("click", () => {
    const url =
      location.origin +
      location.pathname +
      "#/respond/" +
      encodeURIComponent(id);
    navigator.clipboard?.writeText(url);
    alert("Response link copied when clipboard access is available. " + url);
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
      } catch (e) {
        document.querySelector("#export-error").textContent = say(e);
      }
    });
}
function renderResponseResults(result, error, r) {
  if (error)
    return `<section class="card empty" role="alert"><strong>Could not load responses</strong>${esc(error)}<button class="button secondary retry-button" id="retry-responses">Try again</button></section>`;
  if (!result)
    return `<section class="card form-card"><div class="skeleton" aria-label="Loading responses"></div></section>`;
  const items = Array.isArray(result.items) ? result.items : [],
    questions = r.questions || [];
  if (!items.length)
    return `<section class="card empty"><strong>No responses yet</strong>Submitted responses will appear here once they are available to review.</section>${result.next ? '<button class="button secondary load-more" id="load-more-responses">Load more responses</button><p class="form-error" id="response-page-error" role="status"></p>' : ""}<div class="toolbar export-toolbar"><button class="button secondary" id="export-json">Export JSON</button><button class="button secondary" id="export-csv">Export CSV</button></div><p class="form-error" id="export-error"></p>`;
  return `<div class="section-row"><div><h2 class="section-title">Responses</h2><p class="subtitle">${items.length} ${items.length === 1 ? "response" : "responses"} loaded${result.next ? " · more responses available" : ""}</p></div></div><div class="review-list">${items
    .map(
      (item, index) =>
        `<article class="card form-card response-content-card"><div class="question-top"><strong>Response ${index + 1}</strong><span class="help">${item.acceptedAt ? esc(new Date(item.acceptedAt).toLocaleString()) : ""}</span></div>${item.status === "invalid" ? '<p class="alert" role="status">This response could not be decrypted or validated.</p>' : questions
          .map((q) => {
            const answer = (item.answers || []).find(
                (a) => a.questionId === q.id,
              ),
              value = answer?.value;
            return `<div class="question-preview"><strong>${esc(q.text || "Question")}</strong><p class="answer-copy">${value === undefined || value === null ? "No answer" : esc(Array.isArray(value) ? value.join(", ") : value)}</p></div>`;
          })
          .join("")}${(item.answers || [])
          .filter((a) => !questions.some((q) => q.id === a.questionId))
          .map(
            (a) =>
              `<div class="question-preview"><strong>Answer</strong><p class="answer-copy">${esc(Array.isArray(a.value) ? a.value.join(", ") : (a.value ?? ""))}</p></div>`,
          )
          .join("")}</article>`,
    )
    .join(
      "",
    )}</div>${result.next ? '<button class="button secondary load-more" id="load-more-responses">Load more responses</button><p class="form-error" id="response-page-error" role="status"></p>' : ""}<div class="toolbar export-toolbar"><button class="button secondary" id="export-json">Export JSON</button><button class="button secondary" id="export-csv">Export CSV</button></div><p class="form-error" id="export-error"></p>`;
}
function questionHTML(q = {}) {
  return `<div class="question"><div class="question-top"><strong>Question</strong><button class="icon-btn" type="button" data-remove aria-label="Remove question">×</button></div><div class="field"><label>Question text</label><input name="qtext" required maxlength="500" value="${esc(q.text)}"></div><div class="inline"><div class="field"><label>Answer type</label><select name="qtype"><option value="text" ${q.type === "text" ? "selected" : ""}>Text</option><option value="single" ${q.type === "single" ? "selected" : ""}>Choose one</option><option value="multiple" ${q.type === "multiple" ? "selected" : ""}>Choose multiple</option></select></div><label class="check"><input name="qrequired" type="checkbox" ${q.required ? "checked" : ""}> Required</label></div><div class="field"><label>Choices <span class="help">(one per line, for choice questions)</span></label><textarea name="qoptions">${esc((q.options || []).join("\n"))}</textarea></div></div>`;
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
  if (!id) {
    frame(
      emptyCard(
        "Link not complete",
        "Ask the person who shared this review for a complete response link.",
      ),
      "Respond",
    );
    return;
  }
  let r;
  try {
    r = await api.getReview({ reviewId: id });
  } catch (e) {
    frame(`${head("This review is unavailable", say(e))}`, "Respond");
    return;
  }
  const questions = r.questions || [];
  frame(
    `<section class="card response-card"><p class="eyebrow">ANONYMOUS FEEDBACK</p><h1>${esc(r.title || "Share your thoughts")}</h1><p class="subtitle">${esc(r.description || "Your thoughtful answer can help make things better.")}</p><div class="alert">Your response is submitted without your account credentials. Submission availability depends on the review status and limits.</div><form id="respond">${questions.map((q, i) => `<fieldset class="question-preview answer-group"><legend class="label">${esc(q.text)}${q.required ? ' <span aria-label="required">*</span>' : ""}</legend>${q.type === "text" ? `<textarea id="answer-${i}" name="q-${i}" aria-label="${esc(q.text)}" ${q.required ? "required" : ""} maxlength="5000"></textarea>` : (q.options || []).map((o, j) => `<label class="answer-option"><input name="q-${i}" type="${q.type === "multiple" ? "checkbox" : "radio"}" value="${esc(o)}" ${q.required && q.type === "single" && j === 0 ? "required" : ""}> ${esc(o)}</label>`).join("")}</fieldset>`).join("")}<p class="form-error"></p><button class="button" type="submit">Send response</button></form><div id="receipt"></div><p class="footnote">Anonce does not claim protection from network or timing correlation. Please avoid identifying details in your answers.</p></section>`,
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
    let p = await api.prepareResponse({ reviewId: id, answers });
    let result = await api.submitResponse({ pendingId: p.pendingId });
    const box = document.querySelector("#receipt");
    if (result.status === "pending") {
      const pendingId = result.pendingId || p.pendingId;
      box.innerHTML = `<div class="alert">Your response is still processing. Keep this page open and use the button to check again.<p><button type="button" class="button secondary" id="retry">Check status</button> <span id="pending-state"></span></p></div>`;
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
            box.innerHTML = `<div class="notice">Response accepted. Receipt: <strong>${esc(x.receipt)}</strong></div>`;
          } else
            state.textContent =
              "Still processing. You can check again shortly.";
        } catch (e) {
          state.textContent = say(e);
        } finally {
          if (document.querySelector("#retry"))
            document.querySelector("#retry").disabled = false;
        }
      };
    } else {
      document.querySelector("#respond").classList.add("hidden");
      box.innerHTML = `<div class="notice"><strong>Response accepted.</strong> Save this receipt for your records.<p>${esc(result.receipt)}</p></div>`;
    }
  });
}
window.addEventListener("hashchange", load);
load();
