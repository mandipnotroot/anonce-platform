// SPDX-License-Identifier: AGPL-3.0-only
// Opt-in real-browser integration test; targets an already-running HTTPS service.
// Install Playwright in the test environment, not the production dependency set.
import assert from "node:assert/strict";
const origin = process.env.ANONCE_E2E_ORIGIN;
if (!origin)
  throw new Error("Set ANONCE_E2E_ORIGIN to a disposable HTTPS deployment.");
if (!origin.startsWith("https://"))
  throw new Error("E2E requires HTTPS for Secure session cookies.");
const allowSelfSigned = process.env.ANONCE_E2E_ALLOW_SELF_SIGNED === "1";
if (
  allowSelfSigned &&
  !["localhost", "127.0.0.1", "[::1]"].includes(new URL(origin).hostname)
)
  throw new Error("Self-signed TLS bypass is restricted to loopback origins.");
const contextOptions = { ignoreHTTPSErrors: allowSelfSigned };
const { chromium } = await import("playwright");
const browser = await chromium.launch({ headless: true });
const traffic = [],
  responseReads = [];
const capture = (context) => {
  context.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    traffic.push({ path, text: request.url() });
    if (request.postData())
      traffic.push({
        path,
        text: request.postData(),
        method: request.method(),
      });
  });
  context.on("response", (response) => {
    if (new URL(response.url()).pathname.startsWith("/api/"))
      responseReads.push(
        response
          .text()
          .then((text) =>
            traffic.push({ path: new URL(response.url()).pathname, text }),
          )
          .catch(() => {}),
      );
  });
};
// Signed payloads and descriptors are base64url JSON; inspect those as well as HTTP text.
function decodedTexts(text, depth = 0) {
  const result = [text];
  if (depth === 5) return result;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return result;
  }
  const visit = (item) => {
    if (typeof item === "string" && /^[A-Za-z0-9_-]+$/.test(item)) {
      const decoded = Buffer.from(item, "base64url").toString("utf8");
      if (decoded.startsWith("{") || decoded.startsWith("["))
        result.push(...decodedTexts(decoded, depth + 1));
    } else if (item && typeof item === "object")
      for (const child of Object.values(item)) visit(child);
  };
  visit(value);
  return result;
}
const observe = (page) =>
  page.on("response", async (response) => {
    if (
      response.status() >= 400 &&
      new URL(response.url()).pathname.startsWith("/api/")
    ) {
      const body = await response.json().catch(() => null);
      console.error(
        "API failure",
        response.request().method(),
        new URL(response.url()).pathname,
        response.status(),
        body?.error?.code || "non-JSON error",
      );
    }
  });
try {
  const page = await browser.newPage(contextOptions);
  capture(page.context());
  observe(page);
  await page.goto(origin + "/#/register");
  const email = `e2e-${Date.now()}-${Math.random().toString(16).slice(2)}@example.net`;
  const password = crypto.randomUUID() + crypto.randomUUID();
  await page.getByLabel("Email address", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page
    .getByRole("button", { name: "Create account", exact: true })
    .click();
  await page.locator("#saved").waitFor();
  assert.equal(await page.locator(".word-grid .word").count(), 12);
  const originalReviewerWords = await page
    .locator(".word-grid .word")
    .evaluateAll((nodes) =>
      nodes.map((node) =>
        [...node.childNodes]
          .filter((n) => n.nodeType === Node.TEXT_NODE)
          .map((n) => n.textContent)
          .join("")
          .trim(),
      ),
    );
  assert.equal(await page.locator("#continue").isDisabled(), true);
  await page.locator("#saved").check();
  await page.locator("#continue").click();
  await page.evaluate(async () => {
    await (
      await import("/app.js")
    ).createOrganization({ name: "E2E encrypted workspace" });
  });
  await page.reload();
  assert.equal(
    await page.evaluate(async () =>
      Boolean(await (await import("/app.js")).getSession()),
    ),
    true,
    "device cache survives reload",
  );
  await page.evaluate(async () => {
    const app = await import("/app.js");
    const orgs = await app.listOrganizations();
    if (!orgs.items.length) throw Error("Organization missing");
    await app.logout();
  });
  await page.reload();
  await page.evaluate(
    async ({ email, password }) => {
      const app = await import("/app.js");
      await app.login({ email, password });
      await app.changePassword({
        currentPassword: password,
        newPassword: password + "-rotated",
      });
      await app.logout();
    },
    { email, password },
  );
  const reviewer = page;
  await reviewer.evaluate(
    async ({ email, password }) => {
      await (
        await import("/app.js")
      ).login({ email, password: password + "-rotated" });
    },
    { email, password },
  );
  const orgId = await reviewer.evaluate(async () => {
    const a = await import("/app.js");
    return (await a.listOrganizations()).items[0].id;
  });
  const token = await reviewer.evaluate(
    async (orgId) =>
      (
        await (
          await import("/app.js")
        ).createInvite({
          orgId,
          role: "respondent",
          expiresAt: String(Math.floor(Date.now() / 1000) + 3600),
        })
      ).token,
    orgId,
  );
  const respondentContext = await browser.newContext(contextOptions),
    respondent = await respondentContext.newPage();
  await respondent.goto(origin);
  capture(respondentContext);
  observe(respondent);
  const respondentEmail = email.replace("@", "-respondent@");
  const words = await respondent.evaluate(
    async ({ email, password, token }) => {
      const a = await import("/app.js");
      const r = await a.register({ email, password });
      await a.acceptInvite({ token });
      return r.recoveryWords;
    },
    { email: respondentEmail, password, token },
  );
  await reviewer.evaluate(async (orgId) => {
    const a = await import("/app.js");
    for (const m of (await a.listMembers({ orgId })).items)
      if (m.status === "pending" || m.state === "pending")
        await a.approveMember({ orgId, memberId: m.id });
  }, orgId);
  const reviewId = await reviewer.evaluate(async (orgId) => {
    const a = await import("/app.js");
    let r = await a.createReview({
      orgId,
      title: "E2E anonymous feedback",
      maxResponses: 2,
    });
    r = await a.updateReview({
      reviewId: r.id,
      expectedRevision: r.revision,
      title: r.title,
      description: "Disposable integration review",
      maxResponses: 2,
      opensAt: null,
      closesAt: null,
      questions: [
        { text: "Your thoughts?", type: "text", required: true, options: [] },
        {
          text: "Choose one",
          type: "single",
          required: true,
          options: ["One", "Two"],
        },
        {
          text: "Choose several",
          type: "multiple",
          required: true,
          options: ["Red", "Blue"],
        },
      ],
    });
    return r.id;
  }, orgId);
  // A clean browser must restore draft content and publish with only vault-held keys.
  const draftContext = await browser.newContext(contextOptions);
  capture(draftContext);
  try {
    const draftPage = await draftContext.newPage();
    observe(draftPage);
    await draftPage.goto(origin);
    await draftPage.evaluate(
      async ({ email, password, reviewId }) => {
        const a = await import("/app.js");
        await a.login({ email, password });
        const r = await a.getReview({ reviewId });
        if (
          r.contentState !== "open" ||
          r.status !== "draft" ||
          r.title !== "E2E anonymous feedback" ||
          r.description !== "Disposable integration review" ||
          r.questions.length !== 3 ||
          r.content.questions[0].label !== "Your thoughts?"
        )
          throw Error("Fresh-browser draft rehydration failed");
        await a.publishReview({ reviewId, expectedRevision: r.revision });
      },
      { email, password: password + "-rotated", reviewId },
    );
  } finally {
    await draftContext.close();
  }
  const invitation = await reviewer.evaluate(
    async (reviewId) =>
      (await import("/app.js")).getInvitationURL({ reviewId }),
    reviewId,
  );
  const invitationURL = new URL(invitation);
  const createRequest = traffic.find(
    (item) =>
      item.method === "POST" &&
      item.path === `/api/member/orgs/${orgId}/reviews`,
  );
  assert.ok(createRequest, "captured encrypted review creation");
  const createPayload = JSON.parse(
    Buffer.from(JSON.parse(createRequest.text).payload, "base64url").toString(
      "utf8",
    ),
  );
  assert.deepEqual(Object.keys(createPayload).sort(), [
    "encrypted_content",
    "max_responses",
    "request_id",
    "review_id",
    "vault_write",
  ]);
  assert.equal(createPayload.review_id, reviewId);
  assert.equal(createPayload.encrypted_content.v, 1);
  assert.equal(createPayload.vault_write.object.id, reviewId);
  const publishRequest = traffic.find(
    (item) =>
      item.method === "POST" &&
      item.path === `/api/member/reviews/${reviewId}/publish`,
  );
  assert.ok(publishRequest, "captured publication");
  const publishPayload = JSON.parse(
    Buffer.from(JSON.parse(publishRequest.text).payload, "base64url").toString(
      "utf8",
    ),
  );
  assert.equal(
    Object.hasOwn(publishPayload, "vault_write"),
    false,
    "publication reuses saved vault keys",
  );
  assert.equal(invitationURL.origin, new URL(origin).origin);
  assert.equal(invitationURL.pathname, "/");
  assert.equal(invitationURL.search, "");
  assert.match(
    invitationURL.hash,
    new RegExp(`^#/respond/${reviewId}\\?v=1&k=[A-Za-z0-9_-]{43}$`),
  );
  const contentKey = new URLSearchParams(invitationURL.hash.split("?")[1]).get(
    "k",
  );
  await reviewer.evaluate(
    async ({ reviewId, invitation }) => {
      const a = await import("/app.js"),
        parsed = a.parseResponseInvitation(new URL(invitation).hash);
      const r = await a.getReview({ reviewId, contentKey: parsed.contentKey });
      if (
        r.contentState !== "open" ||
        r.title !== "E2E anonymous feedback" ||
        r.description !== "Disposable integration review" ||
        r.content.questions.length !== 3 ||
        r.descriptor.v !== 3 ||
        !r.descriptor.encrypted_content
      )
        throw Error("Encrypted descriptor view mismatch");
      if (
        [
          "title",
          "description",
          "questions",
          "reviewer_account_id",
          "max_responses",
          "opens_at",
          "closes_at",
        ].some((key) => Object.hasOwn(r.descriptor, key))
      )
        throw Error("Descriptor contains private content or configuration");
    },
    { reviewId, invitation },
  );
  await respondent.evaluate(
    async ({ reviewId, invitation, orgId }) => {
      const a = await import("/app.js");
      const listed = (await a.listReviews({ orgId })).items.find(
        (r) => r.id === reviewId,
      );
      if (
        !listed ||
        listed.is_creator !== false ||
        listed.contentState !== "locked"
      )
        throw Error("Noncreator list must stay locked");
      if (
        [
          "creator_account_id",
          "reviewer_account_id",
          "reviewer_membership_id",
          "descriptor",
          "descriptor_signature",
          "revision",
          "max_responses",
          "opens_at",
          "closes_at",
          "issued_count",
          "accepted_count",
          "maxResponses",
          "opensAt",
          "closesAt",
        ].some((key) => Object.hasOwn(listed, key))
      )
        throw Error("Noncreator list exposed private metadata");
      for (const fragment of [
        `#/respond/${reviewId}`,
        new URL(invitation).hash.replace("v=1", "v=2"),
      ]) {
        let rejected = false;
        try {
          a.parseResponseInvitation(fragment);
        } catch {
          rejected = true;
        }
        if (!rejected) throw Error("Malformed invitation accepted");
      }
      let rejected = false,
        locked;
      try {
        locked = await a.getReview({ reviewId });
      } catch {
        rejected = true;
      }
      if (
        !rejected &&
        (locked.contentState !== "locked" ||
          locked.title ||
          locked.description ||
          locked.content ||
          !Array.isArray(locked.questions) ||
          locked.questions.length !== 0)
      )
        throw Error("Missing content key exposed plaintext content");
      const { contentKey } = a.parseResponseInvitation(
        new URL(invitation).hash,
      );
      contentKey[0] ^= 1;
      rejected = false;
      try {
        await a.getReview({ reviewId, contentKey });
      } catch {
        rejected = true;
      }
      if (!rejected) throw Error("Wrong content key accepted");
    },
    { reviewId, invitation, orgId },
  );
  // Preserve the fragment-held secret through the real sign-in continuation.
  await respondent.evaluate(async () => {
    await (await import("/app.js")).logout();
  });
  await respondent.goto(invitation);
  await respondent
    .getByLabel("Email address", { exact: true })
    .fill(respondentEmail);
  await respondent.getByLabel("Password", { exact: true }).fill(password);
  await respondent
    .getByRole("button", { name: "Sign in", exact: true })
    .click();
  await respondent.locator("#answer-0").waitFor();
  assert.equal(
    new URL(respondent.url()).hash,
    invitationURL.hash,
    "sign-in preserves the full secret invitation",
  );
  let issuanceCount = 0;
  const sent = [];
  respondent.on("request", (req) => {
    if (req.url().endsWith("/issuances") && req.method() === "POST")
      issuanceCount++;
  });
  let dropped = false;
  await respondent.route("**/api/anon/submissions", async (route) => {
    const req = route.request(),
      headers = await req.allHeaders();
    assert.equal(headers.cookie, undefined);
    assert.equal(headers.authorization, undefined);
    assert.equal(headers["x-csrf-token"], undefined);
    sent.push(req.postData());
    if (!dropped) {
      dropped = true;
      const upstream = await route.fetch();
      assert.equal(upstream.ok(), true);
      await route.abort("failed");
    } else await route.continue();
  });
  // UI journey: open the published response page and submit all question types.
  await respondent.goto(invitation);
  await respondent.locator("#answer-0").fill("Private browser response");
  await respondent.getByLabel("One", { exact: true }).check();
  await respondent.getByLabel("Red", { exact: true }).check();
  await respondent
    .getByRole("button", { name: "Send response", exact: true })
    .click();
  await respondent.waitForFunction(
    () =>
      document.querySelector("#respond button[type=submit]")?.disabled ===
      false,
  );
  await respondent.waitForFunction(async () => {
    const a = await import("/app.js");
    return (await a.listPendingResponses()).items.length > 0;
  });
  const recoveredReceipt = await respondent.evaluate(async () => {
    const a = await import("/app.js");
    const p = (await a.listPendingResponses()).items[0];
    return a.submitResponse({ pendingId: p.pendingId });
  });
  assert.equal(recoveredReceipt.status, "accepted");
  assert.equal(issuanceCount, 1);
  assert.equal(sent.length, 2);
  assert.equal(sent[0], sent[1]);
  await reviewer.evaluate(async (reviewId) => {
    const a = await import("/app.js");
    const result = await a.listResponses({ reviewId });
    if (result.items[0].answers[0].value !== "Private browser response")
      throw Error("Plaintext mismatch");
    const exported = await a.exportResponses({ reviewId, format: "csv" });
    if (!(await exported.blob.text()).includes("Private browser response"))
      throw Error("Export mismatch");
  }, reviewId);
  const recoveryContext = await browser.newContext(contextOptions),
    recoveryPage = await recoveryContext.newPage();
  await recoveryPage.goto(origin);
  capture(recoveryContext);
  observe(recoveryPage);
  await recoveryPage.evaluate(
    async ({ email, words, newPassword }) => {
      const a = await import("/app.js");
      const r = await a.recover({ email, words: words.join(" "), newPassword });
      if (r.recoveryWords.length !== 12)
        throw Error("Fresh recovery phrase missing");
    },
    { email: respondentEmail, words, newPassword: password + "-recovered" },
  );
  // Reviewer recovery must also preserve decryption of the old recipient key.
  await recoveryPage.evaluate(
    async ({ email, words, newPassword, reviewId }) => {
      const a = await import("/app.js");
      await a.logout();
      await a.recover({ email, words: words.join(" "), newPassword });
      if (!(await a.listResponses({ reviewId })).items.length)
        throw Error("Recovered reviewer cannot decrypt");
    },
    {
      email,
      words: originalReviewerWords,
      newPassword: password + "-recovered",
      reviewId,
    },
  );
  assert.equal(
    await recoveryPage.evaluate(
      async (reviewId) =>
        (await (await import("/app.js")).getReview({ reviewId })).title,
      reviewId,
    ),
    "E2E anonymous feedback",
    "recovery preserves content key",
  );
  await Promise.all(responseReads);
  const secrets = [
    "E2E anonymous feedback",
    "Disposable integration review",
    "Your thoughts?",
    "Choose one",
    "Choose several",
    "Private browser response",
    contentKey,
    Buffer.from(contentKey, "base64url").toString("base64"),
  ];
  for (const { path, text } of traffic)
    for (const decoded of decodedTexts(text))
      for (const secret of secrets)
        assert.equal(
          decoded.includes(secret),
          false,
          `Plaintext or content key leaked over HTTP at ${path}`,
        );
  console.log(
    "PASS: encrypted content/descriptor, secret invitations, missing/wrong keys, sign-in continuation, HTTP secrecy, two-context membership, lost-reply exact retry, receipt, plaintext/export, reload unlock and cross-device recovery",
  );
} finally {
  await browser.close();
}
