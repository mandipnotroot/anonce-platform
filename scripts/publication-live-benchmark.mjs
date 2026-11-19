// SPDX-License-Identifier: AGPL-3.0-only
// Opt-in, synthetic-only benchmark against the dedicated live Compose deployment.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import os from "node:os";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";

const allowedSizes = [1000, 10000, 100000];
let stage = "setup";
let activeSize = null;
let fixtureResult = null;
let httpStatus = null;
const exact = (value, keys) =>
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
const canonical = (value, length) => {
  assert.equal(typeof value, "string");
  assert.match(value, /^[A-Za-z0-9_-]+$/);
  const bytes = Buffer.from(value, "base64url");
  assert.equal(bytes.length, length);
  assert.equal(bytes.toString("base64url"), value);
};

function configuration() {
  const origin = new URL(process.env.ANONCE_E2E_ORIGIN || "");
  assert.equal(origin.protocol, "https:");
  assert.ok(["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname));
  assert.equal(origin.port, "18443", "Use the dedicated benchmark HTTPS port");
  assert.equal(origin.pathname, "/");
  assert.ok(
    !origin.username && !origin.password && !origin.search && !origin.hash,
  );
  for (const [name, role] of [
    ["ANONCE_BENCHMARK_DATABASE_URL", "anonce_member"],
    ["ANONCE_BENCHMARK_ANON_DATABASE_URL", "anonce_anon"],
  ]) {
    const db = new URL(process.env[name] || "");
    assert.ok(["postgres:", "postgresql:"].includes(db.protocol));
    assert.equal(db.hostname, "127.0.0.1");
    assert.equal(db.port, "15432");
    assert.equal(db.pathname, "/anonce_publication_benchmark");
    assert.equal(db.username, role);
  }
  assert.ok(
    process.env.ANONCE_BENCHMARK_KEY_FILE,
    "Explicit fixture key required",
  );
  const sizes = (process.env.ANONCE_BENCHMARK_SIZES || allowedSizes.join(","))
    .split(",")
    .map(Number);
  assert.ok(sizes.length && new Set(sizes).size === sizes.length);
  assert.ok(sizes.every((size) => allowedSizes.includes(size)));
  return {
    origin: origin.origin,
    sizes,
    ignoreHTTPSErrors: process.env.ANONCE_E2E_ALLOW_SELF_SIGNED === "1",
  };
}

async function fixture(origin, orgId, size, reviewId) {
  await new Promise((resolve, reject) => {
    const child = spawn(
      "go",
      [
        "test",
        "./internal/server",
        "-run",
        "^TestLivePublicationBenchmarkFixture$",
        "-count=1",
        "-v",
      ],
      {
        env: {
          ...process.env,
          ANONCE_LIVE_BENCHMARK_FIXTURE: "1",
          ANONCE_BENCHMARK_ORIGIN: origin,
          ANONCE_BENCHMARK_ORG_ID: orgId,
          ANONCE_BENCHMARK_MEMBERS: String(size),
          ANONCE_BENCHMARK_VERIFY: reviewId ? "1" : "0",
          ANONCE_BENCHMARK_REVIEW_ID: reviewId || "",
        },
        // Go test diagnostics may contain fixture identifiers or connection strings.
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let passed = false;
    let skipped = false;
    let carry = "";
    child.stdout.on("data", (chunk) => {
      const lines = (carry + chunk.toString()).split("\n");
      carry = lines.pop().slice(-1024);
      for (const line of lines) {
        if (line.startsWith("--- PASS: TestLivePublicationBenchmarkFixture"))
          passed = true;
        if (line.startsWith("--- SKIP: TestLivePublicationBenchmarkFixture"))
          skipped = true;
      }
    });
    child.stderr.resume();
    child.on("error", () => reject(new Error("Fixture could not start")));
    child.on("close", (code) => {
      fixtureResult = { exitCode: code, passed, skipped };
      if (code === 0 && passed && !skipped) resolve();
      else
        reject(new Error("Fixture failed or skipped; diagnostics suppressed"));
    });
  });
}

function category(path) {
  if (path === "/api/member/challenges") return "challenges";
  if (path.endsWith("/publication/envelopes")) return "batch";
  if (path.endsWith("/publication")) return "start";
  if (path.endsWith("/content-recipients")) return "pages";
  if (path.endsWith("/publish")) return "finalize";
  return "other";
}

function capture(context, markers) {
  const metrics = {};
  const pending = new Set();
  const starts = new WeakMap();
  let failure = false;
  let retryMs = 60000;
  let maxBatch = 0;
  let envelopesAttempted = 0;
  let pagesReceived = 0;
  let enabled = true;
  const scan = (text, depth = 0) => {
    assert.ok(!markers.some((marker) => text.includes(marker)));
    if (depth >= 5) return;
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      return;
    }
    const visit = (item) => {
      if (typeof item === "string" && /^[A-Za-z0-9_-]+$/.test(item)) {
        const decoded = Buffer.from(item, "base64url").toString("utf8");
        assert.ok(!markers.some((marker) => decoded.includes(marker)));
        if (decoded.startsWith("{") || decoded.startsWith("["))
          scan(decoded, depth + 1);
      } else if (item && typeof item === "object")
        Object.values(item).forEach(visit);
    };
    visit(value);
  };
  const validateRequest = (kind, text) => {
    if (!["start", "batch", "finalize"].includes(kind)) return;
    assert.ok(Buffer.byteLength(text) <= 1536 * 1024);
    const wire = JSON.parse(text);
    exact(wire, ["payload", "proof"]);
    exact(wire.proof, ["challenge_id", "membership_sig"]);
    const payload = JSON.parse(
      Buffer.from(wire.payload, "base64url").toString("utf8"),
    );
    const fields = {
      start: [
        "request_id",
        "expected_revision",
        "descriptor",
        "descriptor_signature",
      ],
      batch: ["request_id", "publication_id", "content_key_envelopes"],
      finalize: ["request_id", "expected_revision", "publication_id"],
    };
    exact(payload, fields[kind]);
    if (kind === "start") {
      const bytes = Buffer.from(payload.descriptor, "base64url");
      assert.ok(bytes.length <= 65536);
      exact(JSON.parse(bytes.toString("utf8")), [
        "v",
        "deployment_id",
        "review_id",
        "org_id",
        "reviewer_membership_id",
        "reviewer_certificate",
        "encrypted_content",
        "recipient_public_key",
        "issuer_key_id",
        "issuer_public_key",
      ]);
    }
    if (kind === "batch") {
      const batch = payload.content_key_envelopes;
      assert.ok(
        Array.isArray(batch) && batch.length > 0 && batch.length <= 100,
      );
      maxBatch = Math.max(maxBatch, batch.length);
      envelopesAttempted += batch.length;
      for (const envelope of batch) {
        exact(envelope, [
          "v",
          "membership_id",
          "encryption_key_id",
          "enc",
          "ciphertext",
        ]);
        assert.equal(envelope.v, 1);
        for (const [key, length] of [
          ["membership_id", 16],
          ["encryption_key_id", 32],
          ["enc", 32],
          ["ciphertext", 48],
        ])
          canonical(envelope[key], length);
      }
    }
  };
  context.on("request", (request) => {
    if (!enabled) return;
    const path = new URL(request.url()).pathname;
    if (!path.startsWith("/api/")) return;
    const kind = category(path);
    const metric = (metrics[kind] ||= {
      requests: 0,
      requestBodyBytes: 0,
      responseBodyBytes: 0,
      completed: 0,
      failed: 0,
      durationMs: 0,
      maxDurationMs: 0,
      statuses: {},
    });
    starts.set(request, { time: performance.now(), metric });
    metric.requests++;
    try {
      const body = request.postDataBuffer();
      metric.requestBodyBytes += body?.length || 0;
      scan(request.url());
      if (body) {
        scan(body.toString("utf8"));
        validateRequest(kind, body.toString("utf8"));
      }
    } catch {
      failure = true;
    }
  });
  context.on("requestfailed", (request) => {
    const entry = starts.get(request);
    if (entry) entry.metric.failed++;
    failure = true;
  });
  context.on("response", (response) => {
    const entry = starts.get(response.request());
    if (!entry) return;
    const task = (async () => {
      const { metric, time } = entry;
      const status = response.status();
      metric.statuses[status] = (metric.statuses[status] || 0) + 1;
      if (status === 429) {
        const header = await response.headerValue("retry-after");
        const seconds = Number(header);
        retryMs =
          header && Number.isFinite(seconds) && seconds >= 0
            ? seconds * 1000
            : header && Number.isFinite(Date.parse(header))
              ? Math.max(0, Date.parse(header) - Date.now())
              : 60000;
      }
      const body = await response.body();
      metric.responseBodyBytes += body.length;
      scan(body.toString("utf8"));
      if (
        status === 200 &&
        category(new URL(response.url()).pathname) === "pages"
      ) {
        const page = JSON.parse(body.toString("utf8"));
        exact(page, ["items", "next"]);
        assert.ok(Array.isArray(page.items) && page.items.length <= 100);
        for (const recipient of page.items)
          exact(recipient, [
            "membership_id",
            "account_id",
            "certificate",
            "encryption_public_key",
            "encryption_key_signature",
          ]);
        pagesReceived += page.items.length;
      }
      const duration = performance.now() - time;
      metric.durationMs += duration;
      metric.maxDurationMs = Math.max(metric.maxDurationMs, duration);
      metric.completed++;
    })().catch(() => {
      failure = true;
    });
    pending.add(task);
    void task.finally(() => pending.delete(task));
  });
  return {
    async drain() {
      while (pending.size) await Promise.all([...pending]);
      assert.ok(!failure, "Traffic validation or network observation failed");
    },
    retry: () => retryMs,
    stop: () => {
      enabled = false;
    },
    summary: () => ({
      metrics,
      maxBatch,
      envelopesAttempted,
      directoryRecipientsReceived: pagesReceived,
      plaintextScan: "passed",
      payloadValidation: "exact field sets; pages and batches bounded to 100",
    }),
  };
}

async function run(browser, config, size) {
  activeSize = size;
  stage = "setup";
  fixtureResult = null;
  httpStatus = null;
  const context = await browser.newContext({
    ignoreHTTPSErrors: config.ignoreHTTPSErrors,
  });
  try {
    const page = await context.newPage();
    let browserError = false;
    page.on("pageerror", () => {
      browserError = true;
    });
    page.on("crash", () => {
      browserError = true;
    });
    stage = "navigation";
    await page.goto(config.origin);
    stage = "register";
    const orgId = await page.evaluate(async (nonce) => {
      const app = await import("/app.js");
      await app.register({
        email: `publication-${nonce}@benchmark.invalid`,
        password: crypto.randomUUID() + crypto.randomUUID(),
      });
      await app.createOrganization({ name: "publication-benchmark" });
      return (await app.listOrganizations()).items[0].id;
    }, randomUUID());
    stage = "seed";
    await fixture(config.origin, orgId, size);
    stage = "draft";
    const markers = [
      `Publication title ${randomUUID()}`,
      `Publication description ${randomUUID()}`,
      `Publication question ${randomUUID()}`,
    ];
    const draft = await page.evaluate(
      async ({ orgId, markers }) => {
        const app = await import("/app.js");
        let review = await app.createReview({
          orgId,
          title: markers[0],
          maxResponses: 1,
        });
        review = await app.updateReview({
          reviewId: review.id,
          expectedRevision: review.revision,
          title: markers[0],
          description: markers[1],
          maxResponses: 1,
          opensAt: null,
          closesAt: null,
          questions: [
            { text: markers[2], type: "text", required: true, options: [] },
          ],
        });
        return { reviewId: review.id, expectedRevision: review.revision };
      },
      { orgId, markers },
    );
    const traffic = capture(context, markers);
    const cdp = await context.newCDPSession(page);
    await cdp.send("Performance.enable");
    let heapSamples = 0;
    let heapPeak = 0;
    let sampling = false;
    let sampleTask = Promise.resolve();
    const sample = async () => {
      if (sampling) return;
      sampling = true;
      try {
        const { metrics } = await cdp.send("Performance.getMetrics");
        const used = metrics.find((m) => m.name === "JSHeapUsedSize")?.value;
        if (Number.isFinite(used)) {
          heapPeak = Math.max(heapPeak, used);
          heapSamples++;
        }
      } catch {
        browserError = true;
      } finally {
        sampling = false;
      }
    };
    await sample();
    const timer = setInterval(() => {
      sampleTask = sample();
    }, 1000);
    stage = "publish";
    const started = performance.now();
    let retryWaitMs = 0;
    let attempts = 0;
    try {
      for (;;) {
        attempts++;
        const result = await page.evaluate(async (draft) => {
          try {
            await (await import("/app.js")).publishReview(draft);
            return { ok: true };
          } catch (error) {
            // Never serialize browser error messages, stacks, or request details.
            return {
              ok: false,
              status: Number(error.status ?? error.statusCode),
            };
          }
        }, draft);
        await traffic.drain();
        if (result.ok) break;
        httpStatus = result.status;
        assert.equal(
          result.status,
          429,
          "Publication failed (details suppressed)",
        );
        assert.ok(attempts < 10000, "Harness retry safety limit reached");
        const wait = Math.max(1000, traffic.retry());
        console.error(
          JSON.stringify({
            event: "harness_assisted_429_wait",
            members: size,
            waitMs: wait,
            attempt: attempts,
          }),
        );
        const before = performance.now();
        await delay(wait);
        retryWaitMs += performance.now() - before;
      }
    } finally {
      clearInterval(timer);
      await sampleTask;
    }
    const wallMs = performance.now() - started;
    await sample();
    traffic.stop();
    stage = "verify";
    httpStatus = null;
    const state = await page.evaluate(
      async ({ reviewId, markers }) => {
        const review = await (await import("/app.js")).getReview({ reviewId });
        return {
          published: review.status === "published",
          open:
            review.contentState === "open" &&
            review.title === markers[0] &&
            review.description === markers[1] &&
            review.questions[0]?.text === markers[2],
        };
      },
      { ...draft, markers },
    );
    assert.ok(state.published && state.open);
    const isolated = await page.evaluate(async ({ reviewId }) => {
      const response = await fetch(`/api/member/reviews/${reviewId}`);
      const review = await response.json();
      return (
        response.ok &&
        Boolean(review.content_key_envelope) &&
        !("content_key_envelopes" in review)
      );
    }, draft);
    assert.ok(isolated, "Creator response must contain only its own envelope");
    await traffic.drain();
    await fixture(config.origin, orgId, size, draft.reviewId);
    assert.ok(!browserError, "Browser error occurred (details suppressed)");
    return {
      members: size,
      wallMs,
      harnessRetryWaitMs: retryWaitMs,
      wallExcludingHarnessWaitMs: wallMs - retryWaitMs,
      publishAttempts: attempts,
      retries:
        "Harness re-invokes same app.publishReview on 429; not product auto-retry",
      traffic: traffic.summary(),
      heap: {
        scope:
          "CDP renderer JSHeapUsedSize sampled, not RSS or total browser memory",
        intervalMs: 1000,
        samples: heapSamples,
        peakBytes: heapPeak,
      },
      verification: {
        creatorPublishedAndDecryptable: true,
        creatorEnvelopeIsolated: true,
        backendFixtureVerification: "passed",
      },
      metadata: {
        browser: browser.version(),
        node: process.version,
        platform: process.platform,
        arch: process.arch,
        logicalCPUs: os.cpus().length,
        cpuModel: os.cpus()[0]?.model,
        hostMemoryBytes: os.totalmem(),
        availableParallelism: os.availableParallelism(),
        resourceScope:
          "Host metadata; container CPU/memory limits not measured",
        bodyBytesScope:
          "Actual request buffers and decoded response bodies; excludes headers, compression and TLS overhead",
        timingScope:
          "app.publishReview only, includes harness waits; excludes signup, fixture, draft and final verification",
        throttling: "Unmodified deployment defaults",
        syntheticDataOnly: true,
      },
    };
  } finally {
    await context.close();
  }
}

if (!process.argv.includes("--run")) {
  console.log(
    "Opt-in only: use --run with explicit dedicated benchmark origin, DB URLs and key file.",
  );
} else {
  let browser;
  try {
    const config = configuration();
    const { chromium } = await import("playwright");
    browser = await chromium.launch({ headless: true });
    for (const size of config.sizes)
      console.log(JSON.stringify(await run(browser, config, size)));
  } catch (error) {
    const status = Number(error?.status ?? error?.statusCode ?? httpStatus);
    console.error(
      JSON.stringify({
        event: "benchmark_failed",
        stage,
        members: activeSize,
        ...(Number.isInteger(status) && status >= 100 && status <= 599
          ? { httpStatus: status }
          : {}),
        ...(fixtureResult ? { fixture: fixtureResult } : {}),
        diagnostics: "Raw errors and fixture output suppressed",
      }),
    );
    process.exitCode = 1;
  } finally {
    await browser?.close();
  }
}
