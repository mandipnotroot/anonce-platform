// SPDX-License-Identifier: AGPL-3.0-only
// Opt-in, synthetic data only: node scripts/publication-benchmark.mjs --run
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import * as c from "../web/crypto.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  X509CertificateGenerator,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
} from "@peculiar/x509";

if (process.argv[2] !== "--run") {
  console.error("Opt in with: node scripts/publication-benchmark.mjs --run");
  process.exit(1);
}
const batchSize = 100;
const concurrency = 8;
const b64 = c.toBase64url;
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const deploymentId = random(32),
  orgId = random(16),
  reviewId = random(16);
const caKeys = await crypto.subtle.generateKey("Ed25519", true, [
  "sign",
  "verify",
]);
const dates = {
  notBefore: new Date("2020-01-01T00:00:00Z"),
  notAfter: new Date("2099-01-01T00:00:00Z"),
};
const ca = await X509CertificateGenerator.createSelfSigned(
  {
    ...dates,
    name: "CN=Synthetic benchmark CA",
    keys: caKeys,
    signingAlgorithm: { name: "Ed25519" },
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(32, true),
    ],
  },
  crypto,
);
globalThis.location = { origin: "https://benchmark.invalid" };
const receiptPublicKey = new Uint8Array(
  await crypto.subtle.exportKey("raw", caKeys.publicKey),
);
const receiptKeyId = sha256(receiptPublicKey);
await c.initCrypto({
  deploymentId,
  origin: location.origin,
  caCertificate: new Uint8Array(ca.rawData),
  receiptKeyId,
  receiptKeys: [
    {
      receipt_key_id: b64(receiptKeyId),
      receipt_public_key: b64(receiptPublicKey),
    },
  ],
});
const descriptorBytes = c.utf8('{"synthetic_benchmark_descriptor":true}');
const contentKey = await c.generateContentKey();

async function mapBounded(items, operation) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: concurrency }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await operation(items[i]);
      }
    }),
  );
  return out;
}
async function fixture() {
  const membershipId = random(16),
    accountId = random(16);
  const membership = await c.generateMembershipKey();
  const encryption = await c.generateMemberEncryptionKeyPair();
  const publicKey = await crypto.subtle.importKey(
    "raw",
    membership.publicKey,
    "Ed25519",
    true,
    ["verify"],
  );
  const certificate = await X509CertificateGenerator.create(
    {
      ...dates,
      subject: "CN=Synthetic recipient",
      issuer: ca.subject,
      publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: { name: "Ed25519" },
      extensions: [
        new BasicConstraintsExtension(false, undefined, true),
        new KeyUsagesExtension(1, true),
        new SubjectAlternativeNameExtension([
          {
            type: "url",
            value: `urn:anonce:deployment:${b64(deploymentId)}:org:${b64(orgId)}:member:${b64(membershipId)}`,
          },
        ]),
      ],
    },
    crypto,
  );
  const signature = await c.signMemberEncryptionKeyBinding({
    deploymentId,
    accountId,
    membershipPublicKey: membership.publicKey,
    encryptionPublicKey: encryption.publicKey,
    membershipSeed: membership.seed,
  });
  return {
    membership_id: b64(membershipId),
    account_id: b64(accountId),
    certificate: b64(new Uint8Array(certificate.rawData)),
    encryption_public_key: b64(encryption.publicKey),
    encryption_key_signature: b64(signature),
  };
}
console.log(
  JSON.stringify({
    scope:
      "Actual browser-compatible web/crypto.js verifyContentRecipient + sealReviewContentKey primitive pipeline in Node; NOT app-path timing, live browser or end-to-end. Pipeline concurrently verifies then seals each recipient (eight tasks); app instead verifies sequentially before sealing in chunks of eight. Unique valid CA-signed recipient certificate, membership key, account, encryption key and signed binding per recipient. Synthetic descriptor bytes are context only, not a signed publication descriptor. No network requests.",
    node: process.version,
    batchSize,
    concurrency,
    timing:
      "Crypto elapsed excludes per-batch fixture generation and JSON serialization; wall elapsed includes both. No warmup or forced GC. Memory sampled at batch boundaries includes fixture generation; maxRSS is process-lifetime OS high-water mark.",
  }),
);
for (const recipients of [1000, 10000, 100000]) {
  const wallStart = performance.now();
  let elapsedMs = 0,
    fixtureMs = 0,
    totalPayloadBytes = 0;
  let minBatchPayloadBytes = Infinity,
    maxBatchPayloadBytes = 0,
    maxRetainedBatch = 0;
  const memoryStart = process.memoryUsage();
  const sampledPeak = { ...memoryStart };
  for (let offset = 0; offset < recipients; offset += batchSize) {
    const fixtureStart = performance.now();
    const batch = await mapBounded(
      Array.from({ length: Math.min(batchSize, recipients - offset) }),
      fixture,
    );
    fixtureMs += performance.now() - fixtureStart;
    maxRetainedBatch = Math.max(maxRetainedBatch, batch.length);
    const start = performance.now();
    const envelopes = await mapBounded(batch, async (recipient) => {
      const verified = await c.verifyContentRecipient({ orgId, recipient });
      return c.sealReviewContentKey({
        descriptorBytes,
        orgId,
        reviewId,
        membershipId: verified.membershipId,
        encryptionPublicKey: verified.encryptionPublicKey,
        contentKey,
      });
    });
    elapsedMs += performance.now() - start;
    assert.equal(envelopes.length, batch.length);
    const bytes = Buffer.byteLength(
      JSON.stringify({
        request_id: b64(random(16)),
        publication_id: b64(reviewId),
        content_key_envelopes: envelopes,
      }),
    );
    totalPayloadBytes += bytes;
    minBatchPayloadBytes = Math.min(minBatchPayloadBytes, bytes);
    maxBatchPayloadBytes = Math.max(maxBatchPayloadBytes, bytes);
    const memory = process.memoryUsage();
    for (const key of Object.keys(memory))
      sampledPeak[key] = Math.max(sampledPeak[key], memory[key]);
  }
  console.log(
    JSON.stringify({
      recipients,
      batchSize,
      concurrency,
      elapsedMs,
      recipientsPerSecond: recipients / (elapsedMs / 1000),
      fixtureMs,
      wallElapsedMs: performance.now() - wallStart,
      totalPayloadBytes,
      minBatchPayloadBytes,
      maxBatchPayloadBytes,
      payloadScope:
        "Unsigned envelope-upload JSON payload only; excludes signed wrapper, HTTP/TLS and recipient page bytes.",
      maxRetainedBatch,
      retentionScope:
        "At most one recipient batch and one envelope batch; eight concurrent crypto tasks. Not a GC/heap object-count guarantee.",
      memoryStart,
      memoryEnd: process.memoryUsage(),
      sampledPeak,
      processLifetimeMaxRSSBytes: process.resourceUsage().maxRSS * 1024,
      requestCountEstimates: {
        label:
          "Estimates only; no requests sent. Assumes no retries, next:null on the last nonempty page, one challenge per mutation, and current per-page vault reads plus three initial authenticated reads.",
        recipientPages: Math.ceil(recipients / batchSize),
        envelopeUploads: Math.ceil(recipients / batchSize),
        startAndFinalize: 2,
        otherAuthenticatedReads: Math.ceil(recipients / batchSize) + 3,
        applicationRequests: 3 * Math.ceil(recipients / batchSize) + 5,
        signedChallengeRequests: Math.ceil(recipients / batchSize) + 2,
        overallIncludingChallenges: 4 * Math.ceil(recipients / batchSize) + 7,
      },
    }),
  );
}
