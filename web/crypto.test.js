// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { CryptoError, toBase64url, fromBase64url } from "./crypto.js";
import * as c from "./crypto.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { RSABSSA } from "@cloudflare/blindrsa-ts";
import {
  X509CertificateGenerator,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
} from "@peculiar/x509";

const bytes = (n, fill = 1) => new Uint8Array(n).fill(fill);
const b64 = toBase64url;
globalThis.location = { origin: "https://anonce.test" };
const deploymentId = bytes(32),
  accountId = bytes(16),
  reviewId = bytes(16, 2);
const receiptSeed = bytes(32, 3),
  receiptPublicKey = ed25519.getPublicKey(receiptSeed);
const receiptKeyId = sha256(receiptPublicKey);
const caKeys = await crypto.subtle.generateKey("Ed25519", true, [
  "sign",
  "verify",
]);
const historicalDates = {
  notBefore: new Date("2020-01-01T00:00:00Z"),
  notAfter: new Date("2021-01-01T00:00:00Z"),
};
const ca = await X509CertificateGenerator.createSelfSigned(
  {
    ...historicalDates,
    name: "CN=Test CA",
    keys: caKeys,
    signingAlgorithm: { name: "Ed25519" },
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(32, true),
    ],
  },
  crypto,
);
const receiptKeys = [
  {
    receipt_key_id: b64(receiptKeyId),
    receipt_public_key: b64(receiptPublicKey),
  },
];
const trust = {
  v: 1,
  deployment_id: b64(deploymentId),
  receipt_key_id: b64(receiptKeyId),
  receipt_keys: receiptKeys,
};
const init = {
  deploymentId,
  origin: location.origin,
  caCertificate: new Uint8Array(ca.rawData),
  receiptKeys,
  receiptKeyId,
};
// A separate module instance has never been initialized and needs no location.
const portable = await import("./crypto.js?standalone-receipts");
const standaloneReceipt = signedReceipt();
const savedLocation = globalThis.location;
delete globalThis.location;
try {
  assert.deepEqual(
    await portable.verifyReceiptSignature({
      receipt: standaloneReceipt,
      trust,
    }),
    standaloneReceipt,
  );
} finally {
  globalThis.location = savedLocation;
}
await c.initCrypto(init);
const membership = await c.generateMembershipKey();
const memberPublicKey = await crypto.subtle.importKey(
  "raw",
  membership.publicKey,
  "Ed25519",
  true,
  ["verify"],
);
const certificate = await X509CertificateGenerator.create(
  {
    ...historicalDates,
    subject: "CN=Member",
    issuer: ca.subject,
    publicKey: memberPublicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: { name: "Ed25519" },
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(1, true),
      new SubjectAlternativeNameExtension([
        {
          type: "url",
          value: `urn:anonce:deployment:${b64(deploymentId)}:org:${b64(accountId)}:member:${b64(accountId)}`,
        },
      ]),
    ],
  },
  crypto,
);
const rsaSuite = RSABSSA.SHA384.PSS.Randomized();
const rsa = await rsaSuite.generateKey({
  modulusLength: 3072,
  publicExponent: new Uint8Array([1, 0, 1]),
});
const spki = new Uint8Array(
  await crypto.subtle.exportKey("spki", rsa.publicKey),
);
const recipient = await c.generateRecipientKey();
const contentKey = await c.generateContentKey();
const content = {
  v: 1,
  title: "Review",
  description: "",
  questions: [
    { id: "q1", type: "text", label: "Feedback", required: true, choices: [] },
  ],
};
const encrypted_content = await c.sealReviewContent({
  reviewId,
  orgId: accountId,
  contentKey,
  content,
});
const descriptorJSON = {
  v: 3,
  deployment_id: b64(deploymentId),
  review_id: b64(reviewId),
  org_id: b64(accountId),
  reviewer_membership_id: b64(accountId),
  reviewer_certificate: b64(new Uint8Array(certificate.rawData)),
  encrypted_content,
  recipient_public_key: b64(recipient.publicKey),
  issuer_key_id: b64(sha256(spki)),
  issuer_public_key: b64(spki),
};
const descriptorBytes = c.utf8(JSON.stringify(descriptorJSON));
const descriptorSignature = await c.signDescriptor({
  descriptorBytes,
  membershipSeed: membership.seed,
});
const descriptor = await c.verifyDescriptor({
  descriptorBytes,
  signature: descriptorSignature,
  expectedReviewId: reviewId,
});
await c.openDescriptorContent({ descriptor, contentKey });

test("base64url is unpadded and canonical", () => {
  const bytes = new Uint8Array([0, 255, 254, 128]);
  assert.equal(toBase64url(bytes), "AP_-gA");
  assert.deepEqual(fromBase64url("AP_-gA"), bytes);
  assert.deepEqual(fromBase64url(""), new Uint8Array());
  for (const input of ["A", "AB", "AB==", "a+b/", "AA\n", " AA", null]) {
    assert.throws(() => fromBase64url(input), CryptoError);
  }
});

test("content key is independent; encryption authenticates context, key and envelope", async () => {
  assert.notDeepEqual(contentKey, recipient.privateKey);
  assert.deepEqual(
    await c.recipientPublicKey({ privateKey: recipient.privateKey }),
    recipient.publicKey,
  );
  const args = { reviewId, orgId: accountId, contentKey, content };
  const first = await c.sealReviewContent(args),
    second = await c.sealReviewContent(args);
  assert.notEqual(first.nonce, second.nonce);
  assert.deepEqual(
    await c.openDraftContent({
      ...args,
      contentKey: b64(contentKey),
      encryptedContent: first,
    }),
    content,
  );
  for (const change of [
    { reviewId: bytes(16, 9) },
    { orgId: bytes(16, 9) },
    { contentKey: recipient.privateKey },
    { contentKey: b64(contentKey) + "=" },
  ]) {
    await assert.rejects(
      c.openDraftContent({ ...args, encryptedContent: first, ...change }),
      CryptoError,
    );
  }
  for (const change of [
    { v: 2 },
    { nonce: "AB" },
    { extra: true },
    { ciphertext: b64(bytes(15)) },
    { ciphertext: b64(bytes(32785)) },
  ]) {
    await assert.rejects(
      c.openDraftContent({
        ...args,
        encryptedContent: { ...first, ...change },
      }),
      CryptoError,
    );
  }
  const tampered = fromBase64url(first.ciphertext);
  tampered[0] ^= 1;
  await assert.rejects(
    c.openDraftContent({
      ...args,
      encryptedContent: { ...first, ciphertext: b64(tampered) },
    }),
    CryptoError,
  );
  const other = await import("./crypto.js?other-content-deployment");
  await other.initCrypto({ ...init, deploymentId: bytes(32, 99) });
  await assert.rejects(
    other.openDraftContent({ ...args, encryptedContent: first }),
    other.CryptoError,
  );
});

test("content validation enforces exact schema, UTF8 byte bounds and draft versus publication", async () => {
  assert.deepEqual(
    c.validateReviewContent({ ...content, questions: [] }).questions,
    [],
  );
  assert.throws(
    () =>
      c.validateReviewContent({ ...content, questions: [] }, { publish: true }),
    CryptoError,
  );
  const q = content.questions[0];
  const invalid = [
    { ...content, v: 2 },
    { ...content, extra: true },
    { ...content, title: "" },
    { ...content, title: "界".repeat(101) },
    { ...content, title: "\ud800" },
    { ...content, description: "x".repeat(10001) },
    { ...content, questions: Array(101).fill(q) },
    { ...content, questions: [q, q] },
    ...[
      { id: "" },
      { id: "x".repeat(101) },
      { label: "x".repeat(2001) },
      { required: 1 },
      { type: "other" },
      { extra: 1 },
      { choices: [{ id: "a", label: "A" }] },
    ].map((change) => ({ ...content, questions: [{ ...q, ...change }] })),
    {
      ...content,
      questions: [
        {
          ...q,
          type: "single",
          choices: [
            { id: "a", label: "A" },
            { id: "a", label: "B" },
          ],
        },
      ],
    },
    {
      ...content,
      questions: Array.from({ length: 20 }, (_, i) => ({
        ...q,
        id: String(i),
        label: "x".repeat(2000),
      })),
    },
  ];
  for (const value of invalid)
    assert.throws(() => c.validateReviewContent(value), CryptoError);
  const nonce = bytes(12),
    aad = c.encodeContext("review-content", [
      deploymentId,
      accountId,
      reviewId,
      c.u64be(1),
    ]);
  for (const plaintext of [
    c.utf8('{"v":1,"v":1}'),
    new Uint8Array([0xff]),
    c.utf8(JSON.stringify({ ...content, extra: 1 })),
  ]) {
    const encryptedContent = {
      v: 1,
      nonce: b64(nonce),
      ciphertext: b64(
        chacha20poly1305(contentKey, nonce, aad).encrypt(plaintext),
      ),
    };
    await assert.rejects(
      c.openDraftContent({
        reviewId,
        orgId: accountId,
        contentKey,
        encryptedContent,
      }),
      CryptoError,
    );
  }
});

test("verified descriptor must be opened; signed data and internal content remain separate", async () => {
  const fresh = await c.verifyDescriptor({
    descriptorBytes,
    signature: descriptorSignature,
    expectedReviewId: reviewId,
  });
  const args = {
    descriptorBytes,
    descriptor: fresh,
    answers: { q1: "answer" },
  };
  await assert.rejects(
    c.encryptResponse(args),
    (e) => e.code === "CONTENT_NOT_OPENED",
  );
  await assert.rejects(
    c.decryptResponse({
      ...args,
      recipientPrivateKey: recipient.privateKey,
      enc: bytes(32),
      ciphertext: bytes(16),
    }),
    (e) => e.code === "CONTENT_NOT_OPENED",
  );
  await assert.rejects(
    c.openDescriptorContent({ descriptor: structuredClone(fresh), contentKey }),
    CryptoError,
  );
  const opened = await c.openDescriptorContent({
    descriptor: fresh,
    contentKey,
  });
  assert.deepEqual(fresh, descriptorJSON);
  opened.questions[0].required = false;
  await assert.rejects(
    c.encryptResponse({ ...args, answers: {} }),
    (e) => e.code === "MISSING_ANSWER",
  );
  const sealed = await c.encryptResponse(args);
  await assert.rejects(
    c.decryptResponse({ ...args, ...sealed, recipientPrivateKey: contentKey }),
    (e) => e.code === "RECIPIENT_KEY_MISMATCH",
  );
  fresh.encrypted_content.nonce = b64(bytes(12));
  await assert.rejects(
    c.openDescriptorContent({ descriptor: fresh, contentKey }),
    (e) => e.code === "UNVERIFIED_DESCRIPTOR",
  );
  await assert.rejects(
    c.encryptResponse(args),
    (e) => e.code === "UNVERIFIED_DESCRIPTOR",
  );
});

test("shared deterministic review-content inputs decrypt with fixed nonce and key", async () => {
  const vector = JSON.parse(
    await readFile(
      new URL("../testdata/review-content-v1.json", import.meta.url),
      "utf8",
    ),
  );
  const hex = (value) => new Uint8Array(Buffer.from(value, "hex"));
  const aad = c.encodeContext("review-content", [
    hex(vector.deployment_id_hex),
    hex(vector.org_id_hex),
    hex(vector.review_id_hex),
    c.u64be(1),
  ]);
  const ciphertext = chacha20poly1305(
    hex(vector.key_hex),
    hex(vector.nonce_hex),
    aad,
  ).encrypt(c.utf8(JSON.stringify(vector.content)));
  assert.equal(Buffer.from(aad).toString("hex"), vector.aad_hex);
  assert.equal(Buffer.from(ciphertext).toString("hex"), vector.ciphertext_hex);
  assert.deepEqual(
    await c.openDraftContent({
      reviewId: hex(vector.review_id_hex),
      orgId: hex(vector.org_id_hex),
      contentKey: hex(vector.key_hex),
      encryptedContent: {
        v: 1,
        nonce: b64(hex(vector.nonce_hex)),
        ciphertext: b64(ciphertext),
      },
    }),
    vector.content,
  );
});

test("framing exact lengths and unsigned integers", () => {
  assert.equal(
    Buffer.from(c.encodeContext("x", [new Uint8Array([2])])).toString("hex"),
    "414e4f4e43450100017800010000000102",
  );
  assert.equal(
    Buffer.from(c.u64be("18446744073709551615")).toString("hex"),
    "ffffffffffffffff",
  );
  for (const n of ["01", "-1", "18446744073709551616", 1.5])
    assert.throws(() => c.u64be(n), CryptoError);
});

test("BIP39 exactly12 words, checksum, entropy recovery and domain separation", async () => {
  const recovery = await c.generateRecovery();
  assert.equal(recovery.words.split(" ").length, 12);
  assert.equal(recovery.entropy.length, 16);
  const args = { words: recovery.words, accountId, recoverySalt: bytes(32) };
  const keys = await c.deriveRecovery(args);
  assert.deepEqual(await c.deriveRecovery(args), keys);
  assert.notDeepEqual(keys.authSeed, keys.wrapKey);
  assert.notDeepEqual(
    (await c.deriveRecovery({ ...args, accountId: bytes(16, 2) })).authSeed,
    keys.authSeed,
  );
  for (const words of [
    "abandon ".repeat(11) + "abandon",
    recovery.words + " abandon",
    recovery.words.toUpperCase(),
    " " + recovery.words,
  ]) {
    await assert.rejects(c.deriveRecovery({ ...args, words }), CryptoError);
  }
});

test("password Argon2id, separate auth/wrap contexts and account separation", async () => {
  const kdf = {
    v: 19,
    salt: b64(bytes(16, 3)),
    memory_kib: 65536,
    iterations: 3,
    parallelism: 1,
    length: 32,
  };
  const args = { password: "example password", accountId, kdf };
  const keys = await c.derivePassword(args);
  assert.equal(keys.authSeed.length, 32);
  assert.notDeepEqual(keys.authSeed, keys.wrapKey);
  assert.deepEqual(await c.derivePassword(args), keys);
  assert.notDeepEqual(
    (await c.derivePassword({ ...args, password: "different" })).authSeed,
    keys.authSeed,
  );
  assert.notDeepEqual(
    (await c.derivePassword({ ...args, accountId: bytes(16, 2) })).authSeed,
    keys.authSeed,
  );
  await assert.rejects(
    c.derivePassword({ ...args, kdf: { ...kdf, memory_kib: 1 } }),
    CryptoError,
  );
});

test("vault wraps and objects authenticate all context and reject tamper", async () => {
  const args = {
    accountId,
    kind: "password",
    wrapperId: bytes(16, 3),
    metadataHash: bytes(32, 4),
    wrapKey: bytes(32, 5),
    masterKey: bytes(32, 6),
  };
  const wrapper = await c.wrapVaultMaster(args);
  assert.deepEqual(
    await c.unwrapVaultMaster({ ...args, wrapper }),
    args.masterKey,
  );
  for (const change of [
    { accountId: bytes(16, 2) },
    { kind: "recovery" },
    { metadataHash: bytes(32, 2) },
    { wrapKey: bytes(32, 2) },
  ]) {
    await assert.rejects(
      c.unwrapVaultMaster({ ...args, wrapper, ...change }),
      CryptoError,
    );
  }
  const ct = fromBase64url(wrapper.ciphertext);
  ct[0] ^= 1;
  await assert.rejects(
    c.unwrapVaultMaster({
      ...args,
      wrapper: { ...wrapper, ciphertext: b64(ct) },
    }),
    CryptoError,
  );
  const objectArgs = {
    accountId,
    masterKey: args.masterKey,
    objectId: bytes(16, 8),
    revision: "1",
    plaintext: c.utf8("private"),
  };
  const object = await c.sealVaultObject(objectArgs);
  assert.deepEqual(
    await c.openVaultObject({ ...objectArgs, object }),
    objectArgs.plaintext,
  );
  await assert.rejects(
    c.openVaultObject({ ...objectArgs, object: { ...object, revision: "2" } }),
    CryptoError,
  );
  await assert.rejects(
    c.openVaultObject({
      ...objectArgs,
      object: { ...object, id: b64(bytes(16, 9)) },
    }),
    CryptoError,
  );
});

test("device cache uses deployment/account-bound authenticated ChaCha encryption", async () => {
  const args = { key: bytes(32, 7), accountId, plaintext: c.utf8("cache") };
  const object = await c.sealDeviceCache(args);
  assert.deepEqual(
    await c.openDeviceCache({ ...args, object }),
    args.plaintext,
  );
  await assert.rejects(
    c.openDeviceCache({ ...args, object, accountId: bytes(16, 8) }),
    CryptoError,
  );
});

test("challenge is bound to action account payload epoch expiry and origin", async () => {
  const payloadBytes = c.utf8("{}");
  const challenge = {
    challenge_id: b64(bytes(16, 9)),
    account_id: b64(accountId),
    action: "test",
    payload_hash: b64(sha256(payloadBytes)),
    nonce: b64(bytes(32, 8)),
    credential_epoch: "1",
    expires_at: String(Math.floor(Date.now() / 1000) + 300),
  };
  const args = {
    challenge,
    expectedAction: "test",
    accountId,
    payloadBytes,
    seed: membership.seed,
  };
  assert.equal((await c.signChallenge(args)).length, 64);
  for (const change of [
    { expectedAction: "login" },
    { payloadBytes: c.utf8("[]") },
    { accountId: bytes(16, 9) },
    { challenge: { ...challenge, expires_at: "1" } },
  ])
    await assert.rejects(c.signChallenge({ ...args, ...change }), CryptoError);
  location.origin = "https://wrong.test";
  await assert.rejects(c.signChallenge(args), CryptoError);
  location.origin = init.origin;
});

test("descriptor certificate verification, strict schema, signature and review binding", async () => {
  assert.deepEqual(
    Object.keys(descriptor).sort(),
    [
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
    ].sort(),
  );
  await assert.rejects(
    c.verifyDescriptor({
      descriptorBytes,
      signature: descriptorSignature,
      expectedReviewId: bytes(16, 7),
    }),
    CryptoError,
  );
  const wrong = descriptorSignature.slice();
  wrong[0] ^= 1;
  await assert.rejects(
    c.verifyDescriptor({
      descriptorBytes,
      signature: wrong,
      expectedReviewId: reviewId,
    }),
    CryptoError,
  );
  for (const data of [
    { ...descriptorJSON, v: 1 },
    { ...descriptorJSON, v: 2 },
    { ...descriptorJSON, title: "leak" },
    ...["reviewer_account_id", "max_responses", "opens_at", "closes_at"].map(
      (key) => ({ ...descriptorJSON, [key]: null }),
    ),
    { ...descriptorJSON, suite: "alternate" },
    { ...descriptorJSON, reviewer_membership_id: b64(bytes(16, 4)) },
  ]) {
    const bytes = c.utf8(JSON.stringify(data));
    const signature = await c.signDescriptor({
      descriptorBytes: bytes,
      membershipSeed: membership.seed,
    });
    await assert.rejects(
      c.verifyDescriptor({
        descriptorBytes: bytes,
        signature,
        expectedReviewId: reviewId,
      }),
      CryptoError,
    );
  }
  const duplicate = c.utf8(
    JSON.stringify(descriptorJSON).replace('"v":3', '"v":3,"v":3'),
  );
  await assert.rejects(
    c.verifyDescriptor({
      descriptorBytes: duplicate,
      signature: descriptorSignature,
      expectedReviewId: reviewId,
    }),
    (e) => e.code === "DUPLICATE_JSON_FIELD",
  );
});

test("HPKE roundtrip, ciphertext/enc/context tamper and answers validation", async () => {
  const args = { descriptorBytes, descriptor };
  const sealed = await c.encryptResponse({
    ...args,
    answers: { q1: "Private feedback" },
  });
  const open = {
    ...args,
    ...sealed,
    recipientPrivateKey: recipient.privateKey,
  };
  assert.deepEqual((await c.decryptResponse(open)).answers, {
    q1: "Private feedback",
  });
  const ct = sealed.ciphertext.slice();
  ct[0] ^= 1;
  await assert.rejects(
    c.decryptResponse({ ...open, ciphertext: ct }),
    CryptoError,
  );
  await assert.rejects(
    c.decryptResponse({ ...open, enc: bytes(32, 8) }),
    CryptoError,
  );
  await assert.rejects(
    c.decryptResponse({ ...open, descriptorBytes: c.utf8("{}") }),
    CryptoError,
  );
  await assert.rejects(
    c.encryptResponse({ ...args, answers: {} }),
    CryptoError,
  );
  await assert.rejects(
    c.encryptResponse({ ...args, answers: { q1: "ok", unknown: "bad" } }),
    CryptoError,
  );
});

test("expired CA and leaf retain historical descriptor verification/decryption, not forged signatures", async () => {
  assert.ok(
    ca.notAfter.getTime() < Date.now() &&
      certificate.notAfter.getTime() < Date.now(),
  );
  const historical = await c.verifyDescriptor({
    descriptorBytes,
    signature: descriptorSignature,
    expectedReviewId: reviewId,
  });
  await c.openDescriptorContent({ descriptor: historical, contentKey });
  const sealed = await c.encryptResponse({
    descriptorBytes,
    descriptor: historical,
    answers: { q1: "Historical response" },
  });
  assert.equal(
    (
      await c.decryptResponse({
        descriptorBytes,
        descriptor: historical,
        recipientPrivateKey: recipient.privateKey,
        ...sealed,
      })
    ).answers.q1,
    "Historical response",
  );
  const bad = descriptorSignature.slice();
  bad[0] ^= 1;
  await assert.rejects(
    c.verifyDescriptor({
      descriptorBytes,
      signature: bad,
      expectedReviewId: reviewId,
    }),
    CryptoError,
  );
});

async function withQuestions(questions) {
  const encrypted_content = await c.sealReviewContent({
    reviewId,
    orgId: accountId,
    contentKey,
    content: { ...content, questions },
  });
  const bytes = c.utf8(
    JSON.stringify({ ...descriptorJSON, encrypted_content }),
  );
  const signature = await c.signDescriptor({
    descriptorBytes: bytes,
    membershipSeed: membership.seed,
  });
  const descriptor = await c.verifyDescriptor({
    descriptorBytes: bytes,
    signature,
    expectedReviewId: reviewId,
  });
  await c.openDescriptorContent({ descriptor, contentKey });
  return { descriptorBytes: bytes, descriptor };
}

test("aggregate UTF8 byte bounds reject multibyte and oversized encrypted responses", async () => {
  const args = { descriptorBytes, descriptor };
  // 90000 characters are within the per-text limit but need 270000 UTF8 bytes.
  await assert.rejects(
    c.encryptResponse({ ...args, answers: { q1: "界".repeat(90000) } }),
    (e) => e.code === "RESPONSE_TOO_LARGE",
  );
  const multi = await withQuestions(
    Array.from({ length: 4 }, (_, i) => ({
      id: `q${i}`,
      type: "text",
      label: "Text",
      required: false,
      choices: [],
    })),
  );
  await assert.rejects(
    c.encryptResponse({
      ...multi,
      answers: {
        q0: "x".repeat(70000),
        q1: "x".repeat(70000),
        q2: "x".repeat(70000),
        q3: "x".repeat(70000),
      },
    }),
    (e) => e.code === "RESPONSE_TOO_LARGE",
  );
  await assert.rejects(
    c.decryptResponse({
      ...args,
      recipientPrivateKey: recipient.privateKey,
      enc: bytes(32),
      ciphertext: new Uint8Array(262145),
    }),
    (e) => e.code === "RESPONSE_TOO_LARGE",
  );
  await assert.rejects(
    c.verifyDescriptor({
      descriptorBytes: new Uint8Array(65537),
      signature: descriptorSignature,
      expectedReviewId: reviewId,
    }),
    (e) => e.code === "DESCRIPTOR_TOO_LARGE",
  );
});

test("optional answers still have exact types and required prototype-name ids use own properties", async () => {
  const choices = [
    { id: "a", label: "A" },
    { id: "b", label: "B" },
  ];
  const args = await withQuestions([
    { id: "text", type: "text", label: "T", required: false, choices: [] },
    { id: "single", type: "single", label: "S", required: false, choices },
    { id: "multiple", type: "multiple", label: "M", required: false, choices },
  ]);
  for (const answers of [
    { text: [] },
    { text: null },
    { multiple: "" },
    { multiple: null },
    { single: [] },
    { single: null },
  ]) {
    await assert.rejects(
      c.encryptResponse({ ...args, answers }),
      (e) => e.code === "INVALID_ANSWER",
    );
  }
  await c.encryptResponse({ ...args, answers: {} });
  await c.encryptResponse({
    ...args,
    answers: { text: "", single: "", multiple: [] },
  });
  for (const id of ["constructor", "toString", "__proto__"]) {
    const required = await withQuestions([
      { id, type: "text", label: "Required", required: true, choices: [] },
    ]);
    await assert.rejects(
      c.encryptResponse({ ...required, answers: {} }),
      (e) => e.code === "MISSING_ANSWER",
    );
    await c.encryptResponse({
      ...required,
      answers: JSON.parse(`{"${id}":"answer"}`),
    });
  }
});

test("RFC9474 randomized blind authorization roundtrip and malformed context/signature", async () => {
  const state = await c.prepareAuthorization({ descriptorBytes, descriptor });
  assert.equal(state.serial.length, 32);
  assert.equal(state.inverse.length, 384);
  assert.equal(state.blindedMessage.length, 384);
  const blindSignature = await rsaSuite.blindSign(
    rsa.privateKey,
    state.blindedMessage,
  );
  const token = await c.finalizeAuthorization({
    descriptor,
    ...state,
    blindSignature,
  });
  assert.equal(token.signature.length, 384);
  assert.equal(
    await rsaSuite.verify(
      rsa.publicKey,
      token.signature,
      token.preparedMessage,
    ),
    true,
  );
  const preparedMessage = state.preparedMessage.slice();
  preparedMessage[40] ^= 1;
  await assert.rejects(
    c.finalizeAuthorization({
      descriptor,
      ...state,
      preparedMessage,
      blindSignature,
    }),
    CryptoError,
  );
  await assert.rejects(
    c.finalizeAuthorization({
      descriptor,
      ...state,
      blindSignature: bytes(384),
    }),
    CryptoError,
  );
});

function signedReceipt(overrides = {}, seed = receiptSeed) {
  const receipt = {
    v: 2,
    deployment_id: b64(deploymentId),
    receipt_id: b64(bytes(16, 5)),
    review_id: b64(reviewId),
    descriptor_hash: b64(bytes(32, 7)),
    issuer_key_id: b64(bytes(32, 8)),
    response_hash: b64(bytes(32, 9)),
    accepted_at: "1",
    receipt_key_id: b64(sha256(ed25519.getPublicKey(seed))),
    ...overrides,
  };
  const fields = [
    "deployment_id",
    "receipt_id",
    "review_id",
    "descriptor_hash",
    "issuer_key_id",
    "response_hash",
  ].map((k) => fromBase64url(receipt[k]));
  receipt.signature = b64(
    ed25519.sign(
      c.encodeContext("receipt-v2", [
        ...fields,
        c.u64be(receipt.accepted_at),
        fromBase64url(receipt.receipt_key_id),
      ]),
      seed,
    ),
  );
  return receipt;
}
function receiptArgs(receipt = signedReceipt(), receiptTrust = trust) {
  return {
    receipt,
    trust: receiptTrust,
    expectedDeploymentId: fromBase64url(receipt.deployment_id),
    expectedReviewId: fromBase64url(receipt.review_id),
    expectedDescriptorHash: fromBase64url(receipt.descriptor_hash),
    expectedIssuerKeyId: fromBase64url(receipt.issuer_key_id),
    expectedResponseHash: fromBase64url(receipt.response_hash),
  };
}

test("receipts require every independent context and detach verified data and trust", async () => {
  const args = receiptArgs();
  const verified = await c.verifyReceipt(args);
  assert.deepEqual(verified, args.receipt);
  assert.notEqual(verified, args.receipt);
  for (const key of Object.keys(args).filter((k) => k.startsWith("expected"))) {
    for (const value of [undefined, bytes(args[key].length, 99), bytes(1)]) {
      await assert.rejects(
        c.verifyReceipt({ ...args, [key]: value }),
        CryptoError,
      );
    }
  }
  const detached = c.getReceiptTrust();
  assert.deepEqual(detached, trust);
  detached.receipt_keys[0].receipt_public_key = "";
  assert.deepEqual(c.getReceiptTrust(), trust);
});

test("receipt exact schema, canonical encodings, timestamps and all signed fields reject mutations", async () => {
  const receipt = signedReceipt();
  for (const key of Object.keys(receipt)) {
    const changed = {
      ...receipt,
      [key]:
        key === "v"
          ? 1
          : key === "accepted_at"
            ? "2"
            : b64(bytes(fromBase64url(receipt[key]).length, 99)),
    };
    await assert.rejects(
      c.verifyReceiptSignature({ receipt: changed, trust }),
      CryptoError,
    );
    const missing = { ...receipt };
    delete missing[key];
    await assert.rejects(
      c.verifyReceiptSignature({ receipt: missing, trust }),
      CryptoError,
    );
  }
  for (const accepted_at of [
    "01",
    "-1",
    "18446744073709551616",
    "",
    1,
    "1.0",
  ]) {
    await assert.rejects(
      c.verifyReceiptSignature({ receipt: { ...receipt, accepted_at }, trust }),
      CryptoError,
    );
  }
  for (const change of [
    { extra: true },
    { signature: "AB" },
    { receipt_id: b64(bytes(15)) },
    { deployment_id: receipt.deployment_id + "=" },
  ]) {
    await assert.rejects(
      c.verifyReceiptSignature({ receipt: { ...receipt, ...change }, trust }),
      CryptoError,
    );
  }
  assert.deepEqual(
    await c.verifyReceiptSignature({
      receipt: signedReceipt({ accepted_at: "18446744073709551615" }),
      trust,
    }),
    signedReceipt({ accepted_at: "18446744073709551615" }),
  );
});

test("historical trusted receipt keys work; malformed or untrusted key sets fail closed", async () => {
  const seed = bytes(32, 77),
    key = ed25519.getPublicKey(seed);
  const entry = {
    receipt_key_id: b64(sha256(key)),
    receipt_public_key: b64(key),
  };
  const receipt = signedReceipt({}, seed);
  const historicalTrust = { ...trust, receipt_keys: [...receiptKeys, entry] };
  await c.verifyReceipt(receiptArgs(receipt, historicalTrust));
  await assert.rejects(
    c.verifyReceiptSignature({ receipt, trust }),
    CryptoError,
  );
  for (const bad of [
    { ...trust, v: 2 },
    { ...trust, extra: true },
    { ...trust, receipt_keys: [] },
    { ...trust, receipt_keys: [entry] },
    { ...trust, receipt_keys: [...receiptKeys, ...receiptKeys] },
    { ...trust, receipt_keys: [{ ...receiptKeys[0], extra: true }] },
    {
      ...trust,
      receipt_keys: [{ ...receiptKeys[0], receipt_public_key: b64(bytes(32)) }],
    },
    { ...trust, deployment_id: b64(bytes(32, 77)) },
  ])
    await assert.rejects(
      c.verifyReceiptSignature({ receipt: signedReceipt(), trust: bad }),
      CryptoError,
    );
});

test("accepted response hash binds valid replacement HPKE envelopes and every context", async () => {
  const first = await c.encryptResponse({
    descriptorBytes,
    descriptor,
    answers: { q1: "first" },
  });
  const replacement = await c.encryptResponse({
    descriptorBytes,
    descriptor,
    answers: { q1: "replacement" },
  });
  assert.equal(
    (
      await c.decryptResponse({
        descriptorBytes,
        descriptor,
        recipientPrivateKey: recipient.privateKey,
        ...replacement,
      })
    ).answers.q1,
    "replacement",
  );
  const context = {
    deploymentId,
    reviewId,
    descriptorHash: sha256(descriptorBytes),
    issuerKeyId: fromBase64url(descriptor.issuer_key_id),
    ...first,
  };
  const hash = await c.responseHash(context);
  const receipt = signedReceipt({
    descriptor_hash: b64(context.descriptorHash),
    issuer_key_id: descriptor.issuer_key_id,
    response_hash: b64(hash),
  });
  await c.verifyReceipt(receiptArgs(receipt));
  await assert.rejects(
    c.verifyReceipt({
      ...receiptArgs(receipt),
      expectedResponseHash: await c.responseHash({
        ...context,
        ...replacement,
      }),
    }),
    (e) => e.code === "RESPONSE_HASH_MISMATCH",
  );
  for (const field of Object.keys(context)) {
    const changed = context[field].slice();
    changed[0] ^= 1;
    assert.notDeepEqual(
      await c.responseHash({ ...context, [field]: changed }),
      hash,
    );
  }
  for (const ciphertext of [bytes(15), bytes(262145)])
    await assert.rejects(
      c.responseHash({ ...context, ciphertext }),
      CryptoError,
    );
});

test("shared deterministic receipt-v2 vector matches response and receipt transcripts", async () => {
  const vector = JSON.parse(
    await readFile(
      new URL("../testdata/receipt-v2.json", import.meta.url),
      "utf8",
    ),
  );
  const context = vector.context,
    envelope = vector.envelope;
  const fields = [
    "deployment_id",
    "review_id",
    "descriptor_hash",
    "issuer_key_id",
  ].map((k) => fromBase64url(context[k]));
  const transcript = c.encodeContext("accepted-response-v2", [
    ...fields,
    fromBase64url(envelope.enc),
    fromBase64url(envelope.ciphertext),
  ]);
  assert.equal(
    Buffer.from(transcript).toString("hex"),
    vector.response_transcript_hex,
  );
  const hash = await c.responseHash({
    deploymentId: fields[0],
    reviewId: fields[1],
    descriptorHash: fields[2],
    issuerKeyId: fields[3],
    enc: fromBase64url(envelope.enc),
    ciphertext: fromBase64url(envelope.ciphertext),
  });
  assert.equal(Buffer.from(hash).toString("hex"), vector.response_hash_hex);
  const receipt = vector.receipt;
  const receiptTranscript = c.encodeContext("receipt-v2", [
    fields[0],
    fromBase64url(receipt.receipt_id),
    fields[1],
    fields[2],
    fields[3],
    hash,
    c.u64be(receipt.accepted_at),
    fromBase64url(receipt.receipt_key_id),
  ]);
  assert.equal(
    Buffer.from(receiptTranscript).toString("hex"),
    vector.receipt_transcript_hex,
  );
  assert.equal(
    Buffer.from(
      ed25519.sign(receiptTranscript, Buffer.from(vector.seed_hex, "hex")),
    ).toString("hex"),
    vector.signature_hex,
  );
  assert.deepEqual(
    await portable.verifyReceipt(receiptArgs(receipt, vector.trust)),
    receipt,
  );
});
