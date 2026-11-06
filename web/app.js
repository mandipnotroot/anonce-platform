// SPDX-License-Identifier: AGPL-3.0-only
import * as C from "./crypto.bundle.js";
import { request, setCSRF, jsonBytes, toWire, APIError } from "./api.js";
import {
  saveSealed,
  loadSealed,
  allEncrypted,
  getDeviceRecord,
  putDeviceRecord,
  deleteDeviceRecord,
} from "./storage.js";

let state,
  config,
  generation = 0;
let cookieMutations = Promise.resolve(),
  cookieCSRF,
  localCSRF;
function setSessionCSRF(token) {
  localCSRF = token;
  setCSRF(token);
}
function queueCookieMutation(operation) {
  const result = cookieMutations.then(operation);
  cookieMutations = result.catch(() => {});
  return result;
}
export function getReceiptTrust() {
  return C.getReceiptTrust();
}
export async function loadReceiptTrust() {
  const config = await request("/api/public/config", { anonymous: true });
  return {
    v: 1,
    deployment_id: config.deployment_id,
    receipt_key_id: config.receipt_key_id,
    receipt_keys: config.receipt_keys,
  };
}
// Scan JSON structure before parsing so duplicate keys cannot disappear during parsing.
function receiptJSON(text) {
  const invalid = () => {
    throw new APIError("INVALID_RECEIPT", "Invalid receipt or trust JSON.");
  };
  if (
    typeof text !== "string" ||
    text.length > 65536 ||
    new TextEncoder().encode(text).length > 65536
  )
    invalid();
  let i = 0;
  const space = () => {
    while (/[\x20\t\r\n]/.test(text[i] || "!")) i++;
  };
  const string = () => {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') {
        try {
          return JSON.parse(text.slice(start, i));
        } catch {
          invalid();
        }
      }
      if (c === "\\") i++;
    }
    invalid();
  };
  function value(depth = 0) {
    if (depth > 32) invalid();
    space();
    if (text[i] === '"') {
      string();
      return;
    }
    if (text[i] === "{" || text[i] === "[") {
      const object = text[i++] === "{",
        end = object ? "}" : "]",
        keys = new Set();
      space();
      if (text[i] === end) {
        i++;
        return;
      }
      for (;;) {
        space();
        if (object) {
          if (text[i] !== '"') invalid();
          const key = string();
          if (keys.has(key)) invalid();
          keys.add(key);
          space();
          if (text[i++] !== ":") invalid();
        }
        value(depth + 1);
        space();
        if (text[i] === end) {
          i++;
          return;
        }
        if (text[i++] !== ",") invalid();
      }
    }
    const token =
      /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        text.slice(i),
      );
    if (!token) invalid();
    i += token[0].length;
  }
  value();
  space();
  if (i !== text.length) invalid();
  return JSON.parse(text);
}
export async function verifySavedReceipt({ receiptText, trustText }) {
  const receipt = receiptJSON(receiptText),
    trust = receiptJSON(trustText);
  const schema = (value, keys) =>
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
  const strings = (value, keys) =>
    keys.every((key) => typeof value[key] === "string");
  const fields = [
    "deployment_id",
    "receipt_id",
    "review_id",
    "descriptor_hash",
    "issuer_key_id",
    "response_hash",
    "accepted_at",
    "receipt_key_id",
    "signature",
  ];
  if (
    !schema(receipt, ["v", ...fields]) ||
    receipt.v !== 2 ||
    !strings(receipt, fields) ||
    !schema(trust, ["v", "deployment_id", "receipt_key_id", "receipt_keys"]) ||
    trust.v !== 1 ||
    !strings(trust, ["deployment_id", "receipt_key_id"]) ||
    !Array.isArray(trust.receipt_keys) ||
    !trust.receipt_keys.length ||
    !trust.receipt_keys.every(
      (key) =>
        schema(key, ["receipt_key_id", "receipt_public_key"]) &&
        strings(key, ["receipt_key_id", "receipt_public_key"]),
    )
  )
    throw new APIError("INVALID_RECEIPT", "Invalid receipt or trust JSON.");
  return { receipt: await C.verifyReceiptSignature({ receipt, trust }) };
}
export function getSourceURL() {
  try {
    const url = new URL(config?.source_url);
    if (url.protocol === "https:" && !url.username && !url.password)
      return url.href;
  } catch {
    /* Configuration is not loaded or is not a safe source link. */
  }
  return "https://github.com/mandipnotroot/anonce-platform";
}
async function deviceKey(
  accountId,
  create = false,
  expectedGeneration = generation,
) {
  let key = await getDeviceRecord("key:" + accountId);
  if (!key && create) {
    const raw = random(32);
    try {
      key = await crypto.subtle.importKey("raw", raw, "HKDF", false, [
        "deriveBits",
      ]);
    } finally {
      raw.fill(0);
    }
    if (generation !== expectedGeneration) return;
    await putDeviceRecord("key:" + accountId, key);
  }
  if (!key) return;
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: bytes(config.deployment_id),
        info: C.encodeContext("device-cache-key", [bytes(accountId)]),
      },
      key,
      256,
    ),
  );
}
async function cacheState() {
  const captured = state,
    expectedGeneration = generation;
  const key = await deviceKey(captured.accountId, true, expectedGeneration);
  if (!key) return;
  try {
    const object = await C.sealDeviceCache({
      key,
      accountId: bytes(captured.accountId),
      plaintext: jsonBytes(toWire(captured)),
    });
    if (generation === expectedGeneration && state === captured)
      await putDeviceRecord("cache:" + captured.accountId, object);
  } finally {
    key.fill(0);
  }
}
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const id = () => C.toBase64url(random(16));
const bytes = (x) => (typeof x === "string" ? C.fromBase64url(x) : x);
const time = (x) =>
  x
    ? /^\d+$/.test(String(x))
      ? String(x)
      : String(Math.floor(new Date(x).getTime() / 1000))
    : null;
const fail = () => {
  throw new APIError(
    "LOGIN_REQUIRED",
    "Please sign in to unlock your encrypted workspace.",
  );
};
function active() {
  return state || fail();
}
async function initialize() {
  if (!config) {
    config = await request("/api/public/config", { anonymous: true });
    await C.initCrypto({
      deploymentId: bytes(config.deployment_id),
      origin: location.origin,
      caCertificate: bytes(config.ca_certificate),
      receiptKeys: config.receipt_keys,
      receiptKeyId: bytes(config.receipt_key_id),
    });
  }
  return config;
}
function checkGeneration(expectedGeneration) {
  if (generation !== expectedGeneration)
    throw new APIError(
      "SESSION_CHANGED",
      "The session changed. Please sign in again.",
    );
}
function wipeState(captured) {
  for (const key of [
    "masterKey",
    "authSeed",
    "membershipSeed",
    "encryptionPrivateKey",
  ])
    captured?.[key]?.fill(0);
}
async function signed(
  path,
  action,
  payload,
  seeds,
  method = "POST",
  expectedGeneration = generation,
) {
  await initialize();
  const accountId = payload.account_id || state?.accountId;
  const payloadBytes = jsonBytes(toWire(payload));
  const challenge = await request("/api/member/challenges", {
    method: "POST",
    body: {
      account_id: accountId,
      action,
      payload_hash: await C.hashBytes(payloadBytes),
    },
  });
  const proof = { challenge_id: challenge.challenge_id };
  for (const [kind, seed] of Object.entries(
    seeds || { membership_sig: active().membershipSeed },
  )) {
    proof[kind] = await C.signChallenge({
      challenge,
      expectedAction: action,
      accountId: bytes(accountId),
      payloadBytes,
      seed,
    });
  }
  checkGeneration(expectedGeneration);
  return request(path, {
    method,
    body: { payload: C.toBase64url(payloadBytes), proof },
  });
}
const mutation = (path, action, payload = {}, method) =>
  signed(
    "/api/member" + path,
    action,
    { request_id: id(), ...payload },
    undefined,
    method,
  );
function sessionView(s) {
  return { ...s, accountId: s.account_id, email: state?.email };
}
async function sessionStart(accountId, authSeed, method, expectedGeneration) {
  const session = await queueCookieMutation(async () => {
    checkGeneration(expectedGeneration);
    const result = await signed(
      "/api/member/session",
      method,
      { request_id: id(), account_id: accountId, method },
      {
        [method === "login-password" ? "password_sig" : "recovery_sig"]:
          authSeed,
      },
      "POST",
      expectedGeneration,
    );
    const session = result.session || result;
    // Even a canceled login may have installed an HttpOnly cookie.
    cookieCSRF = session.csrf_token;
    return session;
  });
  checkGeneration(expectedGeneration);
  setSessionCSRF(session.csrf_token);
  return session;
}
async function vaultOpen(accountId, derived, kind) {
  const vault = await request("/api/member/vault");
  const metadataHash =
    kind === "password"
      ? await C.passwordMetadataHash(vault.password_kdf)
      : await C.recoveryMetadataHash(bytes(vault.recovery_salt));
  const masterKey = await C.unwrapVaultMaster({
    accountId: bytes(accountId),
    kind,
    metadataHash,
    wrapKey: derived.wrapKey,
    wrapper: vault[kind + "_wrap"],
  });
  let membershipSeed, encryptionPrivateKey;
  for (const object of vault.vault_objects || vault.objects || []) {
    const raw = await C.openVaultObject({
      accountId: bytes(accountId),
      masterKey,
      object,
    });
    const value = JSON.parse(new TextDecoder().decode(raw));
    if (value.kind === "membership") {
      if (
        membershipSeed ||
        value.v !== 1 ||
        Object.keys(value).sort().join(",") !==
          "encryption_private_key,kind,seed,v" ||
        !canonical(value.seed, 32) ||
        !canonical(value.encryption_private_key, 32)
      )
        throw keyUnavailable();
      membershipSeed = bytes(value.seed);
      encryptionPrivateKey = bytes(value.encryption_private_key);
    }
  }
  if (!membershipSeed)
    throw new APIError(
      "VAULT_INVALID",
      "The encrypted membership key is unavailable.",
    );
  await validateMemberKeys(
    { accountId, membershipSeed, encryptionPrivateKey },
    vault,
  );
  return { masterKey, membershipSeed, encryptionPrivateKey, vault };
}
async function validateMemberKeys(s, vault) {
  const membershipPublicKey = await C.membershipPublicKey({
    seed: s.membershipSeed,
  });
  const encryptionPublicKey = await C.memberEncryptionPublicKey({
    privateKey: s.encryptionPrivateKey,
  });
  if (C.toBase64url(encryptionPublicKey) !== vault.encryption_public_key)
    throw keyUnavailable();
  await C.verifyMemberEncryptionKeyBinding({
    deploymentId: bytes(config.deployment_id),
    accountId: bytes(s.accountId),
    membershipPublicKey,
    encryptionPublicKey,
    signature: bytes(vault.encryption_key_signature),
  });
}
export async function getSession() {
  if (state) return sessionView(state.session);
  const expectedGeneration = ++generation;
  try {
    await initialize();
    await cookieMutations;
    checkGeneration(expectedGeneration);
    const result = await request("/api/member/me"),
      s = result.session || result;
    checkGeneration(expectedGeneration);
    cookieCSRF = s.csrf_token;
    setSessionCSRF(s.csrf_token);
    const key = await deviceKey(s.account_id),
      object = await getDeviceRecord("cache:" + s.account_id);
    if (!key || !object) return null;
    try {
      const cached = JSON.parse(
        new TextDecoder().decode(
          await C.openDeviceCache({
            key,
            accountId: bytes(s.account_id),
            object,
          }),
        ),
      );
      if (cached.session.credential_epoch !== s.credential_epoch) return null;
      const restored = {
        ...cached,
        masterKey: bytes(cached.masterKey),
        authSeed: bytes(cached.authSeed),
        membershipSeed: bytes(cached.membershipSeed),
        encryptionPrivateKey: bytes(cached.encryptionPrivateKey),
        session: s,
      };
      await validateMemberKeys(restored, await request("/api/member/vault"));
      if (generation !== expectedGeneration) {
        wipeState(restored);
        return null;
      }
      state = restored;
      return sessionView(s);
    } finally {
      key.fill(0);
    }
  } catch (e) {
    if (generation !== expectedGeneration) return null;
    if (e.code === "unauthenticated" || e.code === "UNAUTHENTICATED")
      return null;
    throw e;
  }
  return null;
}
export async function login({ email, password }) {
  const expectedGeneration = ++generation;
  await initialize();
  const params = await request("/api/member/auth/params", {
    method: "POST",
    body: { email },
  });
  const derived = await C.derivePassword({
    password,
    accountId: bytes(params.account_id),
    kdf: params.password_kdf,
  });
  let session = await sessionStart(
    params.account_id,
    derived.authSeed,
    "login-password",
    expectedGeneration,
  );
  session = { ...session, ...(await request("/api/member/me")) };
  const unlocked = await vaultOpen(params.account_id, derived, "password");
  if (generation !== expectedGeneration) {
    wipeState({ ...unlocked, authSeed: derived.authSeed });
    checkGeneration(expectedGeneration);
  }
  state = {
    ...unlocked,
    accountId: params.account_id,
    authSeed: derived.authSeed,
    email,
    session,
    params,
  };
  await cacheState();
  checkGeneration(expectedGeneration);
  return sessionView(session);
}
function kdf() {
  return {
    v: 19,
    salt: random(16),
    memory_kib: 65536,
    iterations: 3,
    parallelism: 1,
    length: 32,
  };
}
async function credentials(accountId, password) {
  const passwordKdf = kdf(),
    recoverySalt = random(32),
    recovery = await C.generateRecovery();
  const p = await C.derivePassword({
    password,
    accountId: bytes(accountId),
    kdf: toWire(passwordKdf),
  });
  const r = await C.deriveRecovery({
    words: recovery.words,
    accountId: bytes(accountId),
    recoverySalt,
  });
  return { passwordKdf, recoverySalt, recovery, p, r };
}
async function wrapper(accountId, kind, material, metadataHash, masterKey) {
  return C.wrapVaultMaster({
    accountId: bytes(accountId),
    kind,
    wrapperId: random(16),
    metadataHash,
    wrapKey: material.wrapKey,
    masterKey,
  });
}
export async function register({ email, password }) {
  await initialize();
  const accountId = id(),
    masterKey = random(32),
    membership = await C.generateMembershipKey(),
    encryption = await C.generateMemberEncryptionKeyPair();
  const cr = await credentials(accountId, password);
  const object = await C.sealVaultObject({
    accountId: bytes(accountId),
    masterKey,
    objectId: random(16),
    revision: "1",
    plaintext: jsonBytes({
      v: 1,
      kind: "membership",
      encryption_private_key: C.toBase64url(encryption.privateKey),
      seed: C.toBase64url(membership.seed),
    }),
  });
  await signed(
    "/api/member/register",
    "register",
    {
      request_id: id(),
      account_id: accountId,
      email,
      password_kdf: cr.passwordKdf,
      password_auth_public_key: await C.authenticationPublicKey({
        authSeed: cr.p.authSeed,
      }),
      recovery_salt: cr.recoverySalt,
      recovery_auth_public_key: await C.authenticationPublicKey({
        authSeed: cr.r.authSeed,
      }),
      membership_public_key: membership.publicKey,
      encryption_public_key: encryption.publicKey,
      encryption_key_signature: await C.signMemberEncryptionKeyBinding({
        deploymentId: bytes(config.deployment_id),
        accountId: bytes(accountId),
        membershipPublicKey: membership.publicKey,
        encryptionPublicKey: encryption.publicKey,
        membershipSeed: membership.seed,
      }),
      password_wrap: await wrapper(
        accountId,
        "password",
        cr.p,
        await C.passwordMetadataHash(toWire(cr.passwordKdf)),
        masterKey,
      ),
      recovery_wrap: await wrapper(
        accountId,
        "recovery",
        cr.r,
        await C.recoveryMetadataHash(cr.recoverySalt),
        masterKey,
      ),
      vault_objects: [object],
    },
    {
      password_sig: cr.p.authSeed,
      recovery_sig: cr.r.authSeed,
      membership_sig: membership.seed,
    },
  );
  const session = await login({ email, password });
  return { session, recoveryWords: cr.recovery.words.split(" ") };
}
export async function logout() {
  generation++;
  pendingCreates.clear();
  const captured = state;
  state = undefined;
  setSessionCSRF(undefined);
  wipeState(captured);
  await queueCookieMutation(async () => {
    const results = await Promise.allSettled([
      Promise.resolve().then(() => {
        // request captures CSRF synchronously; do not expose cookie-only CSRF to UI work.
        setCSRF(cookieCSRF);
        try {
          return request("/api/member/session", { method: "DELETE" });
        } finally {
          setCSRF(localCSRF);
        }
      }),
      Promise.resolve().then(async () => {
        if (!captured) return;
        const cleanup = await Promise.allSettled([
          deleteDeviceRecord("key:" + captured.accountId),
          deleteDeviceRecord("cache:" + captured.accountId),
        ]);
        const failure = cleanup.find((result) => result.status === "rejected");
        if (failure) throw failure.reason;
      }),
    ]);
    if (results[0].status === "fulfilled") cookieCSRF = undefined;
    const failure = results.find((result) => result.status === "rejected");
    if (failure) throw failure.reason;
  });
}
const normalizeQuestion = (q) => ({
  id: q.id,
  text: q.label,
  type: q.type,
  required: q.required,
  options: (q.choices || []).map((c) => c.label),
});
function reviewView(r, content) {
  return {
    ...r,
    ...content,
    content,
    contentState: content ? "open" : "locked",
    completedOnThisBrowser: false,
    id: r.id || r.review_id,
    status: r.status || r.state,
    questions: content?.questions.map(normalizeQuestion) || [],
    ...(r.is_creator === true
      ? {
          maxResponses: r.max_responses,
          opensAt: r.opens_at,
          closesAt: r.closes_at,
        }
      : {}),
  };
}
function canonical(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value))
    return false;
  try {
    const raw = bytes(value);
    return raw.length === length && C.toBase64url(raw) === value;
  } catch {
    return false;
  }
}
const keyUnavailable = () =>
  new APIError("KEY_UNAVAILABLE", "The encrypted review keys are unavailable.");
async function reviewKeys(reviewId) {
  const s = active(),
    vault = await request("/api/member/vault");
  const object = (vault.vault_objects || vault.objects || []).find(
    (o) => o.id === reviewId,
  );
  if (!object || String(object.revision) !== "1") throw keyUnavailable();
  try {
    const value = receiptJSON(
      new TextDecoder("utf-8", { fatal: true }).decode(
        await C.openVaultObject({
          accountId: bytes(s.accountId),
          masterKey: s.masterKey,
          object,
        }),
      ),
    );
    const fields = [
      "v",
      "kind",
      "review_id",
      "content_key",
      "recipient_private_key",
    ];
    if (
      !value ||
      Object.keys(value).length !== fields.length ||
      !fields.every((k) => Object.hasOwn(value, k)) ||
      value.v !== 1 ||
      value.kind !== "review-keys" ||
      value.review_id !== reviewId ||
      !canonical(reviewId, 16) ||
      !canonical(value.content_key, 32) ||
      !canonical(value.recipient_private_key, 32)
    )
      throw keyUnavailable();
    return {
      contentKey: bytes(value.content_key),
      privateKey: bytes(value.recipient_private_key),
    };
  } catch {
    throw keyUnavailable();
  }
}
function validateContent(content) {
  return C.validateReviewContent(content);
}
async function memberContentKey(r, p) {
  if (r.is_creator === true)
    return (await reviewKeys(r.review_id || r.id)).contentKey;
  const s = active();
  if (!r.content_key_envelope || !s.encryptionPrivateKey)
    throw keyUnavailable();
  const membership = s.session.memberships?.find((m) => m.org_id === r.org_id);
  const membershipId = membership?.membership_id || membership?.id;
  if (!membershipId || r.content_key_envelope.membership_id !== membershipId)
    throw keyUnavailable();
  return C.openReviewContentKey({
    descriptor: p.descriptor,
    descriptorBytes: p.descriptorBytes,
    membershipId: bytes(membershipId),
    encryptionPrivateKey: s.encryptionPrivateKey,
    envelope: r.content_key_envelope,
  });
}
async function completedHere(reviewId) {
  const s = active();
  for (const object of await allEncrypted()) {
    try {
      const p = JSON.parse(
        new TextDecoder().decode(
          await C.openVaultObject({
            accountId: bytes(s.accountId),
            masterKey: s.masterKey,
            object,
          }),
        ),
      );
      if (
        p.reviewId !== reviewId ||
        !p.receipt ||
        !p.submission ||
        p.submission.enc !== p.encrypted.enc ||
        p.submission.ciphertext !== p.encrypted.ciphertext ||
        p.submission.review_id !== reviewId
      )
        continue;
      const descriptorBytes = bytes(p.descriptor);
      const descriptor = await C.verifyDescriptor({
        descriptorBytes,
        signature: bytes(p.descriptorSignature),
        expectedReviewId: bytes(reviewId),
      });
      if (p.submission.issuer_key_id !== descriptor.issuer_key_id) continue;
      await verifyEnvelopeReceipt(
        { descriptorBytes, descriptor },
        p.submission,
        p.receipt,
      );
      return true;
    } catch {
      /* Invalid local records are not evidence of completion. */
    }
  }
  return false;
}
async function openedReview(r, contentKey) {
  const reviewId = r.review_id || r.id;
  let view;
  try {
    if ((r.state || r.status) !== "draft") {
      const p = await publicDescriptor(reviewId);
      contentKey ||= await memberContentKey(r, p);
      view = reviewView(
        { ...r, descriptor: p.descriptor },
        await C.openDescriptorContent({ descriptor: p.descriptor, contentKey }),
      );
    } else {
      if (r.is_creator !== true) throw keyUnavailable();
      contentKey ||= (await reviewKeys(reviewId)).contentKey;
      view = reviewView(
        r,
        await C.openDraftContent({
          reviewId: bytes(reviewId),
          orgId: bytes(r.org_id),
          contentKey,
          encryptedContent: r.encrypted_content,
        }),
      );
    }
  } catch {
    view = reviewView(r);
  }
  view.completedOnThisBrowser = await completedHere(reviewId);
  return view;
}
const list = (r, fn = (x) => x) => ({
  items: (r.items || []).map(fn),
  next: r.next ?? null,
});
export const listOrganizations = async () =>
  list(await request("/api/member/orgs"), (o) => ({
    ...o,
    id: o.org_id || o.id,
    status: o.status || o.state,
  }));
export const createOrganization = ({ name }) =>
  mutation("/orgs", "org-create", { name });
export const listMembers = async ({ orgId }) =>
  list(await request(`/api/member/orgs/${orgId}/members`));
export const addMember = ({ orgId, email, role }) =>
  mutation(`/orgs/${orgId}/members`, "member-add", { email, role });
export const createInvite = async ({ orgId, role, expiresAt }) => {
  const result = await mutation(`/orgs/${orgId}/invites`, "invite-create", {
    role,
    expires_at: time(expiresAt),
  });
  return { token: result.token || result.invite_token };
};
export const acceptInvite = ({ token }) =>
  mutation("/invites/accept", "invite-accept", { invite_token: token });
export const approveMember = ({ orgId, memberId }) =>
  mutation(`/orgs/${orgId}/members/${memberId}/approve`, "member-approve");
export const revokeMember = ({ orgId, memberId }) =>
  mutation(`/orgs/${orgId}/members/${memberId}/revoke`, "member-revoke");
export const changeMemberRole = ({ orgId, memberId, role }) =>
  mutation(`/orgs/${orgId}/members/${memberId}/role`, "member-role", { role });
export const listReviews = async ({ orgId, after }) => {
  const r = await request(
    `/api/member/orgs/${orgId}/reviews${after ? "?after=" + encodeURIComponent(after) : ""}`,
  );
  return {
    items: await Promise.all((r.items || []).map((r) => openedReview(r))),
    next: r.next ?? null,
  };
};
export async function getReview({ reviewId }) {
  await initialize();
  return openedReview(await request(`/api/member/reviews/${reviewId}`));
}
const pendingCreates = new Map();
export async function createReview({ orgId, title, maxResponses = 1 }) {
  const s = active();
  await initialize();
  const slot = s.accountId + ":" + orgId;
  let pending = pendingCreates.get(slot) || s.pendingReviewCreates?.[orgId];
  if (pending) pending.contentKey = bytes(pending.contentKey);
  if (!pending) {
    const reviewId = id(),
      contentKey = random(32),
      recipient = await C.generateRecipientKey(),
      content = validateContent({
        v: 1,
        title,
        description: "",
        questions: [],
      });
    const object = await C.sealVaultObject({
      accountId: bytes(s.accountId),
      masterKey: s.masterKey,
      objectId: bytes(reviewId),
      revision: "1",
      plaintext: jsonBytes({
        v: 1,
        kind: "review-keys",
        review_id: reviewId,
        content_key: C.toBase64url(contentKey),
        recipient_private_key: C.toBase64url(recipient.privateKey),
      }),
    });
    pending = {
      content,
      contentKey,
      payload: toWire({
        request_id: id(),
        review_id: reviewId,
        encrypted_content: await C.sealReviewContent({
          reviewId: bytes(reviewId),
          orgId: bytes(orgId),
          contentKey,
          content,
        }),
        max_responses: maxResponses,
        vault_write: { expected_revision: "0", object },
      }),
    };
    pendingCreates.set(slot, pending);
    (s.pendingReviewCreates ||= {})[orgId] = pending;
    await cacheState();
  } else {
    try {
      const r = await request(
        `/api/member/reviews/${pending.payload.review_id}`,
      );
      const view = await openedReview(r, pending.contentKey);
      pendingCreates.delete(slot);
      delete s.pendingReviewCreates?.[orgId];
      await cacheState();
      return view;
    } catch (e) {
      if (!["NOT_FOUND", "not_found"].includes(e.code)) throw e;
    }
  }
  const r = await signed(
    `/api/member/orgs/${orgId}/reviews`,
    "review-create",
    pending.payload,
  );
  pendingCreates.delete(slot);
  delete s.pendingReviewCreates?.[orgId];
  await cacheState();
  return reviewView(r, pending.content);
}
export async function updateReview({
  reviewId,
  expectedRevision,
  title,
  description,
  questions,
  maxResponses,
  opensAt,
  closesAt,
}) {
  const old = await request(`/api/member/reviews/${reviewId}`),
    keys = await reviewKeys(reviewId);
  const previous = await C.openDraftContent({
    reviewId: bytes(reviewId),
    orgId: bytes(old.org_id),
    contentKey: keys.contentKey,
    encryptedContent: old.encrypted_content,
  });
  const wireQuestions = questions.map((q, i) => ({
    id: q.id || previous.questions[i]?.id || id(),
    type: q.type,
    label: q.text,
    required: !!q.required,
    choices: (q.options || []).map((label) => ({
      id:
        previous.questions
          .find((x) => x.id === q.id)
          ?.choices?.find((c) => c.label === label)?.id || id(),
      label,
    })),
  }));
  const content = validateContent({
    v: 1,
    title,
    description,
    questions: wireQuestions,
  });
  const encrypted_content = await C.sealReviewContent({
    reviewId: bytes(reviewId),
    orgId: bytes(old.org_id),
    contentKey: keys.contentKey,
    content,
  });
  return reviewView(
    await mutation(
      `/reviews/${reviewId}`,
      "review-update",
      {
        expected_revision: String(expectedRevision),
        encrypted_content,
        max_responses: maxResponses,
        opens_at: time(opensAt),
        closes_at: time(closesAt),
      },
      "PUT",
    ),
    content,
  );
}
export const closeReview = ({ reviewId, expectedRevision }) =>
  mutation(`/reviews/${reviewId}/close`, "review-close", {
    expected_revision: String(expectedRevision),
  });
export async function deleteReview({ reviewId, expectedRevision }) {
  const result = await mutation(
    `/reviews/${reviewId}`,
    "review-delete",
    { expected_revision: String(expectedRevision) },
    "DELETE",
  );
  for (const [slot, pending] of pendingCreates)
    if (pending.payload.review_id === reviewId) pendingCreates.delete(slot);
  if (state?.pendingReviewCreates)
    for (const [orgId, pending] of Object.entries(state.pendingReviewCreates))
      if (pending.payload.review_id === reviewId)
        delete state.pendingReviewCreates[orgId];
  if (state) await cacheState();
  return result;
}
async function publicDescriptor(reviewId) {
  const p = await request(`/api/public/reviews/${reviewId}`, {
    anonymous: true,
  });
  const descriptorBytes = bytes(p.descriptor);
  const descriptor = await C.verifyDescriptor({
    descriptorBytes,
    signature: bytes(p.descriptor_signature),
    expectedReviewId: bytes(reviewId),
  });
  return { ...p, descriptorBytes, descriptor };
}
async function credentialChange({
  currentPassword,
  newPassword,
  recoveryOnly = false,
}) {
  const s = active(),
    accountId = s.accountId,
    expectedGeneration = generation;
  const old = await C.derivePassword({
    password: currentPassword,
    accountId: bytes(accountId),
    kdf: s.params.password_kdf,
  });
  let recovery;
  const payload = {
    request_id: id(),
    expected_epoch: s.session.credential_epoch,
  };
  let proofs = { password_sig: old.authSeed };
  if (recoveryOnly) {
    recovery = await C.generateRecovery();
    const recoverySalt = random(32),
      r = await C.deriveRecovery({
        words: recovery.words,
        accountId: bytes(accountId),
        recoverySalt,
      });
    Object.assign(payload, {
      recovery_salt: recoverySalt,
      recovery_auth_public_key: await C.authenticationPublicKey({
        authSeed: r.authSeed,
      }),
      recovery_wrap: await wrapper(
        accountId,
        "recovery",
        r,
        await C.recoveryMetadataHash(recoverySalt),
        s.masterKey,
      ),
    });
    proofs.new_recovery_sig = r.authSeed;
  } else {
    const passwordKdf = kdf(),
      p = await C.derivePassword({
        password: newPassword,
        accountId: bytes(accountId),
        kdf: toWire(passwordKdf),
      });
    Object.assign(payload, {
      password_kdf: passwordKdf,
      password_auth_public_key: await C.authenticationPublicKey({
        authSeed: p.authSeed,
      }),
      password_wrap: await wrapper(
        accountId,
        "password",
        p,
        await C.passwordMetadataHash(toWire(passwordKdf)),
        s.masterKey,
      ),
    });
    proofs.new_password_sig = p.authSeed;
  }
  await signed(
    "/api/member/credentials/" + (recoveryOnly ? "recovery" : "password"),
    recoveryOnly ? "recovery-rotate" : "password-change",
    payload,
    proofs,
    "POST",
    expectedGeneration,
  );
  const session = await loginAfterCredentialChange(
    { email: s.email, password: newPassword || currentPassword },
    expectedGeneration,
  );
  if (!session)
    return recoveryOnly
      ? {
          session: null,
          recoveryWords: recovery.words.split(" "),
          reauthenticationRequired: true,
        }
      : { reauthenticationRequired: true };
  return recoveryOnly
    ? { session, recoveryWords: recovery.words.split(" ") }
    : session;
}
export const changePassword = (options) => credentialChange(options);
export const rotateRecovery = (options) =>
  credentialChange({ ...options, recoveryOnly: true });
async function loginAfterCredentialChange(options, expectedGeneration) {
  if (generation !== expectedGeneration) return null;
  wipeState(state);
  state = undefined;
  setSessionCSRF(undefined);
  const loginGeneration = generation + 1;
  try {
    return await login(options);
  } catch {
    // Login may set state before device-cache persistence fails.
    if (generation === loginGeneration) {
      wipeState(state);
      state = undefined;
      setSessionCSRF(undefined);
    }
    return null;
  }
}
export async function recover({ email, words, newPassword }) {
  const expectedGeneration = ++generation;
  await initialize();
  const params = await request("/api/member/auth/params", {
      method: "POST",
      body: { email },
    }),
    accountId = params.account_id;
  const old = await C.deriveRecovery({
    words,
    accountId: bytes(accountId),
    recoverySalt: bytes(params.recovery_salt),
  });
  const session = await sessionStart(
    accountId,
    old.authSeed,
    "login-recovery",
    expectedGeneration,
  );
  const unlocked = await vaultOpen(accountId, old, "recovery");
  if (generation !== expectedGeneration) {
    wipeState({ ...unlocked, authSeed: old.authSeed });
    checkGeneration(expectedGeneration);
  }
  state = {
    ...unlocked,
    accountId,
    session,
    email,
    params,
    authSeed: old.authSeed,
  };
  const cr = await credentials(accountId, newPassword);
  checkGeneration(expectedGeneration);
  await signed(
    "/api/member/credentials/reset",
    "credential-reset",
    {
      request_id: id(),
      expected_epoch: session.credential_epoch,
      password_kdf: cr.passwordKdf,
      password_auth_public_key: await C.authenticationPublicKey({
        authSeed: cr.p.authSeed,
      }),
      password_wrap: await wrapper(
        accountId,
        "password",
        cr.p,
        await C.passwordMetadataHash(toWire(cr.passwordKdf)),
        unlocked.masterKey,
      ),
      recovery_salt: cr.recoverySalt,
      recovery_auth_public_key: await C.authenticationPublicKey({
        authSeed: cr.r.authSeed,
      }),
      recovery_wrap: await wrapper(
        accountId,
        "recovery",
        cr.r,
        await C.recoveryMetadataHash(cr.recoverySalt),
        unlocked.masterKey,
      ),
      vault_writes: [],
    },
    {
      recovery_sig: old.authSeed,
      new_password_sig: cr.p.authSeed,
      new_recovery_sig: cr.r.authSeed,
    },
    "POST",
    expectedGeneration,
  );
  const nextSession = await loginAfterCredentialChange(
    { email, password: newPassword },
    expectedGeneration,
  );
  return {
    session: nextSession,
    recoveryWords: cr.recovery.words.split(" "),
    ...(!nextSession ? { reauthenticationRequired: true } : {}),
  };
}
async function seal(objectId, value, revision = "1") {
  const s = active();
  return saveSealed({
    accountId: bytes(s.accountId),
    masterKey: s.masterKey,
    objectId: bytes(objectId),
    revision,
    value,
    sealVaultObject: C.sealVaultObject,
  });
}
async function local(objectId) {
  const s = active();
  const cached = await loadSealed({
    accountId: bytes(s.accountId),
    masterKey: s.masterKey,
    objectId: bytes(objectId),
    openVaultObject: C.openVaultObject,
  });
  if (cached) return cached;
  const vault = await request("/api/member/vault"),
    object = vault.objects.find((o) => o.id === objectId);
  if (!object) return;
  const p = JSON.parse(
    new TextDecoder().decode(
      await C.openVaultObject({
        accountId: bytes(s.accountId),
        masterKey: s.masterKey,
        object,
      }),
    ),
  );
  if (p.authorization) {
    const descriptor = JSON.parse(
      new TextDecoder().decode(bytes(p.descriptor)),
    );
    // Restore sealVaultObject's property order after JSONB storage reorders keys.
    const issuanceObject = {
      v: object.v,
      id: object.id,
      revision: object.revision,
      nonce: object.nonce,
      ciphertext: object.ciphertext,
    };
    p.issuancePayload = {
      request_id: p.requestId,
      issuer_key_id: descriptor.issuer_key_id,
      blinded_message: p.authorization.blindedMessage,
      pending_state: { expected_revision: "0", object: issuanceObject },
    };
  }
  await pendingSave(p);
  return p;
}
async function ensureCertificate(orgId) {
  const certificate = await request(`/api/member/orgs/${orgId}/certificate`);
  if (
    certificate.expires_at !== undefined &&
    BigInt(certificate.expires_at) <=
      BigInt(Math.floor(Date.now() / 1000) + 7 * 24 * 3600)
  ) {
    return mutation(`/orgs/${orgId}/certificate/renew`, "certificate-renew");
  }
  return certificate;
}
export async function listPendingResponses() {
  const s = active(),
    vault = await request("/api/member/vault"),
    found = new Map();
  for (const object of [...vault.objects, ...(await allEncrypted())]) {
    if (!object?.ciphertext || !object?.id) continue;
    let p;
    try {
      p = JSON.parse(
        new TextDecoder().decode(
          await C.openVaultObject({
            accountId: bytes(s.accountId),
            masterKey: s.masterKey,
            object,
          }),
        ),
      );
    } catch {
      continue;
    }
    if (!p.pendingId || !p.reviewId) continue;
    const old = found.get(p.pendingId);
    if (!old || Number(p.revision) > Number(old.revision))
      found.set(p.pendingId, p);
  }
  return {
    items: [...found.values()]
      .filter((p) => !p.receipt)
      .map((p) => ({
        pendingId: p.pendingId,
        reviewId: p.reviewId,
        title: p.title || "Encrypted review",
        status: "pending",
      })),
    next: null,
  };
}
async function contentRecipients(reviewId, orgId) {
  const recipients = [],
    ids = new Set(),
    cursors = new Set();
  let after;
  let previous;
  do {
    const page = await request(
      `/api/member/reviews/${reviewId}/content-recipients${after ? "?after=" + encodeURIComponent(after) : ""}`,
    );
    if (!Array.isArray(page.items)) throw keyUnavailable();
    for (const recipient of page.items) {
      if (
        !canonical(recipient.membership_id, 16) ||
        ids.has(recipient.membership_id) ||
        (previous !== undefined && recipient.membership_id <= previous)
      )
        throw keyUnavailable();
      previous = recipient.membership_id;
      ids.add(recipient.membership_id);
      recipients.push(
        await C.verifyContentRecipient({ orgId: bytes(orgId), recipient }),
      );
    }
    const next = page.next;
    if (
      next != null &&
      (!page.items.length ||
        next !== page.items.at(-1).membership_id ||
        cursors.has(next))
    )
      throw keyUnavailable();
    if (next != null) cursors.add(next);
    after = next;
  } while (after != null);
  return recipients;
}
export async function publishReview({ reviewId, expectedRevision }) {
  return publishWithRosterRetry(reviewId, expectedRevision, true);
}
async function publishWithRosterRetry(
  reviewId,
  expectedRevision,
  rebuildAllowed,
) {
  const s = active();
  const existing = s.pendingReviewPublishes?.[reviewId];
  if (existing) return sendPublication(reviewId, existing, rebuildAllowed);
  const r = await request(`/api/member/reviews/${reviewId}`),
    cert = await ensureCertificate(r.org_id);
  const keys = await reviewKeys(reviewId);
  const content = await C.openDraftContent({
    reviewId: bytes(reviewId),
    orgId: bytes(r.org_id),
    contentKey: keys.contentKey,
    encryptedContent: r.encrypted_content,
  });
  C.validateReviewContent(content, { publish: true });
  const descriptor = {
    v: 3,
    deployment_id: config.deployment_id,
    review_id: reviewId,
    org_id: r.org_id,
    reviewer_membership_id:
      cert.membership_id ||
      s.session.memberships?.find((m) => m.org_id === r.org_id)?.id,
    reviewer_certificate: cert.certificate,
    encrypted_content: r.encrypted_content,
    recipient_public_key: C.toBase64url(
      await C.recipientPublicKey({ privateKey: keys.privateKey }),
    ),
    issuer_key_id: r.issuer_key_id,
    issuer_public_key: r.issuer_public_key,
  };
  const descriptorBytes = jsonBytes(descriptor);
  if (descriptorBytes.length > 65536)
    throw new APIError("INVALID_CONTENT", "Review descriptor is too large.");
  const content_key_envelopes = [];
  for (const recipient of await contentRecipients(reviewId, r.org_id)) {
    content_key_envelopes.push(
      await C.sealReviewContentKey({
        descriptorBytes,
        orgId: bytes(r.org_id),
        reviewId: bytes(reviewId),
        membershipId: recipient.membershipId,
        encryptionPublicKey: recipient.encryptionPublicKey,
        contentKey: keys.contentKey,
      }),
    );
  }
  const payload = toWire({
    request_id: id(),
    expected_revision: String(expectedRevision),
    descriptor: descriptorBytes,
    descriptor_signature: await C.signDescriptor({
      descriptorBytes,
      membershipSeed: s.membershipSeed,
    }),
    content_key_envelopes,
  });
  if (jsonBytes(payload).length > 1536 * 1024)
    throw new APIError("INVALID_CONTENT", "Publication payload is too large.");
  (s.pendingReviewPublishes ||= {})[reviewId] = payload;
  await cacheState();
  return sendPublication(reviewId, payload, rebuildAllowed);
}
async function sendPublication(reviewId, payload, rebuildAllowed) {
  const s = active();
  try {
    const result = await signed(
      `/api/member/reviews/${reviewId}/publish`,
      "review-publish",
      payload,
    );
    delete s.pendingReviewPublishes[reviewId];
    await cacheState();
    return result;
  } catch (e) {
    const status = e.status ?? e.statusCode;
    // Unknown outcomes keep the exact request, including malformed success replies.
    if (status >= 500) throw e;
    if (["recipient_set_conflict", "RECIPIENT_SET_CONFLICT"].includes(e.code)) {
      delete s.pendingReviewPublishes[reviewId];
      await cacheState();
      if (rebuildAllowed)
        return publishWithRosterRetry(
          reviewId,
          payload.expected_revision,
          false,
        );
    } else if (status >= 400 && status < 500) {
      delete s.pendingReviewPublishes[reviewId];
      await cacheState();
    }
    throw e;
  }
}

async function pendingSave(p) {
  await seal(p.pendingId, p, String(p.revision || 1));
}
// Only the authenticated issuance copy is padded; local pending objects stay unchanged.
async function sealIssuancePending(p) {
  const plaintext = jsonBytes(toWire(p)),
    size = 524288;
  if (plaintext.length > size)
    throw new APIError(
      "INVALID_RESPONSE",
      "The response could not be prepared.",
    );
  const padded = new Uint8Array(size).fill(0x20);
  padded.set(plaintext);
  const s = active();
  return C.sealVaultObject({
    accountId: bytes(s.accountId),
    masterKey: s.masterKey,
    objectId: bytes(p.pendingId),
    revision: "1",
    plaintext: padded,
  });
}
export async function prepareResponse({ reviewId, answers }) {
  active();
  const p = await publicDescriptor(reviewId);
  const review = await request(`/api/member/reviews/${reviewId}`);
  const contentKey = await memberContentKey(review, p);
  const content = await C.openDescriptorContent({
    descriptor: p.descriptor,
    contentKey,
  });
  const answerMap = Object.fromEntries(
    answers
      .filter((a) => a.value !== null && a.value !== undefined)
      .map((a) => {
        const q = content.questions.find((q) => q.id === a.questionId);
        const convert = (v) =>
          q?.type === "text"
            ? v
            : q?.choices.find((c) => c.label === v || c.id === v)?.id || v;
        return [
          a.questionId,
          Array.isArray(a.value) ? a.value.map(convert) : convert(a.value),
        ];
      }),
  );
  const pendingId = id();
  const encrypted = await C.encryptResponse({ ...p, answers: answerMap });
  const authorization = await C.prepareAuthorization(p);
  const pending = {
    pendingId,
    reviewId,
    requestId: id(),
    descriptor: C.toBase64url(p.descriptorBytes),
    descriptorSignature: p.descriptor_signature,
    title: content.title,
    authorization: toWire(authorization),
    encrypted: toWire(encrypted),
    revision: 1,
  };
  await pendingSave(pending);
  return { pendingId };
}
async function finishPending(p) {
  const descriptorBytes = bytes(p.descriptor),
    descriptor = await C.verifyDescriptor({
      descriptorBytes,
      signature: bytes(p.descriptorSignature),
      expectedReviewId: bytes(p.reviewId),
    });
  if (!p.submission) {
    if (!p.issuancePayload) {
      await ensureCertificate(descriptor.org_id);
      const object = await sealIssuancePending(p);
      p.issuancePayload = toWire({
        request_id: p.requestId,
        issuer_key_id: descriptor.issuer_key_id,
        blinded_message: bytes(p.authorization.blindedMessage),
        pending_state: { expected_revision: "0", object },
      });
      p.revision++;
      await pendingSave(p);
    }
    const issued = await signed(
      `/api/member/reviews/${p.reviewId}/issuances`,
      "issue",
      p.issuancePayload,
    );
    const token = await C.finalizeAuthorization({
      descriptor,
      preparedMessage: bytes(p.authorization.preparedMessage),
      inverse: bytes(p.authorization.inverse),
      blindSignature: bytes(issued.blind_signature),
    });
    const encrypted = {
      enc: bytes(p.encrypted.enc),
      ciphertext: bytes(p.encrypted.ciphertext),
    };
    p.submission = toWire({
      review_id: p.reviewId,
      issuer_key_id: descriptor.issuer_key_id,
      prepared_message: token.preparedMessage,
      signature: token.signature,
      enc: encrypted.enc,
      ciphertext: encrypted.ciphertext,
    });
    p.revision++;
    await pendingSave(p);
  }
  return p;
}
async function checkedReceipt(p, receipt) {
  const descriptorBytes = bytes(p.descriptor),
    descriptor = await C.verifyDescriptor({
      descriptorBytes,
      signature: bytes(p.descriptorSignature),
      expectedReviewId: bytes(p.reviewId),
    });
  if (
    !p.submission ||
    p.submission.review_id !== p.reviewId ||
    p.submission.issuer_key_id !== descriptor.issuer_key_id ||
    p.submission.enc !== p.encrypted.enc ||
    p.submission.ciphertext !== p.encrypted.ciphertext
  )
    throw new APIError(
      "INVALID_RECEIPT",
      "The receipt does not match the pending response.",
    );
  receipt = await verifyEnvelopeReceipt(
    { descriptorBytes, descriptor },
    p.submission,
    receipt,
  );
  p.receipt = receipt;
  p.revision++;
  await pendingSave(p);
  return { status: "accepted", receipt };
}
async function verifyEnvelopeReceipt(p, envelope, receipt) {
  const deploymentId = bytes(p.descriptor.deployment_id),
    reviewId = bytes(p.descriptor.review_id),
    issuerKeyId = bytes(p.descriptor.issuer_key_id);
  const descriptorHash = await C.hashBytes(p.descriptorBytes);
  const responseHash = await C.responseHash({
    deploymentId,
    reviewId,
    descriptorHash,
    issuerKeyId,
    enc: bytes(envelope.enc),
    ciphertext: bytes(envelope.ciphertext),
  });
  return C.verifyReceipt({
    receipt,
    trust: C.getReceiptTrust(),
    expectedDeploymentId: deploymentId,
    expectedReviewId: reviewId,
    expectedDescriptorHash: descriptorHash,
    expectedIssuerKeyId: issuerKeyId,
    expectedResponseHash: responseHash,
  });
}
export async function submitResponse({ pendingId }) {
  let p = await local(pendingId);
  if (!p)
    throw new APIError(
      "PENDING_NOT_FOUND",
      "Sign in on the original browser to restore this pending response.",
    );
  if (p.receipt) return checkedReceipt(p, p.receipt);
  try {
    p = await finishPending(p);
    return await checkedReceipt(
      p,
      await request("/api/anon/submissions", {
        method: "POST",
        body: p.submission,
        anonymous: true,
      }),
    );
  } catch (e) {
    if (e.code === "NETWORK_ERROR") return { status: "pending", pendingId };
    throw e;
  }
}
export async function lookupReceipt({ pendingId }) {
  const p = await local(pendingId);
  if (!p?.submission) return { status: "pending", pendingId };
  if (p.receipt) return checkedReceipt(p, p.receipt);
  try {
    return await checkedReceipt(
      p,
      await request("/api/anon/receipts/lookup", {
        method: "POST",
        anonymous: true,
        body: {
          review_id: p.reviewId,
          issuer_key_id: p.submission.issuer_key_id,
          serial: p.authorization.serial,
        },
      }),
    );
  } catch (e) {
    if (["NOT_FOUND", "not_found", "NETWORK_ERROR"].includes(e.code))
      return { status: "pending", pendingId };
    throw e;
  }
}
export async function listResponses({ reviewId, after }) {
  active();
  const p = await publicDescriptor(reviewId),
    keys = await reviewKeys(reviewId),
    privateKey = keys.privateKey;
  const content = await C.openDescriptorContent({
    descriptor: p.descriptor,
    contentKey: keys.contentKey,
  });
  const result = await request(
      `/api/member/reviews/${reviewId}/submissions${after ? "?after=" + encodeURIComponent(after) : ""}`,
    ),
    items = [];
  for (const item of result.items) {
    let acceptedAt = null;
    try {
      const receipt = await verifyEnvelopeReceipt(p, item, item.receipt);
      if (item.id !== receipt.receipt_id)
        throw new Error("Receipt identifier mismatch");
      acceptedAt = receipt.accepted_at;
      const decoded = await C.decryptResponse({
        ...p,
        recipientPrivateKey: privateKey,
        enc: bytes(item.enc),
        ciphertext: bytes(item.ciphertext),
      });
      const answerMap = decoded.answers;
      items.push({
        id: item.id,
        acceptedAt,
        status: "valid",
        answers: Object.entries(answerMap).map(([questionId, value]) => {
          const q = content.questions.find((q) => q.id === questionId),
            label = (v) => q?.choices.find((c) => c.id === v)?.label || v;
          return {
            questionId,
            value: Array.isArray(value) ? value.map(label) : label(value),
          };
        }),
      });
    } catch {
      items.push({
        id: item.id,
        acceptedAt,
        status: "invalid",
        error: "RESPONSE_UNREADABLE",
        answers: [],
      });
    }
  }
  return { items, next: result.next ?? null };
}
export async function exportResponses({ reviewId, format }) {
  if (!["json", "csv"].includes(format))
    throw new APIError("INVALID_FORMAT", "Choose JSON or CSV.");
  const result = { items: [] };
  let after;
  const seen = new Set();
  do {
    const page = await listResponses({ reviewId, after });
    result.items.push(...page.items);
    after = page.next;
    if (after && seen.has(after))
      throw new APIError(
        "INVALID_RESPONSE",
        "The response pagination could not be completed.",
      );
    if (after) seen.add(after);
  } while (after);
  const csvCell = (x) =>
    '"' +
    String(x ?? "")
      .replace(/^[=+@\-\t\r]/, "'$&")
      .replaceAll('"', '""') +
    '"';
  const content =
    format === "json"
      ? JSON.stringify(result.items, null, 2)
      : [
          "response_id,accepted_at,status,error,question_id,value",
          ...result.items.flatMap((r) =>
            (r.answers.length ? r.answers : [{}]).map((a) =>
              [
                r.id,
                r.acceptedAt,
                r.status,
                r.error,
                a.questionId,
                Array.isArray(a.value) ? a.value.join("; ") : a.value,
              ]
                .map(csvCell)
                .join(","),
            ),
          ),
        ].join("\r\n");
  const mimeType =
    format === "json" ? "application/json" : "text/csv;charset=utf-8";
  return {
    filename: `review-${reviewId}.${format}`,
    mimeType,
    blob: new Blob([content], { type: mimeType }),
  };
}
