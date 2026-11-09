// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import * as app from "./app.js";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

// Run the service with inert providers, without loading cryptographic dependencies.
async function service(overrides = {}) {
  const source = (await readFile(new URL("./app.js", import.meta.url), "utf8"))
    .replace(/^import[ \t]+(?![.(])[^;]*;[ \t]*$/gm, "")
    .replace(/\bexport /g, "");
  const wire = (value) =>
    JSON.parse(
      JSON.stringify(value, (_, v) =>
        v instanceof Uint8Array ? Buffer.from(v).toString("base64url") : v,
      ),
    );
  class MockAPIError extends Error {
    constructor(code, message) {
      super(message);
      this.code = code;
    }
  }
  let randomCounter = 0;
  const context = vm.createContext({
    Uint8Array,
    TextDecoder,
    TextEncoder,
    Blob,
    URL,
    URLSearchParams,
    crypto: { getRandomValues: (value) => value.fill(++randomCounter) },
    APIError: MockAPIError,
    jsonBytes: (value) => new TextEncoder().encode(JSON.stringify(value)),
    toWire: wire,
    C: {
      fromBase64url: (value) => new Uint8Array(Buffer.from(value, "base64url")),
      toBase64url: (value) => Buffer.from(value).toString("base64url"),
      ...overrides.C,
    },
    request:
      overrides.request ||
      (() => {
        throw Error("Unexpected request");
      }),
    allEncrypted: overrides.allEncrypted || (async () => []),
    loadSealed: overrides.loadSealed,
    saveSealed: overrides.saveSealed || (async () => {}),
    setCSRF: overrides.setCSRF || (() => {}),
    deleteDeviceRecord: overrides.deleteDeviceRecord || (async () => {}),
  });
  vm.runInContext(
    source +
      `;state={accountId:'YQ',masterKey:new Uint8Array(32)};
    globalThis.service={sealIssuancePending,finishPending,local,listResponses,exportResponses,submitResponse,lookupReceipt,verifySavedReceipt,getReceiptTrust,loadReceiptTrust,reviewKeys,listReviews,contentRecipients,memberContentKey,completedHere,validateMemberKeys,register,sendPublication};
    globalThis.setState=value=>{state=value;};
    globalThis.setLogin=value=>{login=value;};
    globalThis.setCredentials=value=>{credentials=value;};
    globalThis.setPublishBuilder=value=>{publishWithRosterRetry=value;};
    globalThis.setReviewKeys=value=>{reviewKeys=value;};
    globalThis.lifecycle={createReview,updateReview,publishReview,deleteReview};
    globalThis.configureLifecycle=()=>{config={deployment_id:'YQ'};cacheState=async()=>{};ensureCertificate=async()=>({membership_id:'member',certificate:'certificate'});};
    globalThis.setSigned=value=>{signed=value;};`,
    context,
  );
  return context;
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

async function authService(overrides = {}) {
  const context = await service(overrides);
  vm.runInContext(
    `initialize=async()=>({});
    cacheState=async()=>{};
    globalThis.auth={getSession,getSessionStatus,login,recover,logout,sessionStart,loginAfterCredentialChange};
    globalThis.inspect=()=>({state,generation});`,
    context,
  );
  return context;
}

test("stale session lookup cannot restore CSRF after logout", async () => {
  const lookup = deferred(),
    entered = deferred();
  let csrf;
  const context = await authService({
    setCSRF: (value) => {
      csrf = value;
    },
    request: (path) => {
      if (path === "/api/member/me") {
        entered.resolve();
        return lookup.promise;
      }
      return Promise.resolve();
    },
  });
  context.setState(undefined);
  const pending = context.auth.getSession();
  await entered.promise;
  await context.auth.logout();
  lookup.resolve({ account_id: "YQ", csrf_token: "stale" });
  assert.equal(await pending, null);
  assert.equal(context.inspect().state, undefined);
  assert.equal(csrf, undefined);
});

test("session status checks identity without initializing vault state", async () => {
  const paths = [];
  const context = await authService({
    request: async (path) => {
      paths.push(path);
      return {
        account_id: "YQ",
        scope: "full",
        email: "member@example.net",
        csrf_token: "never returned to UI",
        memberships: [{ id: "org" }],
      };
    },
  });
  assert.deepEqual(
    JSON.parse(JSON.stringify(await context.auth.getSessionStatus())),
    {
      account_id: "YQ",
      scope: "full",
      email: "member@example.net",
    },
  );
  assert.deepEqual(paths, ["/api/member/me"]);
});

test("session status maps unauthenticated responses to signed out", async () => {
  const paths = [];
  const context = await authService({
    request: async (path) => {
      paths.push(path);
      throw Object.assign(new Error("signed out"), {
        code: "UNAUTHENTICATED",
      });
    },
  });
  assert.equal(await context.auth.getSessionStatus(), null);
  assert.deepEqual(paths, ["/api/member/me"]);
});

test("session status propagates non-authentication failures", async () => {
  const failure = Object.assign(new Error("network unavailable"), {
    code: "NETWORK_ERROR",
  });
  const context = await authService({
    request: async () => {
      throw failure;
    },
  });
  await assert.rejects(
    context.auth.getSessionStatus(),
    (error) => error === failure,
  );
});

test("delayed logout keeps newer login state and CSRF", async () => {
  const revocation = deferred(),
    entered = deferred();
  const deleted = [];
  let csrf = "old",
    revocationCSRF;
  const context = await authService({
    setCSRF: (value) => {
      csrf = value;
    },
    deleteDeviceRecord: async (key) => {
      deleted.push(key);
    },
    request: () => {
      revocationCSRF = csrf;
      entered.resolve();
      return revocation.promise;
    },
  });
  vm.runInContext(`cookieCSRF='old';setSessionCSRF('old');`, context);
  const old = context.inspect().state;
  const pending = context.auth.logout();
  assert.equal(context.inspect().state, undefined);
  assert.equal(csrf, undefined);
  await entered.promise;
  assert.equal(revocationCSRF, "old");
  assert.ok(old.masterKey.every((value) => value === 0));
  vm.runInContext(
    `generation++;state={accountId:'Yg'};setSessionCSRF('new');`,
    context,
  );
  revocation.resolve();
  await pending;
  assert.equal(context.inspect().state.accountId, "Yg");
  assert.equal(csrf, "new");
  assert.deepEqual(deleted.sort(), ["cache:YQ", "key:YQ"]);
});

test("session POST waits for logout response and same-account cache cleanup", async () => {
  const response = deferred(),
    cleanup = deferred(),
    deleting = deferred(),
    post = deferred();
  const events = [];
  let cookie = "old",
    csrf;
  const context = await authService({
    setCSRF: (value) => {
      csrf = value;
    },
    request: async () => {
      events.push(["DELETE", cookie, csrf]);
      await response.promise;
      cookie = undefined;
      events.push(["expired"]);
    },
    deleteDeviceRecord: async () => {
      deleting.resolve();
      await cleanup.promise;
      events.push(["cleanup"]);
    },
  });
  vm.runInContext(`cookieCSRF='old';setSessionCSRF('old');`, context);
  context.setSigned(async () => {
    events.push(["POST"]);
    cookie = "new";
    post.resolve();
    return { account_id: "YQ", csrf_token: "new" };
  });
  const logout = context.auth.logout();
  await deleting.promise;
  const login = context.auth.sessionStart(
    "YQ",
    new Uint8Array(32),
    "login-password",
    1,
  );
  response.resolve();
  await response.promise;
  assert.equal(
    events.some(([event]) => event === "POST"),
    false,
  );
  cleanup.resolve();
  await logout;
  await post.promise;
  await login;
  assert.equal(cookie, "new");
  assert.equal(csrf, "new");
  assert.deepEqual(events[0], ["DELETE", "old", "old"]);
  assert.deepEqual(events.at(-1), ["POST"]);
  assert.equal(events.filter(([event]) => event === "cleanup").length, 2);
});

test("logout waits for in-flight POST and revokes its cookie with response CSRF", async () => {
  const response = deferred(),
    dispatched = deferred();
  let cookie, csrf, revoked;
  const context = await authService({
    setCSRF: (value) => {
      csrf = value;
    },
    request: async () => {
      revoked = { cookie, csrf };
      cookie = undefined;
    },
  });
  context.setSigned(async () => {
    dispatched.resolve();
    await response.promise;
    cookie = "stale-login";
    return { csrf_token: "stale-login-csrf" };
  });
  const login = context.auth.sessionStart(
    "YQ",
    new Uint8Array(32),
    "login-password",
    0,
  );
  const rejected = assert.rejects(login, { code: "SESSION_CHANGED" });
  await dispatched.promise;
  const logout = context.auth.logout();
  assert.equal(revoked, undefined);
  response.resolve();
  await Promise.all([rejected, logout]);
  assert.deepEqual(revoked, {
    cookie: "stale-login",
    csrf: "stale-login-csrf",
  });
  assert.equal(cookie, undefined);
  assert.equal(csrf, undefined);
  assert.equal(context.inspect().state, undefined);
});

test("rejected logout drains only after cleanup and permits later session POST", async () => {
  const cleanup = deferred(),
    deleting = deferred();
  const context = await authService({
    request: async () => {
      throw Error("revocation failed");
    },
    deleteDeviceRecord: async () => {
      deleting.resolve();
      await cleanup.promise;
    },
  });
  let posts = 0;
  context.setSigned(async () => {
    posts++;
    return { csrf_token: "new" };
  });
  const logout = context.auth.logout();
  const rejected = assert.rejects(logout, /revocation failed/);
  await deleting.promise;
  const login = context.auth.sessionStart(
    "YQ",
    new Uint8Array(32),
    "login-password",
    1,
  );
  assert.equal(posts, 0);
  cleanup.resolve();
  await rejected;
  await login;
  assert.equal(posts, 1);
});

test("queued canceled session POST never dispatches", async () => {
  const response = deferred(),
    entered = deferred();
  const context = await authService({
    request: () => {
      entered.resolve();
      return response.promise;
    },
  });
  let posts = 0;
  context.setSigned(async () => {
    posts++;
    return {};
  });
  const firstLogout = context.auth.logout();
  await entered.promise;
  const login = context.auth.sessionStart(
    "YQ",
    new Uint8Array(32),
    "login-password",
    1,
  );
  const rejected = assert.rejects(login, { code: "SESSION_CHANGED" });
  const secondLogout = context.auth.logout();
  response.resolve();
  await Promise.all([firstLogout, rejected, secondLogout]);
  assert.equal(posts, 0);
});

for (const operation of ["login", "recover"]) {
  test(`${operation} cannot install stale keys after logout`, async () => {
    const opened = deferred(),
      entered = deferred();
    const context = await authService({
      C: {
        derivePassword: async () => ({ authSeed: new Uint8Array(32) }),
        deriveRecovery: async () => ({ authSeed: new Uint8Array(32) }),
      },
      request: async () => ({ account_id: "YQ", recovery_salt: "YQ" }),
    });
    context.opened = opened.promise;
    context.entered = entered.resolve;
    vm.runInContext(
      `sessionStart=async()=>({account_id:'YQ'});
      vaultOpen=()=>{entered();return opened;};`,
      context,
    );
    const pending = context.auth[operation]({ email: "member@example.test" });
    await entered.promise;
    await context.auth.logout();
    const masterKey = new Uint8Array(32).fill(7);
    opened.resolve({ masterKey });
    await assert.rejects(pending, { code: "SESSION_CHANGED" });
    assert.equal(context.inspect().state, undefined);
    assert.ok(masterKey.every((value) => value === 0));
  });
}

test("stale session start cannot replace newer CSRF", async () => {
  const result = deferred(),
    entered = deferred();
  let csrf;
  const context = await authService({
    setCSRF: (value) => {
      csrf = value;
    },
  });
  context.setSigned(() => {
    entered.resolve();
    return result.promise;
  });
  const pending = context.auth.sessionStart(
    "YQ",
    new Uint8Array(32),
    "login-password",
    0,
  );
  await entered.promise;
  vm.runInContext(`generation++;setCSRF('new');`, context);
  result.resolve({ csrf_token: "stale" });
  await assert.rejects(pending, { code: "SESSION_CHANGED" });
  assert.equal(csrf, "new");
});

test("credential reauthentication failure cannot clear newer state", async () => {
  const result = deferred();
  const context = await authService();
  context.result = result.promise;
  vm.runInContext(`login=()=>{generation++;return result;};`, context);
  const pending = context.auth.loginAfterCredentialChange({}, 0);
  vm.runInContext(`generation++;state={accountId:'new'};`, context);
  result.reject(Error("old login failed"));
  assert.equal(await pending, null);
  assert.equal(context.inspect().state.accountId, "new");
});

test("session restoration completing validation after logout stays detached", async () => {
  const validation = deferred(),
    entered = deferred();
  let csrf;
  const context = await authService({
    setCSRF: (value) => {
      csrf = value;
    },
    request: async () => ({
      account_id: "YQ",
      credential_epoch: "1",
      csrf_token: "old",
    }),
    C: {
      openDeviceCache: async () =>
        new TextEncoder().encode(
          JSON.stringify({
            session: { credential_epoch: "1" },
            masterKey: "YQ",
            authSeed: "YQ",
            membershipSeed: "YQ",
            encryptionPrivateKey: "YQ",
          }),
        ),
    },
  });
  context.validation = validation.promise;
  context.entered = entered.resolve;
  vm.runInContext(
    `state=undefined;deviceKey=async()=>new Uint8Array(32);
    globalThis.getDeviceRecord=async()=>({});
    validateMemberKeys=()=>{entered();return validation;};`,
    context,
  );
  const pending = context.auth.getSession();
  await entered.promise;
  await context.auth.logout();
  validation.resolve();
  assert.equal(await pending, null);
  assert.equal(context.inspect().state, undefined);
  assert.equal(csrf, undefined);
});

test("logout during recovery credential derivation prevents reset and auto-login", async () => {
  const derived = deferred(),
    entered = deferred();
  const { context, mutations } = await credentialService();
  context.derived = derived.promise;
  context.entered = entered.resolve;
  vm.runInContext(
    `credentials=()=>{entered();return derived;};
    globalThis.endSession=logout;
    request=async()=>({account_id:'YQ',recovery_salt:'YQ'});`,
    context,
  );
  const pending = context.credentialOperations.recover({
    email: "member@example.test",
  });
  await entered.promise;
  await context.endSession();
  derived.resolve({});
  await assert.rejects(pending, { code: "SESSION_CHANGED" });
  assert.deepEqual(mutations, []);
  assert.equal(context.hasActiveState(), false);
});

async function credentialService({ mutationFails = false, loginFailure } = {}) {
  const words = Array(12).fill("abandon");
  const session = { account_id: "YQ", credential_epoch: "2" };
  const mutations = [];
  const context = await service({
    C: {
      derivePassword: async () => ({ authSeed: new Uint8Array(32) }),
      deriveRecovery: async () => ({ authSeed: new Uint8Array(32) }),
      generateRecovery: async () => ({ words: words.join(" ") }),
      authenticationPublicKey: async () => new Uint8Array(32),
      passwordMetadataHash: async () => new Uint8Array(32),
      recoveryMetadataHash: async () => new Uint8Array(32),
      wrapVaultMaster: async () => ({ ciphertext: "wrapped" }),
    },
    request: async (path) => {
      if (path === "/api/member/auth/params") {
        if (loginFailure === "request" && mutations.length)
          throw Error("private login failure");
        return { account_id: "YQ", password_kdf: {}, recovery_salt: "YQ" };
      }
      if (path === "/api/member/me") return session;
      throw Error("Unexpected request: " + path);
    },
  });
  context.setSigned(async (path) => {
    mutations.push(path);
    if (mutationFails) throw Error("mutation rejected");
    return {};
  });
  context.credentialSession = session;
  context.failCache = loginFailure === "cache";
  vm.runInContext(
    `initialize=async()=>({});
    sessionStart=async()=>credentialSession;
    vaultOpen=async()=>({masterKey:new Uint8Array(32)});
    cacheState=async()=>{if(failCache)throw Error('private cache failure');};
    state={accountId:'YQ',email:'member@example.test',masterKey:new Uint8Array(32),params:{password_kdf:{}},session:credentialSession};
    globalThis.credentialOperations={changePassword,rotateRecovery,recover};
    globalThis.hasActiveState=()=>Boolean(state);`,
    context,
  );
  return { context, mutations, words, session };
}

for (const operation of ["changePassword", "rotateRecovery", "recover"]) {
  const options = {
    email: "member@example.test",
    currentPassword: "old password",
    newPassword: "new password",
    words: Array(12).fill("old").join(" "),
  };
  for (const loginFailure of ["request", "cache"]) {
    test(`${operation} preserves committed result after ${loginFailure} login failure`, async () => {
      const { context, mutations, words } = await credentialService({
        loginFailure,
      });
      const result = await context.credentialOperations[operation](options);
      assert.deepEqual(JSON.parse(JSON.stringify(result)), {
        ...(operation === "changePassword"
          ? {}
          : { session: null, recoveryWords: words }),
        reauthenticationRequired: true,
      });
      assert.equal(mutations.length, 1);
      assert.equal(context.hasActiveState(), false);
    });
  }
  test(`${operation} rejects uncommitted mutation without returning recovery words`, async () => {
    const { context, mutations } = await credentialService({
      mutationFails: true,
    });
    await assert.rejects(
      context.credentialOperations[operation](options),
      /mutation rejected/,
    );
    assert.equal(mutations.length, 1);
  });
  test(`${operation} keeps successful return shape`, async () => {
    const { context, session, words } = await credentialService();
    const result = await context.credentialOperations[operation](options);
    const expectedSession = {
      ...session,
      accountId: "YQ",
      email: options.email,
    };
    assert.deepEqual(
      JSON.parse(JSON.stringify(result)),
      operation === "changePassword"
        ? expectedSession
        : { session: expectedSession, recoveryWords: words },
    );
    assert.equal(context.hasActiveState(), true);
  });
}

test("standalone receipt trust loads only public config anonymously without crypto init", async () => {
  let requestArgs;
  const config = {
    v: 99,
    deployment_id: "deployment",
    receipt_key_id: "current",
    receipt_keys: [{ receipt_key_id: "current", receipt_public_key: "public" }],
    ca_certificate: "unused",
  };
  const context = await service({
    request: async (...args) => {
      requestArgs = args;
      return config;
    },
  });
  assert.deepEqual(
    JSON.parse(JSON.stringify(await context.service.loadReceiptTrust())),
    {
      v: 1,
      deployment_id: "deployment",
      receipt_key_id: "current",
      receipt_keys: config.receipt_keys,
    },
  );
  assert.deepEqual(JSON.parse(JSON.stringify(requestArgs)), [
    "/api/public/config",
    { anonymous: true },
  ]);
});

test("issuance padding has fixed byte length, whitespace roundtrip, and fits request limits", async () => {
  const sealed = [];
  const context = await service({
    C: {
      sealVaultObject: async (options) => {
        sealed.push(options);
        return {
          ciphertext: Buffer.alloc(options.plaintext.length + 16).toString(
            "base64url",
          ),
        };
      },
    },
  });
  for (const length of [0, 1, 1024, 262144]) {
    const pending = {
      pendingId: "Yg",
      descriptor: Buffer.alloc(65536).toString("base64url"),
      encrypted: { ciphertext: Buffer.alloc(length).toString("base64url") },
      answer: "日本語",
    };
    const object = await context.service.sealIssuancePending(pending);
    const options = sealed.at(-1);
    assert.equal(options.plaintext.length, 524288);
    assert.equal(options.revision, "1");
    assert.deepEqual(
      JSON.parse(new TextDecoder().decode(options.plaintext)),
      pending,
    );
    assert.equal(options.plaintext.at(-1), 32);
    assert.ok(Buffer.byteLength(object.ciphertext) < 1048576);
    const payload = JSON.stringify({
      pending_state: { expected_revision: "0", object },
    });
    assert.ok(Buffer.byteLength(payload) <= 1536 * 1024);
    assert.ok(
      Buffer.byteLength(
        JSON.stringify({
          payload: Buffer.from(payload).toString("base64url"),
          proof: {},
        }),
      ) <=
        2304 * 1024,
    );
  }
  await assert.rejects(
    context.service.sealIssuancePending({
      pendingId: "Yg",
      value: "x".repeat(524288),
    }),
    (e) => e.code === "INVALID_RESPONSE" && !e.message.includes("xxxxx"),
  );
  assert.equal(sealed.length, 4);
});

test("issuance retries and reload preserve the exact sealed payload", async () => {
  let seals = 0,
    saved;
  const payloads = [];
  const context = await service({
    C: {
      verifyDescriptor: async () => ({
        org_id: "org",
        issuer_key_id: "issuer",
      }),
      sealVaultObject: async () => ({
        id: "Yg",
        ciphertext: "sealed-" + ++seals,
      }),
    },
    request: async () => ({}),
    saveSealed: async ({ value }) => {
      saved = JSON.parse(JSON.stringify(value));
    },
  });
  context.setSigned(async (_path, _action, payload) => {
    payloads.push(JSON.stringify(payload));
    throw Error("retry");
  });
  const pending = {
    pendingId: "Yg",
    reviewId: "Yw",
    requestId: "request",
    descriptor: "e30",
    descriptorSignature: "",
    authorization: { blindedMessage: "YQ" },
    encrypted: { ciphertext: "YQ" },
    revision: 1,
  };
  await assert.rejects(context.service.finishPending(pending), /retry/);
  await assert.rejects(context.service.finishPending(pending), /retry/);
  await assert.rejects(context.service.finishPending(saved), /retry/);
  assert.equal(seals, 1);
  assert.equal(new Set(payloads).size, 1);
});

test("remote recovery restores exact issuance bytes after JSONB key reordering", async () => {
  const descriptor = { org_id: "org", issuer_key_id: "issuer" };
  const pending = {
    pendingId: "Yg",
    reviewId: "Yw",
    requestId: "request",
    descriptor: Buffer.from(JSON.stringify(descriptor)).toString("base64url"),
    descriptorSignature: "",
    authorization: { blindedMessage: "YQ" },
    encrypted: { ciphertext: "YQ" },
    revision: 1,
  };
  const object = {
    v: 1,
    id: "Yg",
    revision: "1",
    nonce: "bm9uY2U",
    ciphertext: "Y2lwaGVydGV4dA",
  };
  // PostgreSQL JSONB may return a different key order from the sealing provider.
  const remoteObject = {
    id: object.id,
    v: object.v,
    nonce: object.nonce,
    ciphertext: object.ciphertext,
    revision: object.revision,
  };
  const payloads = [];
  let seals = 0;
  const context = await service({
    C: {
      verifyDescriptor: async () => descriptor,
      sealVaultObject: async () => {
        seals++;
        return object;
      },
      openVaultObject: async ({ object: received }) => {
        assert.equal(received, remoteObject);
        return new TextEncoder().encode(JSON.stringify(pending));
      },
    },
    loadSealed: async () => undefined,
    request: async (path) =>
      path === "/api/member/vault" ? { objects: [remoteObject] } : {},
  });
  context.setSigned(async (_path, _action, payload) => {
    payloads.push(JSON.stringify(payload));
    throw Error("retry");
  });
  // The remote object contains the issuance-time pending plaintext, before issuancePayload exists.
  const original = JSON.parse(JSON.stringify(pending));
  await assert.rejects(context.service.finishPending(original), /retry/);
  const recovered = await context.service.local(pending.pendingId);
  await assert.rejects(context.service.finishPending(recovered), /retry/);
  assert.equal(seals, 1, "remote recovery must not re-encrypt");
  assert.equal(payloads.length, 2);
  assert.equal(payloads[1], payloads[0]);
  assert.deepEqual(
    JSON.parse(JSON.stringify(recovered.issuancePayload.pending_state.object)),
    object,
  );
});

async function responseService({
  networkFailure = false,
  keyFailure = false,
  descriptorFailure = false,
} = {}) {
  const context = await service({
    C: {
      verifyDescriptor: async () => {
        if (descriptorFailure) throw Error("descriptor");
        return { deployment_id: "YQ", review_id: "Yw", issuer_key_id: "Yg" };
      },
      openDescriptorContent: async ({ descriptor, contentKey }) => {
        assert.equal(descriptor.questions, undefined);
        assert.equal(contentKey.length, 32);
        return { questions: [{ id: "q", type: "text", choices: [] }] };
      },
      hashBytes: async () => new Uint8Array(32),
      responseHash: async () => new Uint8Array(32),
      getReceiptTrust: () => ({}),
      verifyReceipt: async ({ receipt }) => receipt,
      openVaultObject: async () => {
        if (keyFailure) throw Error("key");
        return new TextEncoder().encode(
          JSON.stringify({
            kind: "recipient",
            reviewId: "Yw",
            privateKey: "YQ",
          }),
        );
      },
      decryptResponse: async ({
        ciphertext,
        recipientPrivateKey,
        descriptor,
      }) => {
        assert.equal(recipientPrivateKey.length, 32);
        assert.equal(descriptor.questions, undefined);
        if (ciphertext[0] === 2) throw Error("raw secret provider error");
        if (ciphertext[0] === 3) return { answers: null };
        return { answers: { q: "good answer" } };
      },
    },
    request: async (path) => {
      if (path.startsWith("/api/public/"))
        return { descriptor: "e30", descriptor_signature: "" };
      if (path === "/api/member/vault") return { objects: [{}] };
      if (networkFailure) throw Error("network");
      return {
        items: [1, 2, 3].map((n) => ({
          id: String(n),
          accepted_at: "untrusted",
          receipt: { receipt_id: String(n), accepted_at: "today" },
          enc: "YQ",
          ciphertext: Buffer.from([n]).toString("base64url"),
        })),
        next: null,
      };
    },
  });
  context.setReviewKeys(async () => {
    if (keyFailure) throw Error("key");
    return { privateKey: new Uint8Array(32), contentKey: new Uint8Array(32) };
  });
  return context;
}

test("mixed responses retain readable answers and report unreadable records in JSON and CSV", async () => {
  const context = await responseService();
  const result = JSON.parse(
    JSON.stringify(await context.service.listResponses({ reviewId: "Yw" })),
  );
  assert.equal(result.items[0].status, "valid");
  assert.equal(result.items[0].answers[0].value, "good answer");
  for (const item of result.items.slice(1))
    assert.deepEqual(item, {
      id: item.id,
      acceptedAt: "today",
      status: "invalid",
      error: "RESPONSE_UNREADABLE",
      answers: [],
    });
  for (const format of ["json", "csv"]) {
    const exported = await context.service.exportResponses({
      reviewId: "Yw",
      format,
    });
    const content = await exported.blob.text();
    assert.ok(content.includes("good answer"));
    assert.equal((content.match(/RESPONSE_UNREADABLE/g) || []).length, 2);
    assert.ok(!content.includes("raw secret"));
    if (format === "json") assert.equal(JSON.parse(content).length, 3);
    else {
      assert.ok(
        content.startsWith(
          "response_id,accepted_at,status,error,question_id,value",
        ),
      );
      assert.equal(content.split("\r\n").length, 4);
    }
  }
});

test("response listing does not hide network, key, or descriptor failures", async () => {
  for (const [option, message] of [
    ["networkFailure", "network"],
    ["keyFailure", "key"],
    ["descriptorFailure", "descriptor"],
  ]) {
    const context = await responseService({ [option]: true });
    await assert.rejects(
      context.service.listResponses({ reviewId: "Yw" }),
      new RegExp(message),
    );
  }
});
test("required service entry points are exported", () => {
  for (const name of [
    "register",
    "login",
    "recover",
    "getSession",
    "logout",
    "changePassword",
    "rotateRecovery",
    "publishReview",
    "prepareResponse",
    "submitResponse",
    "lookupReceipt",
    "listResponses",
    "exportResponses",
  ])
    assert.equal(typeof app[name], "function", name);
});
test("source link has a safe HTTPS fallback before initialization", () => {
  assert.equal(
    app.getSourceURL(),
    "https://github.com/mandipnotroot/anonce-platform",
  );
  assert.equal(new URL(app.getSourceURL()).protocol, "https:");
});
test("invalid export format fails before accessing secrets", async () => {
  await assert.rejects(
    app.exportResponses({ reviewId: "x", format: "html" }),
    (e) => e.code === "INVALID_FORMAT",
  );
});
test("review pagination transmits an encoded cursor", async () => {
  let requested;
  globalThis.fetch = async (path) => {
    requested = path;
    return {
      ok: true,
      status: 200,
      json: async () => ({ items: [], next: null }),
    };
  };
  assert.deepEqual(
    await app.listReviews({ orgId: "organization", after: "cursor/+?" }),
    { items: [], next: null },
  );
  assert.equal(
    requested,
    "/api/member/orgs/organization/reviews?after=cursor%2F%2B%3F",
  );
});

const portableReceipt = {
  v: 2,
  deployment_id: "YQ",
  receipt_id: "Yg",
  review_id: "Yw",
  descriptor_hash: "ZA",
  issuer_key_id: "ZQ",
  response_hash: "Zg",
  accepted_at: "123",
  receipt_key_id: "Zw",
  signature: "aA",
};
const portableTrust = {
  v: 1,
  deployment_id: "YQ",
  receipt_key_id: "Zw",
  receipt_keys: [{ receipt_key_id: "Zw", receipt_public_key: "aQ" }],
};
test("standalone verification uses explicit trust without initialization or requests", async () => {
  let calls = 0;
  const context = await service({
    C: {
      verifyReceiptSignature: async ({ receipt, trust }) => {
        calls++;
        assert.deepEqual(JSON.parse(JSON.stringify(trust)), portableTrust);
        return receipt;
      },
    },
  });
  const result = await context.service.verifySavedReceipt({
    receiptText: JSON.stringify(portableReceipt),
    trustText: JSON.stringify(portableTrust),
  });
  assert.equal(result.receipt.receipt_id, "Yg");
  assert.equal(calls, 1);
});
test("standalone verification rejects duplicate, unknown, malformed, trailing and oversized JSON", async () => {
  const context = await service();
  for (const receiptText of [
    "{",
    "null",
    "[]",
    JSON.stringify({ ...portableReceipt, token: "secret" }),
    JSON.stringify(portableReceipt) + " false",
    JSON.stringify(portableReceipt).replace('"v":2', '"v":2,"\\u0076":2'),
    " ".repeat(65537),
    '"' + "日".repeat(22000) + '"',
  ]) {
    await assert.rejects(
      context.service.verifySavedReceipt({
        receiptText,
        trustText: JSON.stringify(portableTrust),
      }),
    );
  }
  await assert.rejects(
    context.service.verifySavedReceipt({
      receiptText: JSON.stringify(portableReceipt),
      trustText: JSON.stringify({
        ...portableTrust,
        url: "https://evil.invalid",
      }),
    }),
  );
});
test("cached and lookup receipts reverify descriptor, envelope and every expected context", async () => {
  for (const method of ["submitResponse", "lookupReceipt"])
    for (const cached of [false, true]) {
      let checks = 0,
        descriptors = 0;
      const pending = {
        pendingId: "Yg",
        reviewId: "Yw",
        descriptor: "e30",
        descriptorSignature: "YQ",
        revision: 1,
        encrypted: { enc: "YQ", ciphertext: "Yg" },
        submission: {
          review_id: "Yw",
          issuer_key_id: "ZQ",
          enc: "YQ",
          ciphertext: "Yg",
        },
        authorization: { serial: "secret" },
        ...(cached ? { receipt: portableReceipt } : {}),
      };
      const context = await service({
        loadSealed: async () => pending,
        request: async () => portableReceipt,
        C: {
          verifyDescriptor: async ({ expectedReviewId }) => {
            descriptors++;
            assert.equal(
              Buffer.from(expectedReviewId).toString("base64url"),
              "Yw",
            );
            return {
              deployment_id: "YQ",
              review_id: "Yw",
              issuer_key_id: "ZQ",
            };
          },
          hashBytes: async (value) => {
            assert.equal(Buffer.from(value).toString(), "{}");
            return new Uint8Array(32).fill(1);
          },
          responseHash: async (options) => {
            assert.equal(
              Buffer.from(options.ciphertext).toString("base64url"),
              "Yg",
            );
            return new Uint8Array(32).fill(2);
          },
          getReceiptTrust: () => portableTrust,
          verifyReceipt: async (options) => {
            checks++;
            for (const field of [
              "expectedDeploymentId",
              "expectedReviewId",
              "expectedDescriptorHash",
              "expectedIssuerKeyId",
              "expectedResponseHash",
            ])
              assert.ok(options[field] instanceof Uint8Array);
            throw Error("receipt mismatch");
          },
        },
      });
      await assert.rejects(
        context.service[method]({ pendingId: "Yg" }),
        /receipt mismatch/,
      );
      assert.equal(checks, 1);
      assert.ok(descriptors >= 1);
      pending.submission.ciphertext = "tampered";
      await assert.rejects(
        context.service[method]({ pendingId: "Yg" }),
        (e) => e.code === "INVALID_RECEIPT",
      );
    }
});
test("reviewer rejects receipt and identifier mismatches before decrypting", async () => {
  for (const badSignature of [false, true]) {
    let decrypts = 0;
    const context = await service({
      C: {
        openDescriptorContent: async () => ({ questions: [] }),
        verifyDescriptor: async () => ({
          deployment_id: "YQ",
          review_id: "Yw",
          issuer_key_id: "ZQ",
        }),
        hashBytes: async () => new Uint8Array(32),
        responseHash: async () => new Uint8Array(32),
        getReceiptTrust: () => portableTrust,
        verifyReceipt: async () => {
          if (badSignature) throw Error("signature");
          return { ...portableReceipt, receipt_id: "different" };
        },
        openVaultObject: async () =>
          new TextEncoder().encode(
            JSON.stringify({
              kind: "recipient",
              reviewId: "Yw",
              privateKey: "YQ",
            }),
          ),
        decryptResponse: async () => {
          decrypts++;
        },
      },
      request: async (path) =>
        path.startsWith("/api/public/")
          ? { descriptor: "e30", descriptor_signature: "YQ" }
          : path === "/api/member/vault"
            ? { objects: [{}] }
            : {
                items: [
                  {
                    id: "Yg",
                    accepted_at: "forged",
                    enc: "YQ",
                    ciphertext: "Yg",
                    receipt: portableReceipt,
                  },
                ],
              },
    });
    context.setReviewKeys(async () => ({
      privateKey: new Uint8Array(32),
      contentKey: new Uint8Array(32),
    }));
    const result = await context.service.listResponses({ reviewId: "Yw" });
    assert.equal(decrypts, 0);
    assert.equal(result.items[0].acceptedAt, null);
    assert.equal(result.items[0].status, "invalid");
    assert.equal(result.items[0].answers.length, 0);
  }
});
test("secret-link service exports are removed", () => {
  assert.equal(app.parseResponseInvitation, undefined);
  assert.equal(app.getInvitationURL, undefined);
});

test("review keys require authoritative vault and exact review binding", async () => {
  const reviewId = Buffer.alloc(16, 1).toString("base64url"),
    key = Buffer.alloc(32, 2).toString("base64url");
  for (const change of [
    {},
    { review_id: Buffer.alloc(16, 3).toString("base64url") },
    { content_key: "YQ" },
    { extra: true },
  ]) {
    let localReads = 0;
    const context = await service({
      loadSealed: async () => {
        localReads++;
        throw Error("must not read local");
      },
      request: async () => ({ objects: [{ id: reviewId, revision: "1" }] }),
      C: {
        openVaultObject: async () =>
          new TextEncoder().encode(
            JSON.stringify({
              v: 1,
              kind: "review-keys",
              review_id: reviewId,
              content_key: key,
              recipient_private_key: key,
              ...change,
            }),
          ),
      },
    });
    if (Object.keys(change).length)
      await assert.rejects(
        context.service.reviewKeys(reviewId),
        (e) => e.code === "KEY_UNAVAILABLE",
      );
    else
      assert.equal(
        (await context.service.reviewKeys(reviewId)).contentKey.length,
        32,
      );
    assert.equal(localReads, 0);
  }
});
test("missing and unreadable authoritative review keys fail closed", async () => {
  const reviewId = Buffer.alloc(16, 1).toString("base64url");
  for (const objects of [
    [],
    [{ id: reviewId, revision: "2" }],
    [{ id: reviewId, revision: "1" }],
  ]) {
    const context = await service({
      request: async () => ({ objects }),
      C: {
        openVaultObject: async () => {
          throw Error("private provider detail");
        },
      },
    });
    await assert.rejects(
      context.service.reviewKeys(reviewId),
      (e) =>
        e.code === "KEY_UNAVAILABLE" &&
        !e.message.includes("private provider detail"),
    );
  }
});
test("creator lists share only one invocation-local authoritative vault read", async () => {
  for (const states of [
    ["draft", "draft"],
    ["published", "published"],
    ["draft", "published"],
  ]) {
    const items = states.map((state, i) => ({
      id: Buffer.alloc(16, i + 1).toString("base64url"),
      org_id: Buffer.alloc(16, 9).toString("base64url"),
      state,
      is_creator: true,
    }));
    let reads = 0;
    let mode = "valid";
    const pending = [];
    const context = await service({
      request: async (path) => {
        if (path === "/api/member/vault") {
          reads++;
          if (mode === "rejected") throw Error("vault unavailable");
          if (mode === "concurrent") {
            const wait = deferred();
            pending.push(wait);
            await wait.promise;
          }
          return {
            objects:
              mode === "missing"
                ? []
                : items.map(({ id }) => ({ id, revision: "1" })),
          };
        }
        if (path.startsWith("/api/public/"))
          return { descriptor: "e30", descriptor_signature: "YQ" };
        return { items, next: "next-page" };
      },
      C: {
        verifyDescriptor: async () => ({}),
        openVaultObject: async ({ object }) =>
          new TextEncoder().encode(
            JSON.stringify({
              v: 1,
              kind: "review-keys",
              review_id: object.id,
              content_key:
                mode === "invalid"
                  ? "YQ"
                  : Buffer.alloc(32, 2).toString("base64url"),
              recipient_private_key: Buffer.alloc(32, 3).toString("base64url"),
            }),
          ),
        openDraftContent: async () => ({ title: "Opened", questions: [] }),
        openDescriptorContent: async () => ({ title: "Opened", questions: [] }),
      },
    });
    for (const nextMode of [
      "valid",
      "missing",
      "invalid",
      "rejected",
      "valid",
    ]) {
      mode = nextMode;
      const before = reads;
      const result = await context.service.listReviews({ orgId: "org" });
      assert.equal(reads - before, 1);
      assert.equal(result.next, "next-page");
      for (const item of result.items) {
        if (mode === "valid") assert.equal(item.title, "Opened");
        else assert.equal(item.contentState, "locked");
      }
    }
    mode = "concurrent";
    const before = reads;
    const first = context.service.listReviews({ orgId: "org" });
    const second = context.service.listReviews({ orgId: "org" });
    // Let both independent list requests reach their pending vault request.
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(reads - before, 2);
    for (const wait of pending) wait.resolve();
    await Promise.all([first, second]);
    mode = "valid";
    const standaloneBefore = reads;
    await context.service.reviewKeys(items[0].id);
    await context.service.reviewKeys(items[0].id);
    assert.equal(reads - standaloneBefore, 2);
  }
});

test("empty review lists never read the vault", async () => {
  const context = await service({
    request: async (path) => {
      assert.equal(path, "/api/member/orgs/org/reviews");
      return { items: [] };
    },
  });
  const result = await context.service.listReviews({ orgId: "org" });
  assert.equal(result.items.length, 0);
});

test("noncreator review list stays locked without vault reads or private metadata", async () => {
  const review = {
    id: "review",
    org_id: "org",
    is_creator: false,
    encrypted_content: { v: 1, nonce: "nonce", ciphertext: "opaque" },
    state: "published",
    issuer_public_key: "public",
    issuer_key_id: "issuer",
  };
  let requests = 0;
  const context = await service({
    request: async (path) => {
      requests++;
      assert.equal(path, "/api/member/orgs/org/reviews");
      return { items: [review] };
    },
  });
  const result = await context.service.listReviews({ orgId: "org" }),
    item = result.items[0];
  assert.equal(requests, 2);
  assert.equal(item.contentState, "locked");
  assert.equal(item.content, undefined);
  assert.equal(item.questions.length, 0);
  for (const key of [
    "title",
    "description",
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
  ])
    assert.equal(Object.hasOwn(item, key), false, key);
});

test("encrypted review lifecycle binds separate keys and keeps all content out of server payloads", async () => {
  const orgId = Buffer.alloc(16, 9).toString("base64url"),
    privateKey = new Uint8Array(32).fill(77),
    publicKey = new Uint8Array(32).fill(78);
  const marker = "PRIVATE-TITLE-MARKER",
    description = "PRIVATE-DESCRIPTION-MARKER",
    question = "PRIVATE-QUESTION-MARKER",
    choice = "PRIVATE-CHOICE-MARKER";
  let stored,
    keys,
    content,
    nonce = 0,
    recipientCalls = 0;
  const payloads = [],
    envelopes = [],
    opened = [];
  const clone = (value) => JSON.parse(JSON.stringify(value));
  const serverReview = () => ({
    id: stored.review_id,
    org_id: orgId,
    is_creator: true,
    encrypted_content: stored.encrypted_content,
    state: "draft",
    issuer_key_id: "issuer-key-id",
    issuer_public_key: "issuer-public-key",
    revision: String(envelopes.length),
    max_responses: stored.max_responses,
    opens_at: stored.opens_at ?? null,
    closes_at: stored.closes_at ?? null,
    issued_count: 0,
    accepted_count: 0,
  });
  const context = await service({
    request: async (path) => {
      if (path.includes("/content-recipients"))
        return { items: [], next: null };
      if (path === "/api/member/vault")
        return { objects: [stored.vault_write.object] };
      return serverReview();
    },
    C: {
      validateReviewContent: (value) => clone(value),
      generateRecipientKey: async () => {
        recipientCalls++;
        return { privateKey, publicKey };
      },
      sealVaultObject: async (options) => {
        keys = JSON.parse(new TextDecoder().decode(options.plaintext));
        assert.equal(options.revision, "1");
        assert.equal(
          Buffer.from(options.objectId).toString("base64url"),
          keys.review_id,
        );
        return {
          v: 1,
          id: keys.review_id,
          revision: "1",
          nonce: "vault-nonce",
          ciphertext: "opaque-vault",
        };
      },
      openVaultObject: async () =>
        new TextEncoder().encode(JSON.stringify(keys)),
      sealReviewContent: async (options) => {
        content = clone(options.content);
        assert.equal(
          Buffer.from(options.contentKey).toString("base64url"),
          keys.content_key,
        );
        assert.equal(
          Buffer.from(options.reviewId).toString("base64url"),
          keys.review_id,
        );
        assert.equal(Buffer.from(options.orgId).toString("base64url"), orgId);
        const envelope = {
          v: 1,
          nonce: String(++nonce),
          ciphertext: "opaque-content",
        };
        envelopes.push(envelope);
        return envelope;
      },
      openDraftContent: async (options) => {
        opened.push(options);
        return clone(content);
      },
      recipientPublicKey: async ({ privateKey: raw }) => {
        assert.deepEqual(Buffer.from(raw), Buffer.from(privateKey));
        return publicKey;
      },
      signDescriptor: async ({ descriptorBytes }) => {
        const descriptor = JSON.parse(
          new TextDecoder().decode(descriptorBytes),
        );
        assert.equal(descriptor.v, 3);
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
        assert.equal(descriptor.reviewer_membership_id, "member");
        assert.deepEqual(descriptor.encrypted_content, envelopes.at(-1));
        assert.equal(
          descriptor.recipient_public_key,
          Buffer.from(publicKey).toString("base64url"),
        );
        return new Uint8Array(64);
      },
    },
  });
  context.configureLifecycle();
  context.setSigned(async (_path, action, payload) => {
    payloads.push({ action, payload: clone(payload) });
    if (action === "review-create") {
      stored = clone(payload);
      throw Error("uncertain create");
    }
    if (action === "review-update") stored = { ...stored, ...clone(payload) };
    return serverReview();
  });
  await assert.rejects(
    context.lifecycle.createReview({ orgId, title: marker, maxResponses: 4 }),
    /uncertain create/,
  );
  const created = await context.lifecycle.createReview({
    orgId,
    title: "must not create another review",
    maxResponses: 4,
  });
  assert.equal(created.title, marker);
  const create = payloads[0].payload;
  assert.deepEqual(
    Object.keys(create).sort(),
    [
      "request_id",
      "review_id",
      "encrypted_content",
      "max_responses",
      "vault_write",
    ].sort(),
  );
  assert.equal(keys.review_id, create.review_id);
  assert.equal(keys.kind, "review-keys");
  assert.equal(keys.v, 1);
  assert.notEqual(keys.content_key, keys.recipient_private_key);
  assert.equal(
    keys.recipient_private_key,
    Buffer.from(privateKey).toString("base64url"),
  );
  await context.lifecycle.updateReview({
    reviewId: create.review_id,
    expectedRevision: "1",
    title: marker,
    description,
    questions: [
      {
        type: "single",
        text: question,
        required: true,
        options: [choice, "OTHER-PRIVATE-CHOICE"],
      },
    ],
    maxResponses: 5,
  });
  assert.equal(envelopes.length, 2);
  assert.notEqual(envelopes[0].nonce, envelopes[1].nonce);
  const update = payloads[1].payload;
  assert.deepEqual(
    Object.keys(update).sort(),
    [
      "request_id",
      "expected_revision",
      "encrypted_content",
      "max_responses",
      "opens_at",
      "closes_at",
    ].sort(),
  );
  await context.lifecycle.publishReview({
    reviewId: create.review_id,
    expectedRevision: "2",
  });
  const publish = payloads[2].payload;
  assert.deepEqual(
    Object.keys(publish).sort(),
    [
      "request_id",
      "expected_revision",
      "descriptor",
      "descriptor_signature",
      "content_key_envelopes",
    ].sort(),
  );
  assert.equal(recipientCalls, 1);
  assert.equal(opened.length, 3);
  assert.equal(envelopes.length, 2);
  for (const { payload } of payloads)
    for (const secret of [
      marker,
      description,
      question,
      choice,
      keys.content_key,
      keys.recipient_private_key,
    ])
      assert.ok(!JSON.stringify(payload).includes(secret));
});

test("recipient directory fetches all pages and rejects duplicate IDs and repeated cursors", async () => {
  const first = Buffer.alloc(16, 1).toString("base64url");
  const second = Buffer.alloc(16, 2).toString("base64url");
  const paths = [];
  const context = await service({
    request: async (path) => {
      paths.push(path);
      return paths.length === 1
        ? { items: [{ membership_id: first }], next: first }
        : { items: [{ membership_id: second }], next: null };
    },
    C: { verifyContentRecipient: async ({ recipient }) => recipient },
  });
  assert.equal(
    (await context.service.contentRecipients("review", "YQ")).length,
    2,
  );
  assert.ok(paths[1].endsWith("?after=" + first));
  for (const page of [
    { items: [{ membership_id: first }, { membership_id: first }], next: null },
    { items: [{ membership_id: first }], next: "bad" },
  ]) {
    const invalid = await service({
      request: async () => page,
      C: { verifyContentRecipient: async ({ recipient }) => recipient },
    });
    await assert.rejects(invalid.service.contentRecipients("review", "YQ"), {
      code: "KEY_UNAVAILABLE",
    });
  }
});
test("completion ignores issuance and invalid local receipts", async () => {
  const records = [
    { reviewId: "review", pendingId: "pending", authorization: {} },
    { reviewId: "review", receipt: {}, submission: {}, encrypted: {} },
  ];
  const context = await service({
    allEncrypted: async () => records,
    C: {
      openVaultObject: async ({ object }) =>
        new TextEncoder().encode(JSON.stringify(object)),
      verifyDescriptor: async () => {
        throw Error("invalid signature");
      },
    },
  });
  assert.equal(await context.service.completedHere("review"), false);
});

test("publication allows one roster rebuild, clears conflicts, and preserves uncertain payloads", async () => {
  const context = await service();
  context.configureLifecycle();
  const payload = { request_id: "first", expected_revision: "2" };
  const next = { request_id: "second", expected_revision: "2" };
  const state = { pendingReviewPublishes: { review: payload } };
  context.setState(state);
  const sent = [];
  context.setSigned(async (_path, _action, body) => {
    sent.push(body);
    throw Object.assign(Error("roster"), { code: "recipient_set_conflict" });
  });
  context.setPublishBuilder(async (reviewId, revision, allowed) => {
    assert.equal(allowed, false);
    assert.equal(revision, "2");
    state.pendingReviewPublishes[reviewId] = next;
    return context.service.sendPublication(reviewId, next, allowed);
  });
  await assert.rejects(
    context.service.sendPublication("review", payload, true),
    { code: "recipient_set_conflict" },
  );
  assert.deepEqual(sent, [payload, next]);
  assert.equal(state.pendingReviewPublishes.review, undefined);
  state.pendingReviewPublishes.review = payload;
  context.setSigned(async (_path, _action, body) => {
    assert.equal(body, payload);
    throw Object.assign(Error("network"), { code: "NETWORK_ERROR" });
  });
  await assert.rejects(
    context.service.sendPublication("review", payload, true),
    { code: "NETWORK_ERROR" },
  );
  assert.equal(state.pendingReviewPublishes.review, payload);
});
test("vault keys verify derived identity binding and reject registered encryption mismatch", async () => {
  let verified = 0;
  const publicKey = new Uint8Array(32).fill(4);
  const context = await service({
    C: {
      membershipPublicKey: async () => new Uint8Array(32).fill(3),
      memberEncryptionPublicKey: async () => publicKey,
      verifyMemberEncryptionKeyBinding: async (args) => {
        verified++;
        assert.deepEqual(
          Buffer.from(args.encryptionPublicKey),
          Buffer.from(publicKey),
        );
      },
    },
  });
  context.configureLifecycle();
  const state = {
    accountId: "YQ",
    membershipSeed: new Uint8Array(32),
    encryptionPrivateKey: new Uint8Array(32),
  };
  const vault = {
    encryption_public_key: Buffer.from(publicKey).toString("base64url"),
    encryption_key_signature: "YQ",
  };
  await context.service.validateMemberKeys(state, vault);
  assert.equal(verified, 1);
  await assert.rejects(
    context.service.validateMemberKeys(state, {
      ...vault,
      encryption_public_key: "wrong",
    }),
    { code: "KEY_UNAVAILABLE" },
  );
  assert.equal(verified, 1);
});
test("member envelope opens with own membership and local completion verifies without network or uploads", async () => {
  let opens = 0,
    receipts = 0;
  const descriptor = {
    deployment_id: "YQ",
    review_id: "Yg",
    issuer_key_id: "Yw",
  };
  const record = {
    reviewId: "Yg",
    descriptor: "ZA",
    descriptorSignature: "ZQ",
    receipt: {},
    encrypted: { enc: "Zg", ciphertext: "Zw" },
    submission: {
      review_id: "Yg",
      issuer_key_id: "Yw",
      enc: "Zg",
      ciphertext: "Zw",
    },
  };
  const context = await service({
    allEncrypted: async () => [record],
    C: {
      openReviewContentKey: async (args) => {
        opens++;
        assert.equal(
          Buffer.from(args.membershipId).toString("base64url"),
          "bQ",
        );
        return new Uint8Array(32);
      },
      openVaultObject: async ({ object }) =>
        new TextEncoder().encode(JSON.stringify(object)),
      verifyDescriptor: async () => descriptor,
      hashBytes: async () => new Uint8Array(32),
      responseHash: async () => new Uint8Array(32),
      getReceiptTrust: () => ({}),
      verifyReceipt: async () => {
        receipts++;
        return {};
      },
    },
  });
  context.setState({
    accountId: "YQ",
    masterKey: new Uint8Array(32),
    encryptionPrivateKey: new Uint8Array(32),
    session: { memberships: [{ org_id: "org", id: "bQ" }] },
  });
  const review = {
    org_id: "org",
    content_key_envelope: { membership_id: "bQ" },
  };
  assert.equal(
    (
      await context.service.memberContentKey(review, {
        descriptor,
        descriptorBytes: new Uint8Array(),
      })
    ).length,
    32,
  );
  assert.equal(opens, 1);
  await assert.rejects(
    context.service.memberContentKey(
      { ...review, content_key_envelope: { membership_id: "other" } },
      {},
    ),
    { code: "KEY_UNAVAILABLE" },
  );
  assert.equal(await context.service.completedHere("Yg"), true);
  assert.equal(receipts, 1);
});

test("registration sends independent encryption key binding and versioned membership vault", async () => {
  const membership = {
    seed: new Uint8Array(32).fill(1),
    publicKey: new Uint8Array(32).fill(2),
  };
  const encryption = {
    privateKey: new Uint8Array(32).fill(3),
    publicKey: new Uint8Array(32).fill(4),
  };
  const signature = new Uint8Array(64).fill(5);
  let plaintext, binding, payload;
  const context = await service({
    C: {
      generateMembershipKey: async () => membership,
      generateMemberEncryptionKeyPair: async () => encryption,
      sealVaultObject: async (args) => {
        plaintext = JSON.parse(new TextDecoder().decode(args.plaintext));
        return {};
      },
      authenticationPublicKey: async () => new Uint8Array(32),
      signMemberEncryptionKeyBinding: async (args) => {
        binding = args;
        return signature;
      },
      passwordMetadataHash: async () => new Uint8Array(32),
      recoveryMetadataHash: async () => new Uint8Array(32),
      wrapVaultMaster: async () => ({}),
    },
  });
  context.configureLifecycle();
  context.setCredentials(async () => ({
    passwordKdf: {},
    recoverySalt: new Uint8Array(32),
    recovery: { words: "word word" },
    p: {},
    r: {},
  }));
  context.setSigned(async (_path, action, value) => {
    assert.equal(action, "register");
    payload = value;
  });
  context.setLogin(async () => ({}));
  await context.service.register({
    email: "member@example.test",
    password: "password",
  });
  assert.equal(payload.encryption_public_key, encryption.publicKey);
  assert.equal(payload.encryption_key_signature, signature);
  assert.equal(binding.membershipSeed, membership.seed);
  assert.equal(binding.membershipPublicKey, membership.publicKey);
  assert.equal(binding.encryptionPublicKey, encryption.publicKey);
  assert.equal(
    Buffer.from(binding.accountId).toString("base64url"),
    payload.account_id,
  );
  assert.deepEqual(plaintext, {
    v: 1,
    kind: "membership",
    encryption_private_key: Buffer.from(encryption.privateKey).toString(
      "base64url",
    ),
    seed: Buffer.from(membership.seed).toString("base64url"),
  });
  assert.equal(Object.hasOwn(payload, "encryption_private_key"), false);
});

test("rejected publication rebuilds corrected revision while unknown outcomes retry exact bytes", async () => {
  const context = await service({
    request: async (path) =>
      path.includes("content-recipients")
        ? { items: [], next: null }
        : {
            org_id: "YQ",
            encrypted_content: {},
            issuer_key_id: "issuer",
            issuer_public_key: "public",
          },
    C: {
      openDraftContent: async () => ({}),
      validateReviewContent: () => {},
      recipientPublicKey: async () => new Uint8Array(32),
      signDescriptor: async () => new Uint8Array(64),
    },
  });
  context.configureLifecycle();
  context.setReviewKeys(async () => ({
    contentKey: new Uint8Array(32),
    privateKey: new Uint8Array(32),
  }));
  const state = { accountId: "YQ", membershipSeed: new Uint8Array(32) };
  context.setState(state);
  const sent = [];
  let error = Object.assign(Error("revision"), {
    code: "REVISION_CONFLICT",
    status: 409,
  });
  context.setSigned(async (_path, _action, payload) => {
    sent.push(payload);
    if (error) throw error;
    return {};
  });
  await assert.rejects(
    context.lifecycle.publishReview({ reviewId: "Yg", expectedRevision: "1" }),
    { status: 409 },
  );
  assert.equal(state.pendingReviewPublishes.Yg, undefined);
  error = Object.assign(Error("unknown"), {
    code: "REQUEST_FAILED",
    status: 503,
  });
  await assert.rejects(
    context.lifecycle.publishReview({ reviewId: "Yg", expectedRevision: "2" }),
    { status: 503 },
  );
  assert.equal(sent[1].expected_revision, "2");
  assert.notEqual(sent[0].request_id, sent[1].request_id);
  assert.equal(state.pendingReviewPublishes.Yg, sent[1]);
  error = Object.assign(Error("reply"), { code: "INVALID_RESPONSE" });
  await assert.rejects(
    context.lifecycle.publishReview({ reviewId: "Yg", expectedRevision: "3" }),
    { code: "INVALID_RESPONSE" },
  );
  assert.equal(sent[2], sent[1]);
  error = undefined;
  await context.lifecycle.publishReview({
    reviewId: "Yg",
    expectedRevision: "3",
  });
  assert.equal(sent[3], sent[1]);
  assert.equal(state.pendingReviewPublishes.Yg, undefined);
});
