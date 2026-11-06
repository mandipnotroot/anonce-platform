// SPDX-License-Identifier: AGPL-3.0-only
import { toBase64url, fromBase64url } from "./crypto.bundle.js";

export { toBase64url, fromBase64url };
export const jsonBytes = (value) =>
  new TextEncoder().encode(JSON.stringify(value));
const binaryKeys = new Set([
  "account_id",
  "challenge_id",
  "payload_hash",
  "nonce",
  "id",
  "salt",
  "ciphertext",
  "password_auth_public_key",
  "recovery_auth_public_key",
  "membership_public_key",
  "recovery_salt",
  "signature",
]);
export function toWire(value) {
  if (value instanceof Uint8Array) return toBase64url(value);
  if (Array.isArray(value)) return value.map(toWire);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, toWire(v)]),
    );
  return value;
}
export function decodeObject(value) {
  return Object.fromEntries(
    Object.entries(value).map(([k, v]) => [
      k,
      binaryKeys.has(k) && typeof v === "string" ? fromBase64url(v) : v,
    ]),
  );
}

export class APIError extends Error {
  constructor(code, message, fields, status) {
    super(message);
    this.name = "APIError";
    this.code = code;
    if (fields) this.fields = fields;
    if (status !== undefined) this.status = status;
  }
}

let csrfToken;
export function setCSRF(token) {
  csrfToken = token;
}

// Anonymous requests deliberately share no session or identifying headers.
export async function request(
  path,
  { method = "GET", body, anonymous = false, signal } = {},
) {
  if (
    !path.startsWith("/api/") ||
    path.includes("://") ||
    path.includes("\\")
  ) {
    throw new APIError("INVALID_REQUEST", "Invalid API request.");
  }
  const headers = { Accept: "application/json" };
  if (body !== undefined || !["GET", "HEAD"].includes(method))
    headers["Content-Type"] = "application/json";
  if (!anonymous && csrfToken && method !== "GET")
    headers["X-CSRF-Token"] = csrfToken;
  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(toWire(body)),
      credentials: anonymous ? "omit" : "same-origin",
      referrerPolicy: "no-referrer",
      redirect: "error",
      cache: "no-store",
      signal,
    });
  } catch {
    throw new APIError(
      "NETWORK_ERROR",
      "The server could not be reached. Retry safely.",
    );
  }
  let result;
  try {
    result = response.status === 204 ? null : await response.json();
  } catch {
    if (response.ok)
      throw new APIError(
        "INVALID_RESPONSE",
        "The server returned an invalid response.",
      );
  }
  if (!response.ok) {
    const code = result?.error?.code ?? result?.code;
    // Do not reflect arbitrary server text, request material, or crypto errors.
    const safeCode =
      typeof code === "string" && /^[A-Z_a-z0-9-]{1,64}$/.test(code)
        ? code.toUpperCase()
        : "REQUEST_FAILED";
    const messages = {
      INVALID_CREDENTIALS: "Email or password is incorrect.",
      INVALID_EMAIL: "Enter a valid email address.",
      INVALID_REGISTRATION: "Check your email and password, then try again.",
      INVALID_NAME: "Enter a valid organization name.",
      EMAIL_EXISTS:
        "An account already uses this email. Sign in or recover that account.",
      ACCOUNT_NOT_FOUND:
        "No account exists for this email. Ask them to create an account or share an invite link.",
      ALREADY_MEMBER: "This person is already a member of this organization.",
      INVALID_REVIEW: "Check review title, limits, dates, and questions.",
      INVALID_NEW_PASSWORD: "Choose a valid new password.",
      INVALID_NEW_RECOVERY:
        "The new recovery phrase could not be saved. Try again.",
      EXPIRED_INVITE: "This invitation has expired. Ask for a new invitation.",
      LAST_OWNER: "Organization must keep at least one owner.",
      NOT_PENDING: "This membership is no longer awaiting approval.",
      EPOCH_CONFLICT: "Account security settings changed. Sign in again.",
      REQUEST_CONFLICT:
        "This request conflicts with a newer change. Refresh and try again.",
      REVISION_CONFLICT: "This review changed. Refresh before saving again.",
      CHALLENGE_USED: "This request was already used. Retry the action.",
      CLOSED: "This review is closed and cannot accept responses.",
      QUOTA_EXHAUSTED: "This review has reached its response limit.",
      INVALID_MEMBERSHIP: "Your organization membership is no longer active.",
      INVALID_PROOF: "Your authorization could not be verified. Sign in again.",
      UNAUTHENTICATED: "Your session has expired. Sign in again.",
      SESSION_REVOKED: "Your session ended. Sign in again.",
      FORBIDDEN: "You do not have permission to do that.",
      NOT_FOUND: "That item is no longer available.",
      RATE_LIMITED: "Too many attempts. Wait a moment, then try again.",
    };
    const statusMessages = {
      400: "Check the information you entered and try again.",
      403: "You do not have permission. Sign in or ask an organization owner for access.",
      401: "Sign in again, then retry your request.",
      409: "This item changed or conflicts with another action. Refresh and try again.",
      410: "This item has expired or closed. Ask for a new invitation or review link.",
      429: "Too many attempts. Wait a moment, then try again.",
    };
    const message =
      messages[safeCode] ||
      (response.status >= 500
        ? "Service is temporarily unavailable. Try again shortly."
        : statusMessages[response.status] ||
          `The request failed (${response.status}). Try again.`);
    throw new APIError(safeCode, message, undefined, response.status);
  }
  return result;
}

export async function signedRequest(
  path,
  { action, accountId, payload, seed, signChallenge, hashBytes },
) {
  const payloadBytes = jsonBytes(payload);
  const challenge = await request("/api/member/challenges", {
    method: "POST",
    body: {
      account_id: accountId,
      action,
      payload_hash: toBase64url(await hashBytes(payloadBytes)),
    },
  });
  const signature = await signChallenge({
    challenge,
    expectedAction: action,
    accountId,
    payloadBytes,
    seed,
  });
  return request(path, {
    method: "POST",
    body: {
      payload: toBase64url(payloadBytes),
      proof: {
        challenge_id: challenge.challenge_id,
        password_sig: toBase64url(signature),
      },
    },
  });
}
