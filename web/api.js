// SPDX-License-Identifier: AGPL-3.0-only
import { toBase64url, fromBase64url } from './crypto.bundle.js';

export { toBase64url, fromBase64url };
export const jsonBytes = value => new TextEncoder().encode(JSON.stringify(value));
const binaryKeys = new Set(['account_id','challenge_id','payload_hash','nonce','id','salt','ciphertext','password_auth_public_key','recovery_auth_public_key','membership_public_key','recovery_salt','signature']);
export function toWire(value) {
  if (value instanceof Uint8Array) return toBase64url(value);
  if (Array.isArray(value)) return value.map(toWire);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,toWire(v)]));
  return value;
}
export function decodeObject(value) {
  return Object.fromEntries(Object.entries(value).map(([k,v])=>[k, binaryKeys.has(k) && typeof v === 'string' ? fromBase64url(v) : v]));
}

export class APIError extends Error {
  constructor(code, message, fields) {
    super(message);
    this.name = 'APIError';
    this.code = code;
    if (fields) this.fields = fields;
  }
}

let csrfToken;
export function setCSRF(token) { csrfToken = token; }

// Anonymous requests deliberately share no session or identifying headers.
export async function request(path, { method = 'GET', body, anonymous = false, signal } = {}) {
  if (!path.startsWith('/api/') || path.includes('://') || path.includes('\\')) {
    throw new APIError('INVALID_REQUEST', 'Invalid API request.');
  }
  const headers = { Accept: 'application/json' };
  if (body !== undefined || !['GET','HEAD'].includes(method)) headers['Content-Type'] = 'application/json';
  if (!anonymous && csrfToken && method !== 'GET') headers['X-CSRF-Token'] = csrfToken;
  let response;
  try {
    response = await fetch(path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(toWire(body)),
      credentials: anonymous ? 'omit' : 'same-origin',
      referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store', signal,
    });
  } catch {
    throw new APIError('NETWORK_ERROR', 'The server could not be reached. Retry safely.');
  }
  let result;
  try { result = response.status === 204 ? null : await response.json(); }
  catch { throw new APIError('INVALID_RESPONSE', 'The server returned an invalid response.'); }
  if (!response.ok) {
    const code = result?.error?.code ?? result?.code;
    // Do not reflect arbitrary server text, request material, or crypto errors.
    throw new APIError(typeof code === 'string' && /^[A-Z_a-z0-9-]{1,64}$/.test(code) ? code : 'REQUEST_FAILED',
      response.status === 401 ? 'Please sign in again.' : 'The request could not be completed.');
  }
  return result;
}

export async function signedRequest(path, { action, accountId, payload, seed, signChallenge, hashBytes }) {
  const payloadBytes = jsonBytes(payload);
  const challenge = await request('/api/member/challenges', {
    method: 'POST', body: { account_id: accountId, action, payload_hash: toBase64url(await hashBytes(payloadBytes)) },
  });
  const signature = await signChallenge({ challenge, expectedAction: action, accountId, payloadBytes, seed });
  return request(path, { method: 'POST', body: {
    payload: toBase64url(payloadBytes), proof: { challenge_id: challenge.challenge_id, password_sig: toBase64url(signature) },
  } });
}
