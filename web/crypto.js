// SPDX-License-Identifier: AGPL-3.0-only
// Cryptographic operations are implemented by established, locally bundled
// libraries. No private input is sent to a remote service by this module.
import 'reflect-metadata';
import { argon2id } from 'hash-wasm';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { X509Certificate, BasicConstraintsExtension, KeyUsagesExtension, SubjectAlternativeNameExtension } from '@peculiar/x509';

export class CryptoError extends Error {
  constructor(code) {
    super(code);
    this.name = 'CryptoError';
    this.code = code;
  }
}

function requireBytes(value, length) {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) {
    throw new CryptoError('INVALID_BYTES');
  }
  return value;
}

export function toBase64url(bytes) {
  requireBytes(bytes);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function fromBase64url(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new CryptoError('INVALID_BASE64URL');
  }
  try {
    const bytes = Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
    if (toBase64url(bytes) !== text) throw new CryptoError('INVALID_BASE64URL');
    return bytes;
  } catch {
    throw new CryptoError('INVALID_BASE64URL');
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export const utf8 = text => {
  if (typeof text !== 'string') throw new CryptoError('INVALID_STRING');
  return encoder.encode(text);
};
const random = n => crypto.getRandomValues(new Uint8Array(n));
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const check = (condition, code = 'INVALID_INPUT') => { if (!condition) throw new CryptoError(code); };
const decode = (text, length) => requireBytes(fromBase64url(text), length);
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};
function uint(value, size) {
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  if (size === 2) view.setUint16(0, value);
  else view.setUint32(0, value);
  return out;
}
export function u64be(value) {
  check((typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) || (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0), 'INVALID_INTEGER');
  const n = BigInt(value);
  check(n <= 0xffffffffffffffffn, 'INVALID_INTEGER');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n);
  return out;
}
export function encodeContext(label, fields = []) {
  check(typeof label === 'string' && /^[\x20-\x7e]+$/.test(label) && label.length <= 65535);
  check(Array.isArray(fields) && fields.length <= 65535);
  const name = utf8(label);
  const encoded = fields.map(field => {
    requireBytes(field);
    check(field.length <= 0xffffffff);
    return concat(uint(field.length, 4), field);
  });
  return concat(utf8('ANONCE'), new Uint8Array([1]), uint(name.length, 2), name, uint(fields.length, 2), ...encoded);
}
export async function hashBytes(bytes) { return sha256(requireBytes(bytes)); }
let config;
const deployment = () => { check(config, 'NOT_INITIALIZED'); return config.deploymentId; };
const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
const blindSuite = RSABSSA.SHA384.PSS.Randomized();
const guard = async fn => {
  try { return await fn(); } catch (e) {
    if (e instanceof CryptoError) throw e;
    // Never include provider error strings: they may contain supplied data.
    throw new CryptoError('CRYPTO_OPERATION_FAILED');
  }
};

export async function initCrypto({ deploymentId, origin, caCertificate, receiptPublicKey, receiptKeyId }) {
  config = undefined;
  return guard(async () => {
    requireBytes(deploymentId, 32); requireBytes(receiptPublicKey, 32); requireBytes(receiptKeyId, 32);
    check(typeof location !== 'undefined' && origin === location.origin, 'ORIGIN_MISMATCH');
    const ca = new X509Certificate(requireBytes(caCertificate));
    check(ca.publicKey.algorithm.name === 'Ed25519' && ca.signatureAlgorithm.name === 'Ed25519', 'INVALID_CA');
    check(ca.getExtension(BasicConstraintsExtension)?.ca === true && (ca.getExtension(KeyUsagesExtension)?.usages & 32) !== 0, 'INVALID_CA');
    // Trust anchor/profile/signature validation, not a claim about publication
    // time or current membership. Expired certificates must remain decryptable.
    check(await ca.verify({ signatureOnly: true }, crypto), 'INVALID_CA');
    check(equal(sha256(receiptPublicKey), receiptKeyId), 'INVALID_RECEIPT_KEY');
    config = { deploymentId: deploymentId.slice(), origin, ca, receiptPublicKey: receiptPublicKey.slice(), receiptKeyId: receiptKeyId.slice() };
  });
}

export async function generateRecovery() {
  const entropy = random(16);
  return { words: entropyToMnemonic(entropy, wordlist), entropy };
}
export async function passwordMetadataHash(kdf) {
  return guard(() => {
    exactKeys(kdf, ['v', 'salt', 'memory_kib', 'iterations', 'parallelism', 'length']);
    check(kdf.v === 19 && kdf.memory_kib === 65536 && kdf.iterations === 3 && kdf.parallelism === 1 && kdf.length === 32, 'INVALID_KDF');
    return sha256(encodeContext('password-params', [decode(kdf.salt, 16), u64be(kdf.v), u64be(kdf.memory_kib), u64be(kdf.iterations), u64be(kdf.parallelism), u64be(kdf.length)]));
  });
}
export async function recoveryMetadataHash(recoverySalt) {
  return guard(() => sha256(encodeContext('recovery-params', [requireBytes(recoverySalt, 32)])));
}
export async function derivePassword({ password, accountId, kdf }) {
  return guard(async () => {
    requireBytes(accountId, 16);
    exactKeys(kdf, ['v', 'salt', 'memory_kib', 'iterations', 'parallelism', 'length']);
    check(kdf.v === 19 && kdf.memory_kib === 65536 && kdf.iterations === 3 && kdf.parallelism === 1 && kdf.length === 32, 'INVALID_KDF');
    const salt = decode(kdf.salt, 16);
    const input = typeof password === 'string' ? utf8(password) : requireBytes(password);
    const output = await argon2id({ password: input, salt, parallelism: 1, iterations: 3, memorySize: 65536, hashLength: 32, outputType: 'binary' });
    try {
      const scope = sha256(encodeContext('password-kdf', [deployment(), accountId]));
      return { authSeed: hkdf(sha256, output, scope, encodeContext('password-auth'), 32), wrapKey: hkdf(sha256, output, scope, encodeContext('password-wrap'), 32) };
    } finally { output.fill(0); }
  });
}
export async function deriveRecovery({ words, accountId, recoverySalt }) {
  return guard(async () => {
    check(typeof words === 'string' && words.split(' ').length === 12 && words === words.trim() && !/\s{2}|[^a-z ]/.test(words), 'INVALID_RECOVERY');
    const entropy = mnemonicToEntropy(words, wordlist);
    requireBytes(entropy, 16); requireBytes(accountId, 16); requireBytes(recoverySalt, 32);
    try {
      const scope = sha256(encodeContext('recovery-kdf', [deployment(), accountId, recoverySalt]));
      return { authSeed: hkdf(sha256, entropy, scope, encodeContext('recovery-auth'), 32), wrapKey: hkdf(sha256, entropy, scope, encodeContext('recovery-wrap'), 32) };
    } finally { entropy.fill(0); }
  });
}
export async function generateMembershipKey() {
  const seed = random(32);
  return { seed, publicKey: ed25519.getPublicKey(seed) };
}
export async function generateRecipientKey() {
  const privateKey = random(32);
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}
export async function authenticationPublicKey({ authSeed }) { return guard(() => ed25519.getPublicKey(requireBytes(authSeed, 32))); }

function wrapAAD(accountId, kind, wrapperId, metadataHash) {
  check(kind === 'password' || kind === 'recovery', 'INVALID_WRAPPER_KIND');
  return encodeContext('vault-wrap', [deployment(), requireBytes(accountId, 16), utf8(kind), requireBytes(wrapperId, 16), requireBytes(metadataHash, 32)]);
}
export async function wrapVaultMaster({ accountId, kind, wrapperId, metadataHash, wrapKey, masterKey }) {
  return guard(() => {
    const nonce = random(12);
    const aad = wrapAAD(accountId, kind, wrapperId, metadataHash);
    const ciphertext = chacha20poly1305(requireBytes(wrapKey, 32), nonce, aad).encrypt(requireBytes(masterKey, 32));
    return { v: 1, id: toBase64url(wrapperId), nonce: toBase64url(nonce), ciphertext: toBase64url(ciphertext) };
  });
}
export async function unwrapVaultMaster({ accountId, kind, metadataHash, wrapKey, wrapper }) {
  return guard(() => {
    exactKeys(wrapper, ['v', 'id', 'nonce', 'ciphertext']);
    check(wrapper.v === 1, 'INVALID_VERSION');
    const aad = wrapAAD(accountId, kind, decode(wrapper.id, 16), metadataHash);
    return requireBytes(chacha20poly1305(requireBytes(wrapKey, 32), decode(wrapper.nonce, 12), aad).decrypt(decode(wrapper.ciphertext, 48)), 32);
  });
}
function objectKey(masterKey, accountId, objectId) {
  const scope = sha256(encodeContext('vault-kdf', [deployment(), requireBytes(accountId, 16), requireBytes(objectId, 16)]));
  return hkdf(sha256, requireBytes(masterKey, 32), scope, encodeContext('vault-object'), 32);
}
export async function sealVaultObject({ accountId, masterKey, objectId, revision, plaintext }) {
  return guard(() => {
    check(typeof revision === 'string', 'INVALID_INTEGER');
    const key = objectKey(masterKey, accountId, objectId);
    try {
      const nonce = random(12);
      const aad = encodeContext('vault-object', [deployment(), accountId, objectId, u64be(revision)]);
      const ciphertext = chacha20poly1305(key, nonce, aad).encrypt(requireBytes(plaintext));
      return { v: 1, id: toBase64url(objectId), revision, nonce: toBase64url(nonce), ciphertext: toBase64url(ciphertext) };
    } finally { key.fill(0); }
  });
}
export async function openVaultObject({ accountId, masterKey, object }) {
  return guard(() => {
    exactKeys(object, ['v', 'id', 'revision', 'nonce', 'ciphertext']);
    check(object.v === 1 && typeof object.revision === 'string', 'INVALID_VERSION');
    const id = decode(object.id, 16);
    const key = objectKey(masterKey, accountId, id);
    try {
      return chacha20poly1305(key, decode(object.nonce, 12), encodeContext('vault-object', [deployment(), accountId, id, u64be(object.revision)])).decrypt(decode(object.ciphertext));
    } finally { key.fill(0); }
  });
}

export async function signChallenge({ challenge, expectedAction, accountId, payloadBytes, seed }) {
  return guard(() => {
    exactKeys(challenge, ['challenge_id', 'account_id', 'action', 'payload_hash', 'nonce', 'credential_epoch', 'expires_at']);
    check(typeof challenge.expires_at === 'string' && typeof challenge.credential_epoch === 'string', 'INVALID_INTEGER');
    check(config && location.origin === config.origin, 'ORIGIN_MISMATCH');
    check(challenge.action === expectedAction && typeof expectedAction === 'string', 'CHALLENGE_ACTION_MISMATCH');
    check(equal(decode(challenge.account_id, 16), requireBytes(accountId, 16)), 'CHALLENGE_ACCOUNT_MISMATCH');
    const hash = sha256(requireBytes(payloadBytes));
    check(equal(hash, decode(challenge.payload_hash, 32)), 'CHALLENGE_PAYLOAD_MISMATCH');
    u64be(challenge.expires_at);
    check(BigInt(challenge.expires_at) > BigInt(Math.floor(Date.now() / 1000)), 'CHALLENGE_EXPIRED');
    const message = encodeContext('challenge', [deployment(), utf8(config.origin), accountId, decode(challenge.challenge_id, 16), utf8(expectedAction), u64be(challenge.credential_epoch), hash, decode(challenge.nonce, 32), u64be(challenge.expires_at)]);
    return ed25519.sign(message, requireBytes(seed, 32));
  });
}
export async function signDescriptor({ descriptorBytes, membershipSeed }) {
  return guard(() => ed25519.sign(encodeContext('review-descriptor', [requireBytes(descriptorBytes)]), requireBytes(membershipSeed, 32)));
}

const verifiedDescriptors = new WeakMap();
const descriptorKeys = ['v', 'deployment_id', 'review_id', 'org_id', 'reviewer_account_id', 'reviewer_membership_id', 'reviewer_certificate', 'title', 'description', 'questions', 'recipient_public_key', 'issuer_key_id', 'issuer_public_key', 'max_responses', 'opens_at', 'closes_at'];
function exactKeys(object, keys) {
  check(object && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).length === keys.length && keys.every(k => Object.hasOwn(object, k)), 'INVALID_SCHEMA');
}
function parseJSON(bytes) {
  check(bytes.length <= 1048576, 'INPUT_TOO_LARGE');
  const text = decoder.decode(bytes);
  const result = JSON.parse(text);
  // Native JSON.parse validates grammar but silently overwrites duplicate keys.
  // Scan only structural tokens and complete JSON strings to reject duplicates,
  // including escaped spellings of a key, before trusting the parsed result.
  const tokens = [...text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]/g)].map(m => m[0]);
  const stack = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === '{') stack.push(new Set());
    else if (t === '[') stack.push(null);
    else if (t === '}' || t === ']') stack.pop();
    else if (t.startsWith('"') && tokens[i + 1] === ':') {
      const key = JSON.parse(t);
      const keys = stack.at(-1);
      check(keys && !keys.has(key), 'DUPLICATE_JSON_FIELD');
      keys.add(key);
    }
  }
  return result;
}
function validateQuestions(questions) {
  check(Array.isArray(questions) && questions.length > 0 && questions.length <= 100, 'INVALID_QUESTIONS');
  const ids = new Set();
  for (const q of questions) {
    exactKeys(q, ['id', 'type', 'label', 'required', 'choices']);
    check(typeof q.id === 'string' && q.id.length > 0 && !ids.has(q.id) && typeof q.label === 'string' && q.label.length > 0 && typeof q.required === 'boolean', 'INVALID_QUESTION');
    ids.add(q.id);
    check(['text', 'single', 'multiple'].includes(q.type) && Array.isArray(q.choices), 'INVALID_QUESTION');
    check(q.type === 'text' ? q.choices.length === 0 : q.choices.length >= 2, 'INVALID_CHOICES');
    const choices = new Set();
    for (const c of q.choices) {
      exactKeys(c, ['id', 'label']);
      check(typeof c.id === 'string' && c.id.length > 0 && !choices.has(c.id) && typeof c.label === 'string' && c.label.length > 0, 'INVALID_CHOICES');
      choices.add(c.id);
    }
  }
}
async function issuerKey(d) {
  const spki = decode(d.issuer_public_key);
  check(equal(sha256(spki), decode(d.issuer_key_id, 32)), 'ISSUER_KEY_MISMATCH');
  const key = await crypto.subtle.importKey('spki', spki, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  check(key.algorithm.modulusLength === 3072 && equal(new Uint8Array(key.algorithm.publicExponent), new Uint8Array([1, 0, 1])), 'INVALID_RSA_KEY');
  return key;
}
export async function verifyDescriptor({ descriptorBytes, signature, expectedReviewId }) {
  return guard(async () => {
    const bytes = requireBytes(descriptorBytes).slice();
    check(bytes.length <= 65536, 'DESCRIPTOR_TOO_LARGE');
    const d = parseJSON(bytes);
    exactKeys(d, descriptorKeys);
    check(d.v === 1 && equal(decode(d.deployment_id, 32), deployment()), 'INVALID_DESCRIPTOR');
    check(equal(decode(d.review_id, 16), requireBytes(expectedReviewId, 16)), 'REVIEW_MISMATCH');
    decode(d.org_id, 16); decode(d.reviewer_account_id, 16); decode(d.reviewer_membership_id, 16); decode(d.recipient_public_key, 32);
    check(typeof d.title === 'string' && d.title.length > 0 && typeof d.description === 'string', 'INVALID_DESCRIPTOR');
    validateQuestions(d.questions);
    check(Number.isSafeInteger(d.max_responses) && d.max_responses >= 1 && d.max_responses <= 1000000, 'INVALID_QUOTA');
    for (const t of [d.opens_at, d.closes_at]) if (t !== null) { check(typeof t === 'string'); u64be(t); }
    if (d.opens_at !== null && d.closes_at !== null) check(BigInt(d.opens_at) < BigInt(d.closes_at), 'INVALID_WINDOW');
    await issuerKey(d);
    const cert = new X509Certificate(decode(d.reviewer_certificate));
    check(cert.publicKey.algorithm.name === 'Ed25519' && cert.signatureAlgorithm.name === 'Ed25519', 'INVALID_CERTIFICATE');
    check(cert.issuer === config.ca.subject && cert.getExtension(BasicConstraintsExtension)?.ca === false, 'INVALID_CERTIFICATE');
    check(cert.getExtension(KeyUsagesExtension)?.usages === 1, 'INVALID_CERTIFICATE');
    const allowedCritical = new Set(['2.5.29.19', '2.5.29.15', '2.5.29.17']);
    check(cert.extensions.every(e => !e.critical || allowedCritical.has(e.type)), 'INVALID_CERTIFICATE');
    check(new Set(cert.extensions.map(e => e.type)).size === cert.extensions.length, 'INVALID_CERTIFICATE');
    check(await config.ca.verify({ signatureOnly: true }, crypto) && await cert.verify({ publicKey: config.ca.publicKey, signatureOnly: true }, crypto), 'INVALID_CERTIFICATE');
    const san = cert.getExtension(SubjectAlternativeNameExtension)?.names.items;
    const expectedSAN = `urn:anonce:deployment:${d.deployment_id}:org:${d.org_id}:member:${d.reviewer_membership_id}`;
    check(san?.length === 1 && san[0].type === 'url' && san[0].value === expectedSAN, 'MEMBERSHIP_MISMATCH');
    const pub = await cert.publicKey.export(crypto);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pub));
    check(ed25519.verify(requireBytes(signature, 64), encodeContext('review-descriptor', [bytes]), raw, { zip215: false }), 'INVALID_DESCRIPTOR_SIGNATURE');
    verifiedDescriptors.set(d, { bytes, json: JSON.stringify(d), key: await issuerKey(d) });
    return d;
  });
}
function trustedDescriptor(descriptor, bytes) {
  const state = verifiedDescriptors.get(descriptor);
  check(state && state.json === JSON.stringify(descriptor) && (!bytes || equal(state.bytes, requireBytes(bytes))), 'UNVERIFIED_DESCRIPTOR');
  return state;
}
function responseContext(label, d, bytes) {
  return encodeContext(label, [deployment(), decode(d.review_id, 16), sha256(bytes)]);
}
export async function prepareAuthorization({ descriptorBytes, descriptor }) {
  return guard(async () => {
    const state = trustedDescriptor(descriptor, descriptorBytes);
    const serial = random(32);
    const token = encodeContext('authorization', [deployment(), decode(descriptor.review_id, 16), sha256(state.bytes), decode(descriptor.issuer_key_id, 32), serial]);
    const preparedMessage = blindSuite.prepare(token);
    const { blindedMsg, inv } = await blindSuite.blind(state.key, preparedMessage);
    requireBytes(blindedMsg, 384); requireBytes(inv, 384);
    return { serial, preparedMessage, blindedMessage: blindedMsg, inverse: inv };
  });
}
export async function finalizeAuthorization({ descriptor, preparedMessage, inverse, blindSignature }) {
  return guard(async () => {
    const state = trustedDescriptor(descriptor);
    const bytes = requireBytes(preparedMessage);
    const prefix = encodeContext('authorization', [deployment(), decode(descriptor.review_id, 16), sha256(state.bytes), decode(descriptor.issuer_key_id, 32), new Uint8Array(32)]);
    check(bytes.length === 32 + prefix.length && equal(bytes.subarray(32, bytes.length - 32), prefix.subarray(0, prefix.length - 32)), 'INVALID_AUTHORIZATION_CONTEXT');
    const signature = await blindSuite.finalize(state.key, bytes, requireBytes(blindSignature, 384), requireBytes(inverse, 384));
    check(await blindSuite.verify(state.key, signature, bytes), 'INVALID_AUTHORIZATION_SIGNATURE');
    return { preparedMessage: bytes.slice(), signature };
  });
}
function validateAnswers(d, answers) {
  check(answers && typeof answers === 'object' && !Array.isArray(answers), 'INVALID_ANSWERS');
  const questions = new Map(d.questions.map(q => [q.id, q]));
  check(Object.keys(answers).every(id => questions.has(id)), 'INVALID_ANSWERS');
  for (const [id, q] of questions) {
    if (!Object.hasOwn(answers, id)) {
      check(!q.required, 'MISSING_ANSWER');
      continue;
    }
    const a = answers[id];
    if (q.type === 'text') check(typeof a === 'string' && a.length <= 100000, 'INVALID_ANSWER');
    else if (q.type === 'single') check(typeof a === 'string' && (a === '' || q.choices.some(c => c.id === a)), 'INVALID_ANSWER');
    else check(Array.isArray(a) && new Set(a).size === a.length && a.every(v => typeof v === 'string' && q.choices.some(c => c.id === v)), 'INVALID_ANSWER');
    const empty = a === '' || (Array.isArray(a) && a.length === 0);
    check(!q.required || !empty, 'MISSING_ANSWER');
  }
}
export async function encryptResponse({ descriptorBytes, descriptor, answers }) {
  return guard(async () => {
    const state = trustedDescriptor(descriptor, descriptorBytes);
    validateAnswers(descriptor, answers);
    const plaintext = utf8(JSON.stringify({ v: 1, review_id: descriptor.review_id, descriptor_hash: toBase64url(sha256(state.bytes)), answers }));
    check(plaintext.length + 16 <= 262144, 'RESPONSE_TOO_LARGE');
    const publicKey = await suite.kem.deserializePublicKey(decode(descriptor.recipient_public_key, 32));
    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey, info: responseContext('response-hpke', descriptor, state.bytes) });
    const ciphertext = new Uint8Array(await sender.seal(plaintext, responseContext('response-aad', descriptor, state.bytes)));
    return { enc: requireBytes(new Uint8Array(sender.enc), 32), ciphertext };
  });
}
export async function decryptResponse({ descriptorBytes, descriptor, recipientPrivateKey, enc, ciphertext }) {
  return guard(async () => {
    const state = trustedDescriptor(descriptor, descriptorBytes);
    requireBytes(ciphertext);
    check(ciphertext.length >= 16 && ciphertext.length <= 262144, 'RESPONSE_TOO_LARGE');
    requireBytes(recipientPrivateKey, 32);
    check(equal(x25519.getPublicKey(recipientPrivateKey), decode(descriptor.recipient_public_key, 32)), 'RECIPIENT_KEY_MISMATCH');
    const privateKey = await suite.kem.deserializePrivateKey(recipientPrivateKey);
    const recipient = await suite.createRecipientContext({ recipientKey: privateKey, enc: requireBytes(enc, 32), info: responseContext('response-hpke', descriptor, state.bytes) });
    const plaintext = new Uint8Array(await recipient.open(requireBytes(ciphertext), responseContext('response-aad', descriptor, state.bytes)));
    const result = parseJSON(plaintext);
    exactKeys(result, ['v', 'review_id', 'descriptor_hash', 'answers']);
    check(result.v === 1 && result.review_id === descriptor.review_id && result.descriptor_hash === toBase64url(sha256(state.bytes)), 'RESPONSE_CONTEXT_MISMATCH');
    validateAnswers(descriptor, result.answers);
    return result;
  });
}
export async function submissionHash({ review_id, issuer_key_id, prepared_message, signature, enc, ciphertext }) {
  return sha256(encodeContext('submission', [decode(review_id, 16), decode(issuer_key_id, 32), decode(prepared_message), decode(signature, 384), decode(enc, 32), decode(ciphertext)]));
}
export async function verifyReceipt({ receipt, expectedSubmissionHash }) {
  return guard(() => {
    exactKeys(receipt, ['v', 'receipt_id', 'review_id', 'issuer_key_id', 'token_hash', 'submission_hash', 'accepted_at', 'receipt_key_id', 'signature']);
    check(receipt.v === 1 && typeof receipt.accepted_at === 'string', 'INVALID_RECEIPT');
    check(equal(decode(receipt.submission_hash, 32), requireBytes(expectedSubmissionHash, 32)), 'SUBMISSION_HASH_MISMATCH');
    check(equal(decode(receipt.receipt_key_id, 32), config.receiptKeyId), 'RECEIPT_KEY_MISMATCH');
    const message = encodeContext('receipt', [deployment(), decode(receipt.receipt_id, 16), decode(receipt.review_id, 16), decode(receipt.issuer_key_id, 32), decode(receipt.token_hash, 32), decode(receipt.submission_hash, 32), u64be(receipt.accepted_at), decode(receipt.receipt_key_id, 32)]);
    check(ed25519.verify(decode(receipt.signature, 64), message, config.receiptPublicKey, { zip215: false }), 'INVALID_RECEIPT_SIGNATURE');
    return structuredClone(receipt);
  });
}

export async function sealDeviceCache({ key, accountId, plaintext }) {
  return guard(() => {
    const nonce = random(12);
    const aad = encodeContext('device-cache', [deployment(), requireBytes(accountId, 16)]);
    const ciphertext = chacha20poly1305(requireBytes(key, 32), nonce, aad).encrypt(requireBytes(plaintext));
    return { v: 1, nonce: toBase64url(nonce), ciphertext: toBase64url(ciphertext) };
  });
}
export async function openDeviceCache({ key, accountId, object }) {
  return guard(() => {
    exactKeys(object, ['v', 'nonce', 'ciphertext']);
    check(object.v === 1, 'INVALID_VERSION');
    const aad = encodeContext('device-cache', [deployment(), requireBytes(accountId, 16)]);
    return chacha20poly1305(requireBytes(key, 32), decode(object.nonce, 12), aad).decrypt(decode(object.ciphertext));
  });
}
