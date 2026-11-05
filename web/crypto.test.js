// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { CryptoError, toBase64url, fromBase64url } from './crypto.js';
import * as c from './crypto.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, SubjectAlternativeNameExtension } from '@peculiar/x509';

const bytes = (n, fill = 1) => new Uint8Array(n).fill(fill);
const b64 = toBase64url;
globalThis.location = { origin: 'https://anonce.test' };
const deploymentId = bytes(32), accountId = bytes(16), reviewId = bytes(16, 2);
const receiptSeed = bytes(32, 3), receiptPublicKey = ed25519.getPublicKey(receiptSeed);
const receiptKeyId = sha256(receiptPublicKey);
const caKeys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
const historicalDates = { notBefore: new Date('2020-01-01T00:00:00Z'), notAfter: new Date('2021-01-01T00:00:00Z') };
const ca = await X509CertificateGenerator.createSelfSigned({ ...historicalDates, name: 'CN=Test CA', keys: caKeys, signingAlgorithm: { name: 'Ed25519' }, extensions: [new BasicConstraintsExtension(true, 0, true), new KeyUsagesExtension(32, true)] }, crypto);
const init = { deploymentId, origin: location.origin, caCertificate: new Uint8Array(ca.rawData), receiptPublicKey, receiptKeyId };
await c.initCrypto(init);
const membership = await c.generateMembershipKey();
const memberPublicKey = await crypto.subtle.importKey('raw', membership.publicKey, 'Ed25519', true, ['verify']);
const certificate = await X509CertificateGenerator.create({ ...historicalDates, subject: 'CN=Member', issuer: ca.subject, publicKey: memberPublicKey, signingKey: caKeys.privateKey, signingAlgorithm: { name: 'Ed25519' }, extensions: [new BasicConstraintsExtension(false, undefined, true), new KeyUsagesExtension(1, true), new SubjectAlternativeNameExtension([{ type: 'url', value: `urn:anonce:deployment:${b64(deploymentId)}:org:${b64(accountId)}:member:${b64(accountId)}` }])] }, crypto);
const rsaSuite = RSABSSA.SHA384.PSS.Randomized();
const rsa = await rsaSuite.generateKey({ modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]) });
const spki = new Uint8Array(await crypto.subtle.exportKey('spki', rsa.publicKey));
const recipient = await c.generateRecipientKey();
const descriptorJSON = { v: 1, deployment_id: b64(deploymentId), review_id: b64(reviewId), org_id: b64(accountId), reviewer_account_id: b64(accountId), reviewer_membership_id: b64(accountId), reviewer_certificate: b64(new Uint8Array(certificate.rawData)), title: 'Review', description: '', questions: [{ id: 'q1', type: 'text', label: 'Feedback', required: true, choices: [] }], recipient_public_key: b64(recipient.publicKey), issuer_key_id: b64(sha256(spki)), issuer_public_key: b64(spki), max_responses: 2, opens_at: null, closes_at: null };
const descriptorBytes = c.utf8(JSON.stringify(descriptorJSON));
const descriptorSignature = await c.signDescriptor({ descriptorBytes, membershipSeed: membership.seed });
const descriptor = await c.verifyDescriptor({ descriptorBytes, signature: descriptorSignature, expectedReviewId: reviewId });

test('base64url is unpadded and canonical', () => {
  const bytes = new Uint8Array([0, 255, 254, 128]);
  assert.equal(toBase64url(bytes), 'AP_-gA');
  assert.deepEqual(fromBase64url('AP_-gA'), bytes);
  assert.deepEqual(fromBase64url(''), new Uint8Array());
  for (const input of ['A', 'AB', 'AB==', 'a+b/', 'AA\n', ' AA', null]) {
    assert.throws(() => fromBase64url(input), CryptoError);
  }
});

test('framing exact lengths and unsigned integers', () => {
  assert.equal(Buffer.from(c.encodeContext('x', [new Uint8Array([2])])).toString('hex'), '414e4f4e43450100017800010000000102');
  assert.equal(Buffer.from(c.u64be('18446744073709551615')).toString('hex'), 'ffffffffffffffff');
  for (const n of ['01', '-1', '18446744073709551616', 1.5]) assert.throws(() => c.u64be(n), CryptoError);
});

test('BIP39 exactly12 words, checksum, entropy recovery and domain separation', async () => {
  const recovery = await c.generateRecovery();
  assert.equal(recovery.words.split(' ').length, 12);
  assert.equal(recovery.entropy.length, 16);
  const args = { words: recovery.words, accountId, recoverySalt: bytes(32) };
  const keys = await c.deriveRecovery(args);
  assert.deepEqual(await c.deriveRecovery(args), keys);
  assert.notDeepEqual(keys.authSeed, keys.wrapKey);
  assert.notDeepEqual((await c.deriveRecovery({ ...args, accountId: bytes(16, 2) })).authSeed, keys.authSeed);
  for (const words of ['abandon '.repeat(11) + 'abandon', recovery.words + ' abandon', recovery.words.toUpperCase(), ' ' + recovery.words]) {
    await assert.rejects(c.deriveRecovery({ ...args, words }), CryptoError);
  }
});

test('password Argon2id, separate auth/wrap contexts and account separation', async () => {
  const kdf = { v: 19, salt: b64(bytes(16, 3)), memory_kib: 65536, iterations: 3, parallelism: 1, length: 32 };
  const args = { password: 'example password', accountId, kdf };
  const keys = await c.derivePassword(args);
  assert.equal(keys.authSeed.length, 32);
  assert.notDeepEqual(keys.authSeed, keys.wrapKey);
  assert.deepEqual(await c.derivePassword(args), keys);
  assert.notDeepEqual((await c.derivePassword({ ...args, password: 'different' })).authSeed, keys.authSeed);
  assert.notDeepEqual((await c.derivePassword({ ...args, accountId: bytes(16, 2) })).authSeed, keys.authSeed);
  await assert.rejects(c.derivePassword({ ...args, kdf: { ...kdf, memory_kib: 1 } }), CryptoError);
});

test('vault wraps and objects authenticate all context and reject tamper', async () => {
  const args = { accountId, kind: 'password', wrapperId: bytes(16, 3), metadataHash: bytes(32, 4), wrapKey: bytes(32, 5), masterKey: bytes(32, 6) };
  const wrapper = await c.wrapVaultMaster(args);
  assert.deepEqual(await c.unwrapVaultMaster({ ...args, wrapper }), args.masterKey);
  for (const change of [{ accountId: bytes(16, 2) }, { kind: 'recovery' }, { metadataHash: bytes(32, 2) }, { wrapKey: bytes(32, 2) }]) {
    await assert.rejects(c.unwrapVaultMaster({ ...args, wrapper, ...change }), CryptoError);
  }
  const ct = fromBase64url(wrapper.ciphertext); ct[0] ^= 1;
  await assert.rejects(c.unwrapVaultMaster({ ...args, wrapper: { ...wrapper, ciphertext: b64(ct) } }), CryptoError);
  const objectArgs = { accountId, masterKey: args.masterKey, objectId: bytes(16, 8), revision: '1', plaintext: c.utf8('private') };
  const object = await c.sealVaultObject(objectArgs);
  assert.deepEqual(await c.openVaultObject({ ...objectArgs, object }), objectArgs.plaintext);
  await assert.rejects(c.openVaultObject({ ...objectArgs, object: { ...object, revision: '2' } }), CryptoError);
  await assert.rejects(c.openVaultObject({ ...objectArgs, object: { ...object, id: b64(bytes(16, 9)) } }), CryptoError);
});

test('device cache uses deployment/account-bound authenticated ChaCha encryption', async () => {
  const args = { key: bytes(32, 7), accountId, plaintext: c.utf8('cache') };
  const object = await c.sealDeviceCache(args);
  assert.deepEqual(await c.openDeviceCache({ ...args, object }), args.plaintext);
  await assert.rejects(c.openDeviceCache({ ...args, object, accountId: bytes(16, 8) }), CryptoError);
});

test('challenge is bound to action account payload epoch expiry and origin', async () => {
  const payloadBytes = c.utf8('{}');
  const challenge = { challenge_id: b64(bytes(16, 9)), account_id: b64(accountId), action: 'test', payload_hash: b64(sha256(payloadBytes)), nonce: b64(bytes(32, 8)), credential_epoch: '1', expires_at: String(Math.floor(Date.now() / 1000) + 300) };
  const args = { challenge, expectedAction: 'test', accountId, payloadBytes, seed: membership.seed };
  assert.equal((await c.signChallenge(args)).length, 64);
  for (const change of [{ expectedAction: 'login' }, { payloadBytes: c.utf8('[]') }, { accountId: bytes(16, 9) }, { challenge: { ...challenge, expires_at: '1' } }]) await assert.rejects(c.signChallenge({ ...args, ...change }), CryptoError);
  location.origin = 'https://wrong.test';
  await assert.rejects(c.signChallenge(args), CryptoError);
  location.origin = init.origin;
});

test('descriptor certificate verification, strict schema, signature and review binding', async () => {
  await assert.rejects(c.verifyDescriptor({ descriptorBytes, signature: descriptorSignature, expectedReviewId: bytes(16, 7) }), CryptoError);
  const wrong = descriptorSignature.slice(); wrong[0] ^= 1;
  await assert.rejects(c.verifyDescriptor({ descriptorBytes, signature: wrong, expectedReviewId: reviewId }), CryptoError);
  for (const data of [{ ...descriptorJSON, max_responses: '2' }, { ...descriptorJSON, suite: 'alternate' }, { ...descriptorJSON, reviewer_membership_id: b64(bytes(16, 4)) }]) {
    const bytes = c.utf8(JSON.stringify(data));
    const signature = await c.signDescriptor({ descriptorBytes: bytes, membershipSeed: membership.seed });
    await assert.rejects(c.verifyDescriptor({ descriptorBytes: bytes, signature, expectedReviewId: reviewId }), CryptoError);
  }
  const duplicate = c.utf8(JSON.stringify(descriptorJSON).replace('"v":1', '"v":1,"v":1'));
  await assert.rejects(c.verifyDescriptor({ descriptorBytes: duplicate, signature: descriptorSignature, expectedReviewId: reviewId }), e => e.code === 'DUPLICATE_JSON_FIELD');
});

test('HPKE roundtrip, ciphertext/enc/context tamper and answers validation', async () => {
  const args = { descriptorBytes, descriptor };
  const sealed = await c.encryptResponse({ ...args, answers: { q1: 'Private feedback' } });
  const open = { ...args, ...sealed, recipientPrivateKey: recipient.privateKey };
  assert.deepEqual((await c.decryptResponse(open)).answers, { q1: 'Private feedback' });
  const ct = sealed.ciphertext.slice(); ct[0] ^= 1;
  await assert.rejects(c.decryptResponse({ ...open, ciphertext: ct }), CryptoError);
  await assert.rejects(c.decryptResponse({ ...open, enc: bytes(32, 8) }), CryptoError);
  await assert.rejects(c.decryptResponse({ ...open, descriptorBytes: c.utf8('{}') }), CryptoError);
  await assert.rejects(c.encryptResponse({ ...args, answers: {} }), CryptoError);
  await assert.rejects(c.encryptResponse({ ...args, answers: { q1: 'ok', unknown: 'bad' } }), CryptoError);
});

test('expired CA and leaf retain historical descriptor verification/decryption, not forged signatures', async () => {
  assert.ok(ca.notAfter.getTime() < Date.now() && certificate.notAfter.getTime() < Date.now());
  const historical = await c.verifyDescriptor({ descriptorBytes, signature: descriptorSignature, expectedReviewId: reviewId });
  const sealed = await c.encryptResponse({ descriptorBytes, descriptor: historical, answers: { q1: 'Historical response' } });
  assert.equal((await c.decryptResponse({ descriptorBytes, descriptor: historical, recipientPrivateKey: recipient.privateKey, ...sealed })).answers.q1, 'Historical response');
  const bad = descriptorSignature.slice(); bad[0] ^= 1;
  await assert.rejects(c.verifyDescriptor({ descriptorBytes, signature: bad, expectedReviewId: reviewId }), CryptoError);
});

async function withQuestions(questions) {
  const bytes = c.utf8(JSON.stringify({ ...descriptorJSON, questions }));
  const signature = await c.signDescriptor({ descriptorBytes: bytes, membershipSeed: membership.seed });
  return { descriptorBytes: bytes, descriptor: await c.verifyDescriptor({ descriptorBytes: bytes, signature, expectedReviewId: reviewId }) };
}

test('aggregate UTF8 byte bounds reject multibyte and oversized encrypted responses', async () => {
  const args = { descriptorBytes, descriptor };
  // 90000 characters are within the per-text limit but need 270000 UTF8 bytes.
  await assert.rejects(c.encryptResponse({ ...args, answers: { q1: '界'.repeat(90000) } }), e => e.code === 'RESPONSE_TOO_LARGE');
  const multi = await withQuestions(Array.from({ length: 4 }, (_, i) => ({ id: `q${i}`, type: 'text', label: 'Text', required: false, choices: [] })));
  await assert.rejects(c.encryptResponse({ ...multi, answers: { q0: 'x'.repeat(70000), q1: 'x'.repeat(70000), q2: 'x'.repeat(70000), q3: 'x'.repeat(70000) } }), e => e.code === 'RESPONSE_TOO_LARGE');
  await assert.rejects(c.decryptResponse({ ...args, recipientPrivateKey: recipient.privateKey, enc: bytes(32), ciphertext: new Uint8Array(262145) }), e => e.code === 'RESPONSE_TOO_LARGE');
  await assert.rejects(c.verifyDescriptor({ descriptorBytes: new Uint8Array(65537), signature: descriptorSignature, expectedReviewId: reviewId }), e => e.code === 'DESCRIPTOR_TOO_LARGE');
});

test('optional answers still have exact types and required prototype-name ids use own properties', async () => {
  const choices = [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }];
  const args = await withQuestions([{ id: 'text', type: 'text', label: 'T', required: false, choices: [] }, { id: 'single', type: 'single', label: 'S', required: false, choices }, { id: 'multiple', type: 'multiple', label: 'M', required: false, choices }]);
  for (const answers of [{ text: [] }, { text: null }, { multiple: '' }, { multiple: null }, { single: [] }, { single: null }]) {
    await assert.rejects(c.encryptResponse({ ...args, answers }), e => e.code === 'INVALID_ANSWER');
  }
  await c.encryptResponse({ ...args, answers: {} });
  await c.encryptResponse({ ...args, answers: { text: '', single: '', multiple: [] } });
  for (const id of ['constructor', 'toString', '__proto__']) {
    const required = await withQuestions([{ id, type: 'text', label: 'Required', required: true, choices: [] }]);
    await assert.rejects(c.encryptResponse({ ...required, answers: {} }), e => e.code === 'MISSING_ANSWER');
    await c.encryptResponse({ ...required, answers: JSON.parse(`{"${id}":"answer"}`) });
  }
});

test('RFC9474 randomized blind authorization roundtrip and malformed context/signature', async () => {
  const state = await c.prepareAuthorization({ descriptorBytes, descriptor });
  assert.equal(state.serial.length, 32); assert.equal(state.inverse.length, 384); assert.equal(state.blindedMessage.length, 384);
  const blindSignature = await rsaSuite.blindSign(rsa.privateKey, state.blindedMessage);
  const token = await c.finalizeAuthorization({ descriptor, ...state, blindSignature });
  assert.equal(token.signature.length, 384);
  assert.equal(await rsaSuite.verify(rsa.publicKey, token.signature, token.preparedMessage), true);
  const preparedMessage = state.preparedMessage.slice(); preparedMessage[40] ^= 1;
  await assert.rejects(c.finalizeAuthorization({ descriptor, ...state, preparedMessage, blindSignature }), CryptoError);
  await assert.rejects(c.finalizeAuthorization({ descriptor, ...state, blindSignature: bytes(384) }), CryptoError);
});

test('Ed25519 receipts bind submission and reject modifications', async () => {
  const receipt = { v: 1, receipt_id: b64(bytes(16, 5)), review_id: b64(reviewId), issuer_key_id: descriptor.issuer_key_id, token_hash: b64(bytes(32, 8)), submission_hash: b64(bytes(32, 9)), accepted_at: '1900000000', receipt_key_id: b64(receiptKeyId) };
  const transcript = c.encodeContext('receipt', [deploymentId, fromBase64url(receipt.receipt_id), reviewId, fromBase64url(receipt.issuer_key_id), fromBase64url(receipt.token_hash), fromBase64url(receipt.submission_hash), c.u64be(receipt.accepted_at), receiptKeyId]);
  receipt.signature = b64(ed25519.sign(transcript, receiptSeed));
  const args = { receipt, expectedSubmissionHash: bytes(32, 9) };
  assert.deepEqual(await c.verifyReceipt(args), receipt);
  await assert.rejects(c.verifyReceipt({ ...args, expectedSubmissionHash: bytes(32, 8) }), CryptoError);
  await assert.rejects(c.verifyReceipt({ ...args, receipt: { ...receipt, accepted_at: '1900000001' } }), CryptoError);
});
