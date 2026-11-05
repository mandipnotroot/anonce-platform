// SPDX-License-Identifier: AGPL-3.0-only
// Compatibility checks with ephemeral test data, not an audit or assurance claim.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { toBase64url as b64, fromBase64url as dec, encodeContext as E, utf8, u64be } from '../web/crypto.js';

// CIRCL distributes the published RFC 9474 vectors with its pinned module.
// Read that independently maintained fixture rather than generating an oracle.
const circlDir = execFileSync('go', ['list', '-m', '-f', '{{.Dir}}', 'github.com/cloudflare/circl'], { encoding: 'utf8' }).trim();
const vectors = JSON.parse(gunzipSync(readFileSync(join(circlDir, 'blindsign/blindrsa/testdata/test_vectors_rfc9474.json.gz'))));
const vector = vectors.find(v => v.name === 'RSABSSA-SHA384-PSS-Randomized');
const hex = s => new Uint8Array(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const vectorSuite = RSABSSA.SHA384.PSS.Randomized();
const vectorKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: b64(hex(vector.n)), e: b64(hex(vector.e)), alg: 'PS384', ext: true }, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
assert.equal(await vectorSuite.verify(vectorKey, hex(vector.sig), hex(vector.input_msg)), true);
assert.deepEqual(await vectorSuite.finalize(vectorKey, hex(vector.input_msg), hex(vector.blind_sig), hex(vector.inv)), hex(vector.sig));
assert.deepEqual(hex(vector.input_msg), new Uint8Array([...hex(vector.msg_prefix), ...hex(vector.msg)]));
console.log('PASS published RFC9474 SHA384-PSS-Randomized vector verify and exact finalize');

const child = spawn('go', ['run', './scripts/crypto-fixture.go'], { stdio: ['pipe', 'pipe', 'inherit'] });
const lines = createInterface({ input: child.stdout });
const iterator = lines[Symbol.asyncIterator]();
const exit = once(child, 'exit');
async function call(request) {
  child.stdin.write(JSON.stringify(request) + '\n');
  const { value, done } = await iterator.next();
  assert.equal(done, false, 'Go fixture unexpectedly closed stdout');
  return JSON.parse(value);
}
try {
  const init = await call({ op: 'init' });
  assert.ok(init.rsa_spki && init.hpke_public_key);
  const fields = [new Uint8Array(0), utf8('deployment'), u64be('18446744073709551615')];
  assert.equal((await call({ op: 'context', label: 'interop', fields: fields.map(b64) })).bytes, b64(E('interop', fields)));
  console.log('PASS Go/browser E framing and U64BE');

  const key = new Uint8Array(32).fill(3), salt = new Uint8Array(32).fill(4), info = E('interop-kdf');
  assert.equal((await call({ op: 'hkdf', key: b64(key), salt: b64(salt), info: b64(info) })).bytes, b64(hkdf(sha256, key, salt, info, 32)));
  console.log('PASS Go/browser HKDF-SHA256');

  const nonce = new Uint8Array(12).fill(5), aad = E('interop-aad'), plaintext = utf8('dummy interop plaintext');
  const ciphertext = chacha20poly1305(key, nonce, aad).encrypt(plaintext);
  assert.equal((await call({ op: 'chacha-open', key: b64(key), nonce: b64(nonce), aad: b64(aad), ciphertext: b64(ciphertext) })).plaintext, b64(plaintext));
  assert.equal((await call({ op: 'chacha-seal', key: b64(key), nonce: b64(nonce), aad: b64(aad), plaintext: b64(plaintext) })).ciphertext, b64(ciphertext));
  assert.ok((await call({ op: 'chacha-open', key: b64(key), nonce: b64(nonce), aad: b64(E('wrong')), ciphertext: b64(ciphertext) })).error);
  console.log('PASS Go/browser ChaCha20-Poly1305 both directions and AAD tamper');

  const rsaSuite = RSABSSA.SHA384.PSS.Randomized();
  const publicKey = await crypto.subtle.importKey('spki', dec(init.rsa_spki), { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  const message = E('authorization', [key, salt.subarray(0, 16), sha256(plaintext), sha256(dec(init.rsa_spki)), key]);
  const prepared = rsaSuite.prepare(message);
  const blind = await rsaSuite.blind(publicKey, prepared);
  const signed = await call({ op: 'sign', message: b64(blind.blindedMsg) });
  const signature = await rsaSuite.finalize(publicKey, prepared, dec(signed.blind_signature), blind.inv);
  assert.equal(await rsaSuite.verify(publicKey, signature, prepared), true);
  assert.equal((await call({ op: 'verify', message: b64(prepared), signature: b64(signature) })).valid, true);
  const bad = prepared.slice(); bad[0] ^= 1;
  assert.equal((await call({ op: 'verify', message: b64(bad), signature: b64(signature) })).valid, false);
  console.log('PASS browser blind -> CIRCL blind sign -> browser finalize -> CIRCL verify; tamper rejected');

  const hpke = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
  const publicHPKE = await hpke.kem.deserializePublicKey(dec(init.hpke_public_key));
  const privateHPKE = await hpke.kem.deserializePrivateKey(dec(init.hpke_private_key));
  const sender = await hpke.createSenderContext({ recipientPublicKey: publicHPKE, info });
  const sealed = new Uint8Array(await sender.seal(plaintext, aad));
  assert.equal((await call({ op: 'hpke-open', info: b64(info), aad: b64(aad), enc: b64(new Uint8Array(sender.enc)), ciphertext: b64(sealed) })).plaintext, b64(plaintext));
  assert.ok((await call({ op: 'hpke-open', info: b64(E('wrong')), aad: b64(aad), enc: b64(new Uint8Array(sender.enc)), ciphertext: b64(sealed) })).error);
  const goSealed = await call({ op: 'hpke-seal', info: b64(info), aad: b64(aad), plaintext: b64(plaintext) });
  const recipient = await hpke.createRecipientContext({ recipientKey: privateHPKE, enc: dec(goSealed.enc), info });
  assert.deepEqual(new Uint8Array(await recipient.open(dec(goSealed.ciphertext), aad)), plaintext);
  console.log('PASS Go/browser HPKE X25519/HKDF-SHA256/ChaCha20-Poly1305 both directions; info tamper rejected');
} finally {
  child.stdin.end();
  const [code] = await exit;
  assert.equal(code, 0, 'Go fixture exited unsuccessfully');
}
