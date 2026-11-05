<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Protocol v1 contract

Normative requirements; implementation and verification status must be reported separately.

## Encoding

Binary JSON values are canonical unpadded base64url. IDs are random 16 bytes; deployment IDs, hashes, nonces specified as 32 bytes and token serials are 32 bytes. Revisions, credential epochs and timestamps are decimal strings (timestamps are Unix seconds); encode them as unsigned U64BE in cryptographic transcripts. Raw Ed25519/X25519 public keys are 32 bytes, Ed25519 signatures 64 bytes. Certificates and RSA public keys use DER (X.509 certificate and SubjectPublicKeyInfo respectively). Reject invalid lengths, noncanonical encodings, duplicate/unknown JSON fields and trailing JSON.

Define `E(label,...fields)` as `ASCII("ANONCE") || 0x01 || U16BE(label byte length) || ASCII(label) || U16BE(field count) || concat(U32BE(field length) || field)`. Fields are bytes; textual fields use UTF-8, integers use U64BE. SHA-256 is the application hash; HKDF is HKDF-SHA-256 with 32-byte output unless stated otherwise.

## Challenges and credentials

Authenticated mutation envelope: `{payload: base64url(exact JSON bytes), proof: {challenge_id,password_sig?,recovery_sig?,membership_sig?,new_password_sig?,new_recovery_sig?}}`. `payload_hash = SHA256(exact payload bytes)`; never reserialize before hashing. Sign:

`E('challenge',deployment_id,UTF8(origin),account_id,challenge_id,UTF8(action),U64(credential_epoch),payload_hash,nonce,U64(expires_at))`.

Origin is the browser's known configured origin, not an untrusted response value. Challenges expire after five minutes, are one-use and session-bound except `register`, `login-password`, `login-recovery`. Registration uses epoch 0 and verifies proposed public keys. Default mutation proof is membership; credential actions additionally require the proofs specified in the API.

Password KDF parameters: `{v:19,salt,memory_kib:65536,iterations:3,parallelism:1,length:32}`, salt 16 bytes. `P = Argon2id(password,salt,v=19,m=65536 KiB,t=3,p=1,len=32)`; `S = SHA256(E('password-kdf',deployment,account))`. Derive authentication seed using `HKDF(P,S,E('password-auth'),32)` and wrapping key using info `E('password-wrap')`.

Recovery is exactly 12 English BIP-39 words with standard checksum, decoded to 16-byte entropy, not the BIP-39 passphrase seed. Generate entropy securely. `T = SHA256(E('recovery-kdf',deployment,account,recovery_salt))`, recovery salt 32 bytes. Derive authentication seed with `HKDF(entropy,T,E('recovery-auth'),32)` and wrapping key with info `E('recovery-wrap')`. Authentication seeds instantiate Ed25519; only public keys reach the server.

## Vault

Generate random 32-byte master key `V`; wrap it independently for password and recovery. **All wrapping and vault-object encryption uses ChaCha20-Poly1305, never AES**, with fresh random 12-byte nonces. Ciphertext includes the authentication tag.

Wrapper: `{v:1,id,nonce,ciphertext}`, id 16 bytes. AAD: `E('vault-wrap',deployment,account,UTF8(kind),wrapper_id,metadata_hash)`, kind `password` or `recovery`. Password metadata hash is `SHA256(E('password-params',salt,U64(19),U64(65536),U64(3),U64(1),U64(32)))`; recovery metadata hash is `SHA256(E('recovery-params',recovery_salt))`.

Object: `{v:1,id,revision,nonce,ciphertext}`. Key: `HKDF(V,SHA256(E('vault-kdf',deployment,account,object_id)),E('vault-object'),32)`. AAD: `E('vault-object',deployment,account,object_id,U64(revision))`. CAS `expected_revision="0"` creates revision `"1"`; updates increment by one. Objects encrypt membership seed, recipient keys, pending issuance state, tokens and exact pending submissions. Server never receives their plaintext.

Same-device automatic unlock persists a nonextractable HKDF CryptoKey in IndexedDB, deriving an in-memory ChaCha cache key for encrypted V/private state. This trusted-origin capability is not password-gated defense against malicious served code, XSS or profile backups. Logout deletes capability/cache and guards pending writes, but cannot revoke copies. Password/phrase changes preserve V/data through wrapping; they do not repair old snapshot compromise.

## Reviews and blind authorizations

Descriptor is base64url exact JSON bytes containing exactly `{v:1,deployment_id,review_id,org_id,reviewer_account_id,reviewer_membership_id,reviewer_certificate,title,description,questions,recipient_public_key,issuer_key_id,issuer_public_key,max_responses,opens_at,closes_at}`. Each question is `{id,type,label,required,choices:[{id,label}]}`, type `text|single|multiple`. `max_responses` is a positive JSON integer, per member. Creator signs `E('review-descriptor',descriptor_bytes)` with membership Ed25519; descriptor hash is SHA256 of those bytes. Published metadata is immutable.

Browser verification authenticates descriptor signature, certificate signatures/profile, deployment, organization and certified membership key. `reviewer_account_id` association is server DB-validated at publication, not independently certificate-bound. Historical decoding ignores current certificate validity while retaining signature/profile checks, preserving decryption after expiry. Backend enforces current validity and membership revocation at publication/issuance. Browser checks cannot establish signing time, historical approval or non-revocation; no trusted timestamp is provided.

Dedicated review RSA key: 3072 bits, exponent 65537. Use RFC 9474 **RSABSSA-SHA384-PSS-Randomized**: SHA-384, MGF1-SHA384, salt 48 bytes; this is the necessary exception to application SHA-256. Authorization message is `E('authorization',deployment,review_id,descriptor_hash,issuer_key_id,serial)` with random 32-byte serial. RFC preparation adds its random 32-byte prefix. RSA signatures/blinded messages are 384 bytes. Use established libraries, not homegrown primitives.

Browser encrypts pending `{request_id,serial,descriptor_hash,prepared_message,blinded_message,inverse}` before requesting issuance. The pending vault write and server quota/signature cache commit together. Preserve exact prepared message, unblinding state and later exact submission for retries.

## Response encryption and receipts

RFC 9180 HPKE base mode: X25519/HKDF-SHA256/ChaCha20-Poly1305, suite `0x0020/0x0001/0x0003`. Info is `E('response-hpke',deployment,review_id,descriptor_hash)`; AAD is `E('response-aad',deployment,review_id,descriptor_hash)`. Plaintext JSON: `{v:1,review_id,descriptor_hash,answers:{question_id:string|array}}`. Validate answers against the signed descriptor in the browser; server cannot inspect plaintext.

Ciphertext has a hard cap of 256 KiB (262144 bytes), including the 16-byte authentication tag, excluding base64url expansion. Before issuance, browser preflights the exact serialized plaintext UTF-8 byte length plus tag against this cap; server rejects oversized ciphertext.

Submission: `{review_id,issuer_key_id,prepared_message,signature,enc,ciphertext}`; `enc` is 32 bytes. Verify the prepared authorization and extract serial. `token_hash = SHA256(E('token',review_id,issuer_key_id,serial))`. `submission_hash = SHA256(E('submission',review_id,issuer_key_id,prepared_message,signature,enc,ciphertext))`.

Receipt: `{v:1,receipt_id,review_id,issuer_key_id,token_hash,submission_hash,accepted_at,receipt_key_id,signature}`. Ed25519 signature transcript: `E('receipt',deployment,receipt_id,review_id,issuer_key_id,token_hash,submission_hash,U64(accepted_at),receipt_key_id)`. Exact spend retries return the original receipt; changed submissions for a spent token conflict. Acceptance and receipt persistence are one transaction.

## Browser implementation references

Use the actual named exports in `web/crypto.js` and interoperability vectors/tests in `web/crypto.test.js` as the implementation references. The durable protocol contract does not freeze an implementation-progress snapshot or substitute export presence for verification evidence.
