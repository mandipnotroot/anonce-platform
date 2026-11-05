<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Protocol contracts

Normative formats; implementation and verification status are separate. HTTP fields and endpoints are defined in [openapi.yaml](openapi.yaml); system trust boundaries are in [architecture.md](architecture.md).

## Encoding

| Value                                                   | Encoding                                                                          |
| ------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Binary JSON fields                                      | Canonical unpadded base64url                                                      |
| Random object/account/review IDs                        | 16 bytes                                                                          |
| Deployment IDs, hashes, challenge nonces, token serials | 32 bytes                                                                          |
| Revisions, credential epochs, timestamps                | Decimal JSON strings; unsigned U64BE in transcripts. Timestamps use Unix seconds. |
| Raw Ed25519/X25519 public keys                          | 32 bytes                                                                          |
| Ed25519 signatures                                      | 64 bytes                                                                          |
| Certificates / RSA public keys                          | DER X.509 / DER SubjectPublicKeyInfo                                              |
| ChaCha20-Poly1305 nonces / tags                         | 12 bytes / 16 bytes                                                               |

Reject invalid lengths, noncanonical encodings, duplicate or unknown JSON fields, and trailing JSON values. Trailing JSON whitespace is allowed.

Define `E(label,...fields)` as `ASCII("ANONCE") || 0x01 || U16BE(label byte length) || ASCII(label) || U16BE(field count) || concat(U32BE(field length) || field)`. Fields are bytes; textual fields use UTF-8, integers use U64BE. SHA-256 is the application hash; HKDF is HKDF-SHA-256 with 32-byte output unless stated otherwise.

## Challenges and credentials

Authenticated mutation envelope: `{payload: base64url(exact JSON bytes), proof: {challenge_id,password_sig?,recovery_sig?,membership_sig?,new_password_sig?,new_recovery_sig?}}`. `payload_hash = SHA256(exact payload bytes)`; never reserialize before hashing. Sign:

`E('challenge',deployment_id,UTF8(origin),account_id,challenge_id,UTF8(action),U64(credential_epoch),payload_hash,nonce,U64(expires_at))`.

| Challenge rule  | Behavior                                                                    |
| --------------- | --------------------------------------------------------------------------- |
| Origin          | Browser's known configured origin, not an untrusted response value          |
| Lifetime        | Five minutes; one-use                                                       |
| Session binding | Required except for `register`, `login-password`, and `login-recovery`      |
| Registration    | Epoch 0; verifies proposed public keys                                      |
| Mutation proof  | Membership by default; credential actions also require API-specified proofs |

- Password KDF parameters: `{v:19,salt,memory_kib:65536,iterations:3,parallelism:1,length:32}`, salt 16 bytes.
- `P = Argon2id(password,salt,v=19,m=65536 KiB,t=3,p=1,len=32)`.
- `S = SHA256(E('password-kdf',deployment,account))`.
- Authentication seed: `HKDF(P,S,E('password-auth'),32)`; wrapping key uses info `E('password-wrap')`.

- Recovery uses exactly 12 English BIP-39 words with standard checksum, decoded to securely generated 16-byte entropy, not the BIP-39 passphrase seed.
- `T = SHA256(E('recovery-kdf',deployment,account,recovery_salt))`, recovery salt 32 bytes.
- Authentication seed: `HKDF(entropy,T,E('recovery-auth'),32)`; wrapping key uses info `E('recovery-wrap')`.
- Authentication seeds instantiate Ed25519; only public keys reach the server.

## Vault

Generate random 32-byte master key `V`; wrap it independently for password and recovery. **All wrapping and vault-object encryption uses ChaCha20-Poly1305, never AES**, with fresh random 12-byte nonces. Ciphertext includes the authentication tag.

| Wrapper field or derivation | Value                                                                        |
| --------------------------- | ---------------------------------------------------------------------------- |
| JSON                        | `{v:1,id,nonce,ciphertext}`, id 16 bytes                                     |
| AAD                         | `E('vault-wrap',deployment,account,UTF8(kind),wrapper_id,metadata_hash)`     |
| Kind                        | `password` or `recovery`                                                     |
| Password metadata hash      | `SHA256(E('password-params',salt,U64(19),U64(65536),U64(3),U64(1),U64(32)))` |
| Recovery metadata hash      | `SHA256(E('recovery-params',recovery_salt))`                                 |

| Vault object field or operation | Value                                                                                                                                                 |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| JSON                            | `{v:1,id,revision,nonce,ciphertext}`                                                                                                                  |
| Key                             | `HKDF(V,SHA256(E('vault-kdf',deployment,account,object_id)),E('vault-object'),32)`                                                                    |
| AAD                             | `E('vault-object',deployment,account,object_id,U64(revision))`                                                                                        |
| CAS                             | `expected_revision="0"` creates revision `"1"`; updates increment by one                                                                              |
| Contents                        | Membership seed, review content and recipient keys, pending issuance state, tokens, and exact pending submissions; plaintext never reaches the server |

- Same-device automatic unlock persists a nonextractable HKDF CryptoKey in IndexedDB and derives an in-memory ChaCha cache key for encrypted V/private state.
- This trusted-origin capability is not password-gated defense against malicious served code, XSS, or profile backups.
- Logout deletes capability/cache and guards pending writes, but cannot revoke copies.
- Password/phrase changes preserve V/data through wrapping; they do not repair old snapshot compromise.

## Reviews and blind authorizations

### Encrypted review content

Before creating a draft, the browser generates a random 16-byte review ID,
an independent random 32-byte content key, and an X25519 recipient key pair.
The content key does not decrypt responses. Content plaintext contains exactly
`{v:1,title,description,questions}`. Each question contains exactly
`{id,type,label,required,choices:[{id,label}]}`, with type `text|single|multiple`.
Question IDs, types, required flags, choices, and array structure are encrypted too.

Encrypt UTF-8 JSON with the established ChaCha20-Poly1305 implementation using
the content key and a fresh random 12-byte nonce. AAD is
`E('review-content',deployment_id,org_id,review_id,U64(1))`.
The envelope contains exactly `{v:1,nonce,ciphertext}`; ciphertext includes the
16-byte tag. Plaintext is at most 32768 bytes; ciphertext is 16–32784 bytes.

The creator's vault object uses the review ID as its object ID. Its plaintext
contains exactly
`{v:1,kind:'review-keys',review_id,content_key,recipient_private_key}`.
Both keys encode 32 bytes independently. Draft creation atomically stores the
encrypted review and encrypted vault object. Updates reuse keys with fresh
content nonces. Publication reuses the exact saved content envelope.

Browser content validation requires a 1–300-byte title, a description of at most
10000 bytes, and 0–100 draft questions. Publication and responding require at
least one question. Question IDs are unique and 1–100 bytes; labels are
1–2000 bytes. `required` is boolean. Text questions have no choices; single
and multiple choice questions have 2–100 choices. Choice IDs are unique within
their question and 1–100 bytes; choice labels are 1–1000 bytes. These bounds
measure UTF-8 bytes, and the aggregate plaintext bound also applies.
The server can validate envelope framing, not question semantics.

### Descriptor v3

Descriptor is base64url exact JSON bytes, at most 65536 decoded bytes, containing exactly:

`{v:3,deployment_id,review_id,org_id,reviewer_membership_id,reviewer_certificate,encrypted_content,recipient_public_key,issuer_key_id,issuer_public_key}`.

- `encrypted_content`: the saved content envelope. Descriptors v1 and v2 are not supported.
- Quotas, schedules, and account IDs are not published in the descriptor.
- Creator signature: membership Ed25519 over `E('review-descriptor',descriptor_bytes)`.
- Descriptor hash: SHA256 of exact descriptor bytes. Published metadata is immutable.

Verify the outer descriptor before opening its content. Browser answer
encryption/decryption requires successfully authenticated, validated content;
plaintext is not appended to the signed descriptor. Publication compares the
stored encrypted envelope, membership, and issuer metadata under revision CAS. Keys
already exist in the vault; publication does not write another vault object.

The server retains `max_responses` and opening/closing times in plaintext to
enforce per-member authorization quotas and acceptance windows atomically.
These settings are not E2EE. Removing their public descriptor copies reduces
disclosure without changing server enforcement. No encrypted duplicate is used
to imply confidentiality from the server.

Member review responses contain `id`, `org_id`, `is_creator`, `encrypted_content`,
`state`, `issuer_public_key`, and `issuer_key_id`. Only the creator also receives
`revision`, `max_responses`, `opens_at`, `closes_at`, `issued_count`, and
`accepted_count`. Creator association stays internal; responses do not expose
creator account IDs, duplicate reviewer account IDs, or membership IDs.
Published descriptors and signatures are fetched from the public endpoint,
not repeated in member responses. `is_creator` is computed from the authenticated
session, not supplied by the browser.

### Invitation links

Respondent links have this exact shape:
`https://<origin>/#/respond/<review_id>?v=1&k=<content_key>`.
The review ID and key are canonical unpadded base64url encodings of 16 and
32 bytes respectively. Require exactly one `v=1` and one `k`, with no unknown
parameters or extra path components. The query-like portion is inside the URL
fragment, not the HTTP query. Preserve the complete fragment through sign-in,
registration, and recovery; never put its key in requests, challenges, or logs.

Anyone holding the link can read the review content. The link grants neither
membership nor response authorization and cannot decrypt submitted answers.
Creator vault keys restore drafts and links after sign-in. Other organization
members see only locked review metadata unless given a link. Missing keys fail
closed rather than producing empty questions. There is no content-key rotation
or reviewer key-distribution mechanism in this contract. Deleting a draft removes
its creator vault object, not copies, historical snapshots, or operation caches.

| Verification                 | Scope and limit                                                                                                        |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Browser                      | Descriptor signature, certificate signatures/profile, deployment, organization, and certified membership key           |
| Creator association          | Server authorizes publication using its internal creator/membership records; public descriptor contains no account ID  |
| Historical decoding          | Ignores current certificate validity while retaining signature/profile checks, preserving decryption after expiry      |
| Backend publication/issuance | Enforces current validity and membership revocation                                                                    |
| Unproven history             | Browser checks cannot establish signing time, historical approval, or non-revocation; no trusted timestamp is provided |

| Blind authorization parameter     | Value                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------ |
| Dedicated review RSA key          | 3072 bits, exponent 65537                                                      |
| RFC 9474 variant                  | **RSABSSA-SHA384-PSS-Randomized**                                              |
| Hash / MGF / salt                 | SHA-384 / MGF1-SHA384 / 48 bytes; necessary exception to application SHA-256   |
| Authorization message             | `E('authorization',deployment,review_id,descriptor_hash,issuer_key_id,serial)` |
| Serial / RFC preparation prefix   | Random 32 bytes each                                                           |
| RSA signatures / blinded messages | 384 bytes                                                                      |

Use established libraries, not homegrown primitives.

Browser encrypts pending `{request_id,serial,descriptor_hash,prepared_message,blinded_message,inverse}` before requesting issuance. The pending vault write and server quota/signature cache commit together. Preserve exact prepared message, unblinding state and later exact submission for retries.

- The authenticated pending object also includes the encrypted response.
- Pad serialized UTF-8 JSON plaintext with ASCII spaces to exactly 524288 bytes before vault encryption; reject larger plaintext.
- Ciphertext is 524304 bytes including the authentication tag. JSON readers accept the trailing whitespace.
- Reuse the exact encrypted object on issuance retries.
- Padding prevents direct answer-length linkage for new issuance objects, not previously stored objects, timing, or other metadata.

## Response encryption and receipts

RFC 9180 HPKE base mode: X25519/HKDF-SHA256/ChaCha20-Poly1305, suite `0x0020/0x0001/0x0003`. Info is `E('response-hpke',deployment,review_id,descriptor_hash)`; AAD is `E('response-aad',deployment,review_id,descriptor_hash)`. Plaintext JSON: `{v:1,review_id,descriptor_hash,answers:{question_id:string|array}}`. Validate answers against the authenticated decrypted descriptor content in the browser; server cannot inspect plaintext.

| Size boundary                           |  Bytes | Meaning                                                      |
| --------------------------------------- | -----: | ------------------------------------------------------------ |
| Authenticated pending-object plaintext  | 524288 | Fixed space-padded JSON before vault encryption              |
| Authenticated pending-object ciphertext | 524304 | Padded plaintext plus authentication tag                     |
| Anonymous response ciphertext maximum   | 262144 | HPKE ciphertext including tag, excluding base64url expansion |

These are different objects and limits. Before issuance, the browser preflights the exact response plaintext UTF-8 length plus the 16-byte tag; the server rejects oversized response ciphertext.

Submission: `{review_id,issuer_key_id,prepared_message,signature,enc,ciphertext}`; `enc` is 32 bytes. Verify the prepared authorization and extract serial. `token_hash = SHA256(E('token',review_id,issuer_key_id,serial))`. `submission_hash = SHA256(E('submission',review_id,issuer_key_id,prepared_message,signature,enc,ciphertext))`.

The token and full submission hashes remain internal replay/idempotency values;
neither appears in exported receipts. Define
`response_hash = SHA256(E('accepted-response-v2',deployment,review_id,descriptor_hash,issuer_key_id,enc,ciphertext))`,
where `descriptor_hash` is SHA-256 of the exact verified descriptor bytes.

Receipt contains exactly
`{v:2,deployment_id,receipt_id,review_id,descriptor_hash,issuer_key_id,response_hash,accepted_at,receipt_key_id,signature}`.
Ed25519 signature transcript:
`E('receipt-v2',deployment,receipt_id,review_id,descriptor_hash,issuer_key_id,response_hash,U64(accepted_at),receipt_key_id)`.
Exact spend retries return the original receipt; changed submissions for a spent
token conflict. Acceptance and receipt persistence are one transaction. Receipt
v1 is not supported; this unreleased project provides no upgrade migration.

The portable public trust document contains exactly
`{v:1,deployment_id,receipt_key_id,receipt_keys:[{receipt_key_id,receipt_public_key}]}`.
Each key ID is SHA-256 of its raw 32-byte Ed25519 public key. Require unique IDs
and an entry for the current `receipt_key_id`. Historical keys must be explicitly
trusted by the operator; receipt fields cannot introduce verification keys.
Public configuration v2 publishes this keyring alongside the other deployment
configuration. Obtain and retain trust information through a trusted channel;
an arbitrary key bundled with a receipt does not establish authenticity.

Signature-only portable verification authenticates the server's acceptance
statement, not a match to an independently held submission. Submission and
reviewer flows additionally require the expected deployment, review, exact
descriptor hash, issuer, and independently computed response hash. Reviewers
verify the receipt and item ID before decryption and use only the signed
acceptance time. A failed receipt check makes that record invalid without
blocking other records. Receipt timestamps are server assertions, not trusted
timestamps. Receipts do not prove answer correctness, continued storage,
completeness of results, or anonymity.

### Acceptance sequence

1. Check the token spend. An identical submission hash returns the original receipt, including after review closure; a different hash conflicts.
2. For an unspent token, validate review eligibility, authorization signature, and ciphertext framing.
3. Atomically persist the spend, ciphertext, and signed receipt, and increment `accepted_count` before replying.

Issuance, validation rejection, rollback, exact retries, and conflicting replays do not increment `accepted_count`. This counts committed encrypted records, not proven-valid plaintext: the server cannot decrypt answers. Reviewers isolate unreadable or invalid responses, display their status, and report them in exports without blocking valid records.

## Browser implementation references

- [Browser cryptography](../web/crypto.js)
- [Interoperability vectors and tests](../web/crypto.test.js)
