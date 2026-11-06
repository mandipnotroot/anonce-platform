<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Member content-key delivery contract

Status: implementation contract, not proof of passed tests. Follow the
[verification requirements](../CONTRIBUTING.md#verification-and-release-gates)
and record run results in pull requests or CI artifacts.
This replaces secret question-key links, not creator-only answer decryption.

## Access policy

Publication snapshots every approved organization membership, including the
creator and all roles. Later approvals receive no historical content keys.
Published content stays immutable. Revoked members cannot fetch envelopes, but
cannot unlearn keys or content already obtained. No compatibility path for old
registrations or secret links is provided in this unreleased application.
Changing the initial schema does not upgrade an initialized database. Operators
must explicitly approve any fresh-database deployment; never delete existing data
automatically.

## Account keys

Generate an independent X25519 account encryption pair in the browser. Keep
Ed25519 membership keys separate. Registration requires canonical base64url
`encryption_public_key` (32 bytes) and `encryption_key_signature` (64 bytes).
The membership signing key signs the existing length-prefixed transcript:

```text
E('member-encryption-key', deployment_id, account_id,
  membership_public_key, encryption_public_key, U64(1))
```

Registration challenge signatures cover these additional fields. Server verifies
the binding, lengths, canonical encoding, and usable X25519 input through an
established implementation. Keys are immutable. `encryption_key_id` is SHA-256
of the raw encryption public key.

Membership vault plaintext becomes:

```json
{
  "v": 1,
  "kind": "membership",
  "seed": "<base64url membership seed, 32 bytes>",
  "encryption_private_key": "<base64url X25519 private key, 32 bytes>"
}
```

`GET /api/member/vault` additionally returns the registered public key and
binding signature. Unlock recomputes both public keys and verifies the binding
and restored private key against the registered key; mismatches fail closed.
Encrypted device cache includes the new private key. Logout clears memory.
Creator review-key vault objects remain unchanged and are never distributed.

## Recipient directory

`GET /api/member/reviews/{id}/content-recipients?after=<membership_id>` requires
a full session, approved membership, and review creator authorization. It returns
pages of 100 approved memberships with `items` and `next`:

```json
{
  "items": [
    {
      "membership_id": "<16 bytes>",
      "account_id": "<16 bytes>",
      "certificate": "<DER certificate>",
      "encryption_public_key": "<32 bytes>",
      "encryption_key_signature": "<64 bytes>"
    }
  ],
  "next": null
}
```

Use bytewise canonical membership-ID string ordering and last-returned-ID
cursors. Fetch every page; reject duplicate IDs and repeated cursors. Do not
reuse the manager-only, capped organization member list.

Browser verifies the certificate CA signature/profile, deployment, organization,
membership ID, and encryption-key binding using its Ed25519 public key. Bind the
directory account ID too. Historical certificate validation must not silently
exclude approved members because of expiry; creator publication still requires
a currently valid signing certificate. Do not expose this directory publicly.

## HPKE envelopes

Use existing RFC 9180 base-mode X25519 / HKDF-SHA256 / ChaCha20-Poly1305
libraries (suite `0x0020 / 0x0001 / 0x0003`). Independently seal only the raw
32-byte content key for each recipient. Define `D = SHA256(exact descriptor
bytes)`, `M = membership ID`, and `K = encryption_key_id`:

```text
info = E('review-content-key-hpke', deployment_id, org_id, review_id, D, M, K)
aad  = E('review-content-key-aad',  deployment_id, org_id, review_id, D, M, K)
```

Envelope has exactly `v: 1`, `membership_id` (16 bytes), `encryption_key_id`
(32 bytes), `enc` (32 bytes), and `ciphertext` (48 bytes). Binary fields use
canonical base64url. Accept a recovered key only after verifying the descriptor
signature and successfully decrypting its authenticated content. No separate
envelope signature is required. Descriptor v3 and response HPKE stay unchanged.

## Atomic publication and storage

Signed `review-publish` payload gains `content_key_envelopes: [envelope, ...]`.
Under the existing organization lock and review transaction, validate creator,
revision, descriptor signature, and saved content. Require exactly one envelope
for every current approved membership, including creator, with matching key ID.
Reject missing, duplicate, extra, pending, revoked, or foreign recipients.
Persist all envelopes, publication, public descriptor, and idempotent result
atomically. Roster mismatch is `409 recipient_set_conflict`.

On roster conflict, browser refetches and rebuilds envelopes with a new request
ID. Uncertain-network retries reuse the exact payload and request ID. Changed
payload with reused ID remains `request_conflict`. Keep the 1536*1024-byte
decoded payload limit; reject excess explicitly, never truncate.

Initial account schema gains required `encryption_public` (32 bytes) and
`encryption_key_signature` (64 bytes). Member-only `review_content_keys` stores
`review_id`, `membership_id`, `encryption_key_id`, `enc`, and `ciphertext` with
length checks, foreign keys, and primary key `(review_id, membership_id)`.
Anonymous database role has no access.

Authenticated review get/list views return `content_key_envelope`: only caller's
envelope, or `null` for drafts and later-approved members. Check current approved
membership. Creator uses existing vault keys; others open their own envelope.
Missing or corrupt keys affect only that review, not the entire dashboard.

## Application and UI interface

Ordinary navigation is `/#/respond/<review_id>`. Reject old secret query forms.
`prepareResponse({reviewId, answers})` obtains the key internally using authenticated
review access. Remove secret-link APIs and UI rather than retaining a fallback.

Review view models retain `contentState` (`locked` or existing unlocked state)
and gain boolean `completedOnThisBrowser`. Derive completion only from encrypted
local pending records with verified acceptance receipts. Do not infer completion
from issuance, quota exhaustion, or counters. Do not upload completion state.
Use “Completed on this browser” and “No completion recorded here”; keep response
actions available when more responses are allowed. Browser clearing or another
browser can lose completion visibility. No new completion store/API is needed.

## Limits and required evidence

Signed bindings prevent encryption-key substitution under an unchanged identity;
they do not defeat malicious replacement of both identity and CA certificate.
Served JavaScript remains trusted. Envelopes reveal access metadata, not named
response completion. Network/timing correlation remains possible. Server cannot
prove an envelope contains the right key.

Verify registration binding/input failures; vault mismatch; directory pagination
beyond 100; exact recipient coverage and concurrent roster changes; atomic
rollback and exact/changed retries; HPKE tampering and transplantation; creator-only
response decryption; later-approved/revoked access; local receipt-based completion;
and credential-free anonymous requests. Record commands, results, and unverified
database/browser boundaries without claiming production readiness or audit.
