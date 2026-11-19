<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Member content-key delivery contract

- Status: implementation contract, not proof of passed tests.

## Access policy

- Publication start snapshots every approved organization membership, including the creator and all roles.
- Later approvals receive no historical content keys.
- Published content stays immutable.
- Revoked members cannot fetch envelopes, but cannot unlearn keys or content already obtained.
- Changing the initial schema does not upgrade an initialized database.
- Operators must explicitly approve any fresh-database deployment; never delete existing data automatically.

## Account keys

- Generate an independent X25519 account encryption pair in the browser.
- Keep Ed25519 membership keys separate.
- Registration requires canonical base64url `encryption_public_key` (32 bytes) and `encryption_key_signature` (64 bytes).
- The membership signing key signs the length-prefixed transcript:

```text
E('member-encryption-key', deployment_id, account_id,
  membership_public_key, encryption_public_key, U64(1))
```

- Registration challenge signatures cover these additional fields.
- Server verifies the binding, lengths, canonical encoding, and usable X25519 input through an established implementation.
- Keys are immutable. `encryption_key_id` is SHA-256 of the raw encryption public key.

Membership vault plaintext:

```json
{
  "v": 1,
  "kind": "membership",
  "seed": "<base64url membership seed, 32 bytes>",
  "encryption_private_key": "<base64url X25519 private key, 32 bytes>"
}
```

- `GET /api/member/vault` returns the registered public key and binding signature.
- Unlock recomputes both public keys and verifies the binding and restored private key against the registered key; mismatches fail closed.
- Encrypted device cache includes the account encryption private key.
- Logout clears memory.
- Creator review-key vault objects are never distributed.

## Recipient directory

- `GET /api/member/reviews/{id}/content-recipients?publication_id=<id>&after=<membership_id>` requires a full session, approved membership, and review creator authorization.
- It returns pages of at most 100 frozen snapshot recipients with `items` and `next`:

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

- Use bytewise canonical membership-ID string ordering and last-returned-ID cursors.
- Process and upload one page at a time; reject duplicate or unordered IDs and repeated cursors.
- Do not reuse the manager-only, capped organization member list.

- Browser verifies the certificate CA signature/profile, deployment, organization, membership ID, and encryption-key binding using its Ed25519 public key.
- Bind the directory account ID too.
- Historical certificate validation must not silently exclude approved members because of expiry; creator publication still requires a currently valid signing certificate.
- Do not expose this directory publicly.

## HPKE envelopes

- Use existing RFC 9180 base-mode X25519 / HKDF-SHA256 / ChaCha20-Poly1305 libraries (suite `0x0020 / 0x0001 / 0x0003`).
- Independently seal only the raw 32-byte content key for each recipient.
- Define `D = SHA256(exact descriptor bytes)`, `M = membership ID`, and `K = encryption_key_id`:

```text
info = E('review-content-key-hpke', deployment_id, org_id, review_id, D, M, K)
aad  = E('review-content-key-aad',  deployment_id, org_id, review_id, D, M, K)
```

- Envelope has exactly `v: 1`, `membership_id` (16 bytes), `encryption_key_id` (32 bytes), `enc` (32 bytes), and `ciphertext` (48 bytes).
- Binary fields use canonical base64url.
- Accept a recovered key only after verifying the descriptor signature and successfully decrypting its authenticated content.
- No separate envelope signature is required.

## Atomic publication and storage

1. Start with signed `review-publication-start` at `POST /api/member/reviews/{id}/publication`: `{request_id,expected_revision,descriptor,descriptor_signature}`.
   Under the organization lock followed by the review lock, validate creator, revision, descriptor signature, and saved content; freeze recipient membership and key bindings.
2. Page recipients using the returned `publication_id`. Snapshots contain at most 100000 recipients and expire after 24 hours; only one snapshot per review is active.
3. Upload signed `review-publication-envelopes` at `POST /api/member/reviews/{id}/publication/envelopes`: `{request_id,publication_id,content_key_envelopes}` with 1–100 envelopes.
   Validate each recipient and key ID against the snapshot; reject duplicates, foreign recipients, and conflicting retries atomically.
4. Finalize with signed `review-publish` at `POST /api/member/reviews/{id}/publish`: `{request_id,expected_revision,publication_id}`.
   Require complete snapshot coverage, current creator authorization, and matching draft revision. Make envelopes, publication, public descriptor, and idempotent result available atomically.

- Approvals after snapshot creation do not change its recipients. Current revocation checks still restrict envelope retrieval.
- Staging never makes a draft's envelopes available through member review views.
- Uncertain-network retries reuse the exact current operation payload and request ID; changed payload with reused ID remains `request_conflict`.
- Browser retains only the current page's envelopes and progress, not the complete directory or publication payload.
- HTTP 429 retains progress for a later retry. Publication remains subject to
  member/challenge rate limits; batching does not bypass them.
- Losing the encrypted browser progress cache does not cancel the active snapshot.
  A new start must wait for expiry or a changed draft revision; cross-device
  resume and explicit cancellation are not implemented.
- Retain the 1536*1024-byte decoded payload limit and the tighter upload item limit; reject excess explicitly, never truncate.

- Account schema requires `encryption_public` (32 bytes) and `encryption_key_signature` (64 bytes).
- Member-only `review_content_keys` stores `review_id`, `membership_id`, `encryption_key_id`, `enc`, and `ciphertext` with length checks, foreign keys, and primary key `(review_id, membership_id)`.
- Envelope uploads use bounded bulk writes rather than one database round trip per recipient.
- Anonymous database role has no access.

- Authenticated review get/list views return `content_key_envelope`: only caller's envelope, or `null` for drafts and later-approved members.
- Check current approved membership.
- Creator uses existing vault keys; others open their own envelope.
- Missing or corrupt keys affect only that review, not the entire dashboard.

## Application and UI interface

- Ordinary navigation is `/#/respond/<review_id>`.
- Reject old secret query forms. `prepareResponse({reviewId, answers})` obtains the key internally using authenticated review access.

- Review view models include `contentState` (`locked` or unlocked state)
  and boolean `completedOnThisBrowser`.
- Derive completion only from encrypted local pending records with verified acceptance receipts.
- Do not infer completion from issuance, quota exhaustion, or counters.
- Do not upload completion state.
- Use “Completed on this browser” and “No completion recorded here”; keep response actions available when more responses are allowed.
- Browser clearing or another browser can lose completion visibility.

## Limits and required evidence

- Signed bindings prevent encryption-key substitution under an unchanged identity;
  they do not defeat malicious replacement of both identity and CA certificate.
- Served JavaScript remains trusted.
- Envelopes reveal access metadata, not named response completion.
- Network/timing correlation remains possible.
- Server cannot prove an envelope contains the right key.

Follow the [verification requirements](../CONTRIBUTING.md#verification-and-release-gates)
with these contract-specific cases:

- Registration binding/input failures and vault mismatch.
- Directory pagination beyond 100.
- Exact recipient coverage and concurrent roster changes.
- Atomic rollback and exact/changed retries.
- HPKE tampering and transplantation.
- Creator-only response decryption.
- Later-approved/revoked access.
- Local receipt-based completion.
- Credential-free anonymous requests.

## Publication scale benchmarks

- See [publication performance](publication-performance.md) for the live-browser
  benchmark path, deployment isolation, and interpretation limits.
- Run `npm ci`, then `node scripts/publication-benchmark.mjs --run` for synthetic
  1000, 10000, and 100000-recipient certificate verification and HPKE measurements.
- The script uses the actual browser-compatible crypto module in Node, bounded
  batches, and valid synthetic recipient identities. It reports elapsed time,
  payload sizes, memory observations, and estimated request counts.
- This is not a live browser or end-to-end publication benchmark. Fixture
  generation is reported separately; request estimates exclude real network
  latency and throttling. Do not treat component timings as deployment capacity.
- Use only disposable synthetic databases for PostgreSQL benchmarks. Database
  fixtures and role requirements follow the
  [verification gates](../CONTRIBUTING.md#verification-and-release-gates).
- With `ANONCE_TEST_DATABASE_URL` pointing to such a database, run
  `go test ./internal/server -run '^$' -bench '^BenchmarkPublicationStorage$' -benchtime=1x -benchmem`.
  This measures snapshot freezing, bounded recipient queries, production envelope
  validation/storage, and promotion at all three sizes. It excludes fixture
  setup, HTTP authentication, browser crypto, throttling, and commit durability;
  each synthetic run rolls back its transaction.
- Record execution results with machine/resource limits in review or CI
  artifacts, not as checked-in execution diaries.
