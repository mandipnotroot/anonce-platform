<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Architecture contract

These are implementation requirements, not assertions that features are complete or verified. Repository: `mandipnotroot/anonce-platform`. The wire and cryptographic contracts are in [protocol.md](protocol.md) and [api.md](api.md); evidence requirements are in [verification.md](verification.md).

## Boundaries

- Go standard-library-first modular monolith, PostgreSQL, parameterized SQL and transactional migrations. Separate authentication, organization authorization, vault, reviews, issuance, anonymous submission and receipt boundaries.
- HTML/CSS/vanilla JavaScript ES modules; established crypto dependencies bundled locally, never runtime CDN imports. Keep UI, API transport and crypto imports separate. UI design belongs to `@designer`; response navigation uses `#respond/<id>`.
- Browser owns password/recovery material, authentication seeds, membership signing seed, recipient private keys, vault master key, unblinding secrets and response plaintext. Server stores public authentication keys and opaque encrypted vault objects only, never those secrets or plaintext answers.
- Server has distinct protected-at-rest membership CA, per-review RSA blind issuer and Ed25519 receipt signing keys. Do not reuse keys across these purposes.

## State and transactions

Accounts have credential epochs. Sessions bind account, scope, epoch and expiry; challenge consumption is one-use and atomic. Credential rotation uses epoch compare-and-swap and revokes existing sessions and challenges. Password changes rewrap the same vault key, preserving objects. Recovery sessions may only read/write the vault, reset credentials or log out.

Membership signing keys are separate from password/recovery authentication keys. Browser proves possession directly, without a CSR. Server issues Ed25519 X.509 leaves from its Ed25519 CA, DigitalSignature only and CA=false, with bounded validity and URI SAN `urn:anonce:deployment:<deployment>:org:<org>:member:<membership>`. Database roles, approval and revocation remain authoritative; possession of a certificate is not sufficient authorization.

Browser descriptor verification authenticates the signature, certificate profile, deployment, organization and certified membership key. The server validates `reviewer_account_id` against its membership database at publication; that account association is not independently certificate-bound. Historical browser decoding checks certificate signatures/profile but ignores current validity, so certificate expiry does not destroy decryption. Backend publication/issuance enforce current certificate validity and membership revocation. Browser verification cannot prove signing time, historical approval or absence of revocation; there is no trusted timestamp guarantee.

Same-device automatic unlock stores a nonextractable HKDF CryptoKey in IndexedDB and derives an in-memory ChaCha cache key protecting encrypted V/private state. This is a trusted-origin capability, not password-gated protection against malicious served JavaScript, XSS or profile backups. Logout deletes the capability/cache and guards against pending writes restoring them; it cannot revoke copied capabilities or state. Password and phrase changes preserve V/data by rewrapping, not by repairing compromise of old snapshots.

Review drafts are revisioned. Publication atomically freezes signed descriptor bytes and writes the encrypted recipient-key vault object. Each review has a dedicated RSA issuer. `max_responses` is a configurable positive integer, default 1, limiting authorizations **per member**, not global submissions. Do not impose any additional one-response rule.

Issuance locks member and review rows, checks active membership and review eligibility, and reserves a distinct `(review,membership,slot)` with a uniqueness constraint and `slot <= max_responses`. Every new issuance has a new `request_id`; the exact same request ID and request hash returns its cached signature. A changed request under the same ID conflicts. Save encrypted pending state and issuance quota/cache atomically. Track `issued_count` separately from aggregate `accepted_count`; neither implies the other. Revocation blocks future issuance, not already issued tokens.

Anonymous acceptance first checks for an existing spend: an identical submission hash returns the original receipt even after closure; a different hash conflicts. Otherwise validate eligibility, signature and ciphertext framing, then atomically insert spend, ciphertext and signed receipt and increment aggregate accepted count before replying. Submission storage has no member/account/session/issuance-request column or identifying logs. Never join issuance to submissions.

Only committed encrypted records contribute to `accepted_count`; issuance, rejected requests, rolled-back transactions and retries do not. The server cannot validate encrypted answer content. One unreadable record must not block other reviewer results or exports.

## Privacy boundary

Public/anonymous fetches use `credentials: "omit"`, `referrerPolicy: "no-referrer"`, and `redirect: "error"`. The proxy strips Cookie, Authorization and identifying headers on these routes; the backend rejects Cookie/Authorization rather than using them. Logs, telemetry and errors must not recreate an identifying submission trail.

Authenticated issuance pending objects use fixed 512 KiB plaintext padding before vault encryption to prevent direct response-length linkage. Older retained objects remain exposed to that linkage. Response lengths, timing and other deployment metadata remain observable. Before decrypting a reviewer result, the browser verifies a receipt binding the encrypted envelope to its deployment, review, descriptor, and issuer. This detects unsigned ciphertext replacement; it does not establish complete database integrity. A database-write attacker can delete or replay accepted records, roll back history, or remove spend state and reuse stored bearer authorizations through the honest signing endpoint. Acceptance also trusts database-held issuer context. Protect database integrity and retain independently trusted receipt public keys.

This does not hide network IP/timing correlation, tiny anonymity sets, malicious served JavaScript, operator access, issuer minting or server-CA substitution. Independent source-first security review is required, not an audit claim. Rotating a recovery phrase does not revoke compromised encrypted snapshots: full compromise repair requires a new vault key, object re-encryption and membership-key rotation.
