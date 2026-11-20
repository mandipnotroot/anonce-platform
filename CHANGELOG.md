<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Changelog

- Notable changes follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
- Future releases will follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- Opt-in live-browser publication benchmarks with isolated HTTPS/PostgreSQL
  fixtures, bounded traffic checks, and performance interpretation guidance.
- Go/PostgreSQL backend and browser flows for encrypted vaults, recovery,
  organizations, review publication, blind authorizations, anonymous encrypted
  responses, and creator-only decryption/export.
- Browser-side encryption of review titles, descriptions, questions, and drafts.
  Publication delivers content keys to members approved at that time.
- Organization invite links, direct membership by registered email, multiple
  admins, and owner-only admin appointment controls.
- Bundled browser cryptography, versioned protocol/API contracts, and shared
  Go/browser cryptographic test vectors.
- Transactional quota, replay, and idempotency controls with separate member
  and anonymous database roles.
- Docker Compose deployment with Caddy HTTPS, a nonroot application runtime,
  configurable database volumes, and backup guidance.
- Disposable PostgreSQL and container CI checks, browser tests, and weekly
  Dependabot checks with manually reviewed update PRs.
- Deployment-configured corresponding-source links.

### Changed

- Group container build and Caddy configuration files under `docker/`, keeping
  the deployment Compose file at the repository root.
- Use one Compose file and Caddyfile for local and public deployments, with
  automatic certificate selection by hostname instead of local-only overrides.
- Remove unused certificate-formatting and nullable-comparison helpers.
- Clarify that shared API rate-limit pools do not provide per-client fairness
  or denial-of-service protection.
- Combine review setup and question building on one page before creating a draft.
- Remove redundant interface instructions while retaining actionable validation
  errors and security warnings.
- Use version-supported modern Go idioms for error matching, path splitting,
  fixed-count loops, and test contexts without changing protocol formats.
- Freeze publication recipients before paged key encryption and bounded envelope
  uploads; finalize complete snapshots atomically instead of sending one full-roster payload.
- Use one current schema with transactional, version-checked initialization.
  Initialization requires an empty database or the current schema; automatic
  upgrades and data transfer are not supported.
- Deliver review-content keys through per-member HPKE envelopes at publication.
  Later-approved members do not receive historical keys; answer decryption stays
  creator-only.
- Use normalized email addresses for registration, sign-in, and recovery.
  Organization owners and admins can see member emails; addresses are not
  mailbox-verified.
- Minimize descriptor metadata and restrict review settings and activity counters
  to creators. Operational metadata is not end-to-end encrypted.
- Bind receipt v2 to the encrypted response, deployment, review, descriptor, and
  issuer, with an operator-approved public signing-key ring.
- Improve responsive layouts, keyboard focus, loading feedback, and action
  notifications across account, organization, and review flows.
- Reuse a fresh vault download within each review-list request and load overview
  reviews and pending responses concurrently.
- Gate proxy startup on application readiness and bound graceful shutdown.

### Fixed

- Ignore stale session and workspace requests after logout or organization changes.
- Enforce review creation roles under the organization lock, including retries
  after demotion.
- Preserve committed credential changes when automatic sign-in fails, and warn
  before discarding unacknowledged recovery words.
- Verify receipt context before cached acceptance or result decryption and load
  public verification keys on direct visits.
- Handle response timestamps and unreadable encrypted responses in results/exports.
- Preserve issuance retry bytes restored from PostgreSQL JSONB and count only
  committed responses.

### Removed

- Standalone receipt verification, receipt PNG/QR downloads and imports, and
  public signing-key import/export controls. Signed receipts remain internal to
  submission confirmation, retries, and reviewer validation.

### Security

- Build and test with Go 1.27.4, including the standard-library fix for
  CVE-2026-97054.
- Use the upstream PostgreSQL 18.7 Alpine image with refreshed bundled libraries;
  unresolved upstream component advisories remain documented in the security review.
- Refresh the application image's OpenSSL libraries to Alpine's fixed
  `3.5.9-r1` packages without modifying third-party service images.
- Bind in-flight registration, review mutations, encrypted response persistence,
  and decrypted review/result operations to their originating browser session;
  discard stale renders, exports, and submission feedback after logout or navigation.
- Separate authenticated-member request capacity from public and anonymous traffic
  without adding identifying tracking to anonymous endpoints.
- Reject unsafe server master-key files and bound key-material reads.
- Pad authenticated issuance pending objects to a fixed plaintext size to prevent
  direct response-length linkage for new objects. Previously retained objects,
  timing correlation, and other [trust limitations](SECURITY.md) remain out of scope.
- Use inert HTML parsing in responsive checks.
- Raise review limits to 500 questions, 512 KiB of plaintext, and 64 KiB
  descriptions; expose bounded operator-configurable limits to browser validation.
- Increase descriptor and response ceilings to 768 KiB and 512 KiB, with
  consistent 1 MiB pending padding and anonymous request bounds.
- Pin compact pending recovery records to public descriptor hashes; remote
  recovery requires the immutable descriptor to remain available. Schema version
  3 requires a fresh pre-release database; existing data is not migrated.
