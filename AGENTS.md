<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Repository guidance

This guidance applies to all contributors and automated coding tools working in
this repository. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for setup and the
contribution process. Nested guidance may add requirements for its directory.

## Mandatory references
- Conventional Commits 1.0.0: https://www.conventionalcommits.org/en/v1.0.0/
  Use `type(scope): description`; mark breaking changes with `!` or a
  `BREAKING CHANGE:` footer. Use `feat` for features and `fix` for bug fixes.
- Keep a Changelog 1.1.0: https://keepachangelog.com/en/1.1.0/
  Maintain human-curated `CHANGELOG.md`, newest first, with `Unreleased` and
  Added/Changed/Deprecated/Removed/Fixed/Security as applicable. Date releases
  YYYY-MM-DD, link versions, and state the versioning policy; do not dump commits.
- JetBrains modern Go: https://github.com/JetBrains/go-modern-guidelines
  Read its applicable feature guidance. Detect the supported version from
  `go.mod`; use modern idioms only when supported by that version. Before a
  module exists, agree on a supported version; never assume the newest features.

## Contribution workflow
- Use your own contributor identity and Git configuration. Never attribute a
  contribution to another person or require a maintainer's author identity.
- Original sources must carry `SPDX-License-Identifier: AGPL-3.0-only` in an
  appropriate comment. Preserve third-party licenses and attribution.
- Preserve existing work; no destructive resets, force pushes, or unsolicited
  commits. Use Conventional Commits when commits are authorized.
- Agree shared API, schema, and cryptographic format contracts before parallel
  writers begin. Assign disjoint file scopes; escalate cross-scope changes.
- Keep documentation and changelog accurate to implemented behavior. Record
  decisions, limitations, and unfinished work rather than implying completion.
- Keep documentation concise. Use verified latest stable dependencies and Alpine
  container images; pin versions and validate changes.
- This is unreleased: target the current stack only; do not add legacy support
  or upgrade migrations. Keep schema initialization and versioning as needed.

## Architecture
- Build a Go standard-library-first modular monolith with explicit boundaries.
  Justify external dependencies; established cryptographic libraries are required
  where the standard library lacks the prescribed primitive.
- Use PostgreSQL, parameterized SQL, and transactional migrations. Never build
  SQL by interpolating untrusted values.
- Browser stack: HTML, CSS, and vanilla JavaScript ES modules by default. A
  lightweight frontend-only framework requires a documented need and review of
  bundle size, accessibility, maintenance, and build complexity. Keep the Go
  backend independent of frontend tooling.
- Bundle established crypto dependencies locally; no runtime CDN crypto imports.
- All user flows are web-only. UI changes must consider layout, hierarchy,
  responsiveness, keyboard access, focus states, and component behavior. Use
  consistent bundled icons with visible labels or accessible names. Prefer
  purposeful controls over decorative elements. When specialist design review is
  available, use it; no particular editor, agent, or paid tool is required.

## Security and privacy invariants
- Never implement cryptographic primitives. Use established implementations of
  Argon2id, ChaCha20-Poly1305, Ed25519, X25519, RFC 9474 RSA blind signatures,
  SHA-256, HKDF-SHA-256, and X.509 with Ed25519.
- HPKE suite: X25519 / HKDF-SHA-256 / ChaCha20-Poly1305.
- RFC 9474 RSABSSA-SHA384-PSS-Randomized necessarily uses SHA-384 internally;
  application hashing and HKDF remain SHA-256.
- BIP-39 recovery is exactly 12 English words from 128 bits of entropy, with
  standard checksum and a cryptographically secure random source.
- Client-held private keys, vault master/wrapping keys, password/recovery
  material, and response plaintext remain browser-only; never send them to the
  server or log them. RSA blind issuer, membership CA, and Ed25519 receipt signing
  keys are separate server-only keys and must be protected at rest.
  Define central, versioned formats
  and encodings; share test vectors rather than inventing per-component formats.
- Do not claim anonymity against malicious served code or network/timing
  correlation. State trust assumptions and metadata limitations explicitly.
- Anonymous endpoints must omit credentials (`credentials: "omit"` in browser
  requests); server handling must not depend on identifying sessions.
- Do not store identifying submission fields or identifying submission logs.
  Review middleware, infrastructure logging, and error reporting for leakage.
- Enforce quotas, replay prevention, and idempotency atomically, including under
  concurrent requests and retries; fail closed on invalid cryptographic input.

## Verification and evidence
- Run focused checks appropriate to changed behavior, including negative cases
  and security/concurrency boundaries. Record exact commands, exit statuses,
  results, and skipped checks with reasons.
- Distinguish implemented behavior, tested evidence, and unverified assumptions.
  Never claim production readiness, audit, or security guarantees without evidence.
- Do not fabricate passing tests, deployments, review, or cryptographic assurance.
