<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Anonce

Private, anonymous feedback for verified members. A Go 1.27/PostgreSQL 18 modular
monolith serves HTML, CSS and vanilla browser ES modules, with locally bundled
cryptographic dependencies and same-origin HTTPS.

**Development / pre-release. Not approved for sensitive production data.**
Broad tests, disposable HTTPS browser E2E, backup/restore and the final nonroot
application image smoke checks passed on 2026-11-05; see
[verification evidence](docs/verification.md). Independent focused source reviews
are not an audit. No production-readiness claim is made. This is unreleased
source; no version has been released.

## Browser workflows

Register and unlock an encrypted vault; save a 12-word recovery phrase; create
or join organizations and approve members; draft and publish signed reviews;
obtain blind response authorizations; submit encrypted answers anonymously;
verify receipts; decrypt/export received responses; change passwords or recover
on another device. These are web flows, not user-facing CLI commands.

## Security boundaries

Client private keys, password/recovery material and response plaintext remain in
the browser. Server-only membership CA, RSA issuer and receipt keys are distinct
and protected at rest. Argon2id, ChaCha20-Poly1305, Ed25519, X25519, SHA-256,
HKDF-SHA-256, X.509 Ed25519, HPKE (X25519/HKDF-SHA-256/ChaCha20-Poly1305), and
BIP-39 (exactly 12 English words, 128-bit entropy) use established implementations.
RFC 9474 RSABSSA-SHA384-PSS-Randomized necessarily uses SHA-384 internally;
application hashing/HKDF remain SHA-256.

Go uses its standard library plus CIRCL and golang.org/x/crypto; pgx supplies
PostgreSQL access. Browsers use Web Crypto where applicable plus bundled noble,
scure, hash-wasm, hpke-js, Cloudflare blindrsa-ts and Peculiar X.509 libraries.
See [third-party notices](THIRD_PARTY_NOTICES.md) for pinned dependencies/licenses.

This is not anonymity against malicious served JavaScript, XSS, operators,
network/timing correlation, tiny groups, issuer minting or server-CA substitution.
Database role isolation does not make a malicious application/issuer trustworthy.
Public password-derived authentication keys permit offline password guessing;
use strong unique passwords. Phrase/password rotation rewraps the same vault key
V: old compromised snapshots are not revoked. Blind authorizations reserve quota;
lost pending/unblinding state can strand it, and issued count is not accepted count.
Pagination currently uses fixed 50-item pages with only partial limit-parameter
support. Registration, credential changes and deletion do not universally cache
retries; durable idempotency is specifically tested for blind issuance and spends.
See [architecture/threat boundaries](docs/architecture.md),
[protocol](docs/protocol.md), [API](docs/api.md), and
[verification requirements](docs/verification.md).

## Development and deployment

Requires Go 1.27.3, Node.js 26, and PostgreSQL 18 (or Docker Compose v2). Operator/dev
commands only; do not use real sensitive data in development.

```sh
npm ci
npm run build
npm test
npm run test:interop
make test
make vet
```

Database integration tests need both `ANONCE_TEST_DATABASE_URL` and
`ANONCE_TEST_ANON_DATABASE_URL`, pointing to separate member/anonymous roles in a
**disposable** database. They are skipped without those variables; a green
ordinary Go run alone is not database-integration evidence.

For HTTPS deployment, follow [operations](docs/operations.md): configure `.env`
from `.env.example`, distinct DB roles, and a 32-byte base64url server secret
readable by runtime UID 65532 (owner 65532, mode 0400 on rootful Linux).
`make compose-check` validates configuration; `make build` builds images.
Back up the server key and PostgreSQL metadata/data as a coordinated recovery set.
Do not start a public deployment until gates and source availability are resolved.

Optional browser E2E targets an already-running disposable HTTPS service:

```sh
npx playwright install chromium
ANONCE_E2E_ORIGIN=https://localhost:18443 ANONCE_E2E_ALLOW_SELF_SIGNED=1 npm run test:e2e
```

Self-signed TLS bypass is explicitly restricted to loopback test origins, never
public deployment. Historical Node 24 E2E evidence covers the whole browser flow,
lost-reply exact retry and original-phrase recovery, not every failure/renewal case.
Later Node 26 checks are listed separately in the verification record.

## Project and license

[Source](https://github.com/mandipnotroot/anonce-platform) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

Original material is **AGPL-3.0-only**, not “or later”; see [LICENSE](LICENSE).
Network deployments must offer complete corresponding source for their exact
version, including modifications. Third-party licenses remain applicable.
