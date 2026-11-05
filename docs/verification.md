<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Verification contract and evidence

**No security audit or production approval is claimed.** Required coverage,
configured automation, and recorded results are different evidence. This
documentation rewrite did not rerun application tests or deploy anything.

## Reproduce the gates

Use Go 1.27.3, Node.js 26.12.1, and disposable synthetic data. Never use
production databases. See [operations](operations.md) for HTTPS and role setup.

| Gate | Command | Preconditions and limits |
| --- | --- | --- |
| Go/race | `make test` | Runs `go test -race ./...`; database tests skip unless both `ANONCE_TEST_DATABASE_URL` and `ANONCE_TEST_ANON_DATABASE_URL` are set |
| Go static checks | `make vet` | Runs `go vet ./...` |
| Browser modules/interop | `make browser` | Runs `npm ci`, `npm run build`, `npm test`, `npm run test:interop`; interop requires Go |
| Mock browser UI | `node scripts/ui-check.mjs` and `node scripts/ui-responsive.mjs` | Requires browser tooling; not live-backend or accessibility-conformance evidence |
| Compose syntax | `make compose-check` | Requires configured variables; does not start services |
| Image build | `make build` | Builds Compose images; does not validate deployment |
| Live HTTPS E2E | `ANONCE_E2E_ORIGIN=https://localhost:18443 ANONCE_E2E_ALLOW_SELF_SIGNED=1 npm run test:e2e` | Requires an already-running disposable HTTPS deployment and browser tooling; does not provision services |

Provide distinct member/migration and anonymous fixture-role URLs for database
tests. A green Go command without those URLs is not database/concurrency evidence.
Self-signed E2E bypass is restricted to `localhost`, `127.0.0.1`, and `[::1]`.

### CI configuration

[CI](../.github/workflows/ci.yml) exists and runs on pushes/pull requests, with
a 20-minute Ubuntu job. It pins Go 1.27.3 and Node.js 26.12.1 and runs race
tests, vet, dependency installation, build, module tests, and interop. It defines
no PostgreSQL service/test URLs or live HTTPS E2E step. Workflow configuration
does not establish a successful run or database coverage.

## Latest recorded receipt-v2 checks — 2026-11-05

These are previously recorded results, not new runs for this documentation change.
Older baselines do not validate receipt-v2. Execution used disposable snapshots
in a network-isolated namespace/chroot, read-only source/toolchains, allowlisted
environment, 512 MiB scratch, 2 GiB memory/no swap, one CPU, 128 tasks, and
180-second command limits. No deployment secrets, database connections, or live
services were exposed.

| Recorded command | Exit/result | Scope |
| --- | --- | --- |
| `node --test --test-concurrency=1 web/*.test.js` | 0; 55 passed, no failures/skips | Node 26.12.1; receipt vectors/mutations, historical trust, ciphertext replacement, acceptance checks, reviewer order, limits and stale reads |
| `node scripts/build.mjs` | 0 | Scratch-only build; bundles not promoted or deployed |
| `node scripts/crypto-interop.mjs` | 0; six groups | Go 1.27.3 with `CGO_ENABLED=0`; RFC 9474 vector, framing/U64, HKDF, ChaCha20-Poly1305, blind RSA, HPKE |
| `CGO_ENABLED=0 go test -p=1 ./...` | 0 | Protocol/server passed; three packages without tests; database tests remained opt-in |
| `CGO_ENABLED=1 go test -race -p=1 ./internal/protocol ./internal/server` | 0 | Both packages passed in fresh scratch; not database acceptance/concurrency coverage |

Initial compilation found two test-code type/name issues; successful reruns include
fixes. An initial race attempt exhausted shared scratch; a standalone run passed
with the same limits. Focused static protocol/browser review reported no issues,
but was not a complete audit.

Recorded local logs under `/tmp/opencode/anonce-security-verification/logs/`:

| Log | Evidence |
| --- | --- |
| `run-rnnyo9ht.log` | Node/build and initial compilation failures |
| `run-z93wemgr.log` | Passing interop and remaining compilation issue |
| `run-r_j8_map.log` | Passing full Go rerun |
| `run-xyr8gajw.log` | Passing standalone race check |

Local paths are evidence pointers, not repository artifacts or a guarantee that
another machine retains them.

## Required coverage

| Area | Positive and negative cases required |
| --- | --- |
| Authentication | Registration key proofs; password/recovery; challenge origin/action/hash/epoch/session binding, expiry, replay and concurrent consumption; strict decoding, duplicate/unknown fields, body limits, CSRF |
| Vault/credentials | Revision/epoch CAS races; nonce/AAD tampering; recovery scope; session/challenge revocation; old/new proofs; unchanged vault after rewrap; logout prevents pending writes restoring capabilities |
| Membership | Normalized email uniqueness/invalid addresses; owner/admin/member/pending/revoked boundaries; direct addition/retry; owner-only admin appointment; escalation/cross-account/org denial; certificate proof/renewal is not database authorization |
| Publication/issuance | Descriptor/vault atomicity; draft revisions/immutable publication; independent per-member quotas greater than one; request-ID/hash conflicts; concurrent slots/uniqueness; issued count differs from accepted count |
| Anonymous acceptance | Cookie/Authorization rejection and proxy stripping; no identifying fields/logs/joins; concurrent spends, closure races, lost replies/exact retries; spend/ciphertext/receipt/counter commit or roll back together; lookup returns original verifiable receipt |
| Cryptography | Shared framing/JSON hashes/KDF/wrapper/vault vectors; decimal U64/canonical base64url; prescribed Argon2id, 12-English-word BIP-39, Ed25519, RFC 9474/RFC 9180; wrong key/context/nonce/tag/hash/signature rejection |
| Receipt v2 | Go/browser `testdata/receipt-v2.json` transcripts, hash/key ID/signature; reject changed context/envelope, noncanonical timestamp/encoding, unknown/duplicate fields; maximum U64; explicit historical trust and removed/substituted-key rejection |
| Browser journeys | Registration/phrase confirmation, login, organization membership/approval, publication, multiple authorizations, response, creator-only decrypt/export, recovery/reset; preserve exact pending bytes across crashes/retries |
| Browser receipt use | Verify submitted/looked-up/cached acceptance against saved envelope/verified descriptor before decryption; ignore unsigned timestamps; isolate invalid records; public offline verifier requires explicit trust, 64 KiB limits, stale-read guards and escaped values |
| Operations | Compose health/readiness, role grants, migration rollback, HTTPS/cookies/CSP/Origin, local dependencies, logging leakage, encrypted restore and signing-key continuity |

Anonymous browser requests must omit credentials/referrer, reject redirects, and
retry identical ciphertext. Check the 256 KiB ciphertext boundary using serialized
UTF-8 length plus the 16-byte tag, including multibyte input and server rejection.
Check descriptor signature/profile/deployment/org/membership-key and reviewer
account association without implying independent certificate binding. Historical
certificate decoding retains signature/profile checks but cannot prove trusted
signing time or historical approval/non-revocation.

Test nonextractable IndexedDB HKDF capabilities, in-memory ChaCha cache keys,
encrypted private state, and logout cleanup. Password/phrase changes preserve data
but do not repair copied snapshots. Signature-only saved-file checks must not
claim original-submission matching. Check keyboard, responsive behavior, and
assistive technology separately from module tests.

## Historical summary — recorded 2026-11-05

These snapshots predate receipt-v2 validation. Counts belong to separate snapshots;
do not add them or treat them as current coverage.

| Snapshot | Recorded result | Limits / evidence pointer |
| --- | --- | --- |
| Navigation/shared UI | Node 26.12.1 build, 44 module tests, mock UI/responsive checks and diff check exited 0; light/dark widths 320–1365px | Mocked backend, not device/E2E/WCAG evidence; `/tmp/opencode/anonce-ui-final`, `anonce-nav-*.log`, `anonce-charcoal-*.log` |
| Email accounts/admins | Go 1.27.3 race/vet against disposable PostgreSQL 18.6 with both roles exited 0; 10 top-level Go tests; 42 frontend tests/mock UI passed | No HTTPS E2E or mailbox ownership proof; `/tmp/opencode/anonce-email-final/summary.log` |
| Dark interface/acceptance | Race/vet with both PostgreSQL 18.6 URLs, build, 31 module tests, six interop groups and mock UI exited 0 | Initial old-toolchain/harness MIME errors corrected; `/tmp/opencode/anonce-current-checks.log` and follow-up logs |
| Interface/contributor cleanup | Isolated Node 26.12.1 build/31 module tests, mock UI, diff/link checks exited 0 | No backend/DB/E2E/rebuild or full contrast/accessibility audit for that change |
| Earlier baseline | PostgreSQL 17 race suite (8 tests across two packages), vet, Node 24 build/modules/interop passed; dependency audit reported no vulnerabilities then | Old snapshot/toolchains; `/tmp/opencode/anonce-final`; initial tracked-secret scan inconclusive before staging |
| Earlier HTTPS E2E | Node 24 disposable journey passed registration, membership/publication, submission/lost-reply retry, receipt/decrypt/export, reload and original-phrase recovery; no CSP/page errors | Not current E2E; renewal wrapper simulated only near-expiry metadata, not actual expiry |
| Earlier restore/runtime | Dump/restore matched 14 table counts and sorted row digests, including four ciphertext/receipt rows; synthetic Compose/proxy checks and hardened UID65532 smoke passed | Fixture key continuity only; not encrypted off-host recovery, public DNS/TLS, or current deployment |

## Open gates and limitations

- Receipt-v2 **database integration, concurrent acceptance, rollback, and restart
  continuity were not run**: no approved offline PostgreSQL binaries were available.
  Seven top-level tests use the opt-in helper; default output did not capture
  individual skips. Non-database race tests do not close this gap.
- Receipt-v2 full browser rendering/live HTTPS E2E was not run. Module tests,
  historical mock UI, and Node 24 E2E do not substitute for it.
- The foreign-owner key fixture depends on chown capability and lacks independent
  execution evidence here. Production key permissions, encrypted off-host restore,
  and signing-key rotation remain unverified.
- Pagination remains limited: organization lists have no cursor; member lists
  return at most 100; reviews/submissions return at most 50 with `after` only.
  No configurable `limit` is supported. Registration,
  credential changes, and deletion are not universally retry-cached; core issuance
  and spend idempotency coverage is not a global retry guarantee.
- Independent source-first review remains a release gate: examine transcripts,
  libraries, replay/CAS/quota races, roles, atomicity, browser persistence and
  metadata. No public deployment, independent audit, release, or sensitive-production
  approval is established.
- Malicious code/operators, timing/IP correlation, offline password guessing,
  tiny anonymity sets, issuer minting, CA substitution and compromised recovery
  snapshots retain the [security model's](../SECURITY.md) limitations.

See [OpenAPI](openapi.yaml) for endpoints and [protocol](protocol.md) for formats.
