<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Verification contract and evidence

The checklist below describes required coverage, not blanket proof of every case.
Executed evidence is recorded separately below. Neither tests nor independent
focused source reviews constitute an audit or production-readiness approval.

## Backend: real PostgreSQL

- Registration proposed-key proofs; password and recovery login; challenge origin/action/hash/epoch/session binding, expiry, replay and concurrent consumption; strict decoding, unknown/duplicate fields, body limits and CSRF.
- Vault revision CAS, nonce/AAD tampering, recovery scope boundaries; credential epoch CAS races, session/challenge revocation, old/new proof requirements and unchanged vault after password rewrap.
- Organization owner/member/pending/revoked role boundaries, cross-account/cross-org reads and mutations, certificate proof and renewal; certificate validity is not database authorization.
- Publish descriptor and vault write atomicity, draft revisions and immutable publication. Positive max_responses values greater than one, default one, per-member independence (not global capacity), distinct request IDs, exact retry/hash conflicts, concurrent slot allocation and unique constraints. Confirm issued_count differs from accepted_count.
- Revocation blocks issuance but not outstanding tokens. Verify no identifying submission columns/logs/joins. Anonymous Cookie/Authorization rejection and proxy stripping; creator-only ciphertext export.
- Concurrent identical/different spends, closure racing acceptance, response loss and retry after closure. Fault injection must show spend/ciphertext/receipt/counter all commit or all roll back. Lookup returns the exact original verifiable receipt.

## Crypto interoperability

- Shared byte-for-byte E, JSON payload hash, KDF, password/recovery wrapper, vault-object and receipt vectors in browser and Go. Validate decimal U64 handling and canonical base64url lengths/roundtrips.
- Established Argon2id v19 parameters, exact 12-English-word BIP-39 checksum/entropy, Ed25519 derived authentication seeds and separate membership seed. Wrong password/phrase, modified metadata, nonce, revision and AAD must fail closed.
- RFC 9474 randomized SHA384-PSS browser blind → Go issuer → browser unblind/verify interoperability, malformed messages, wrong review/key/hash/serial, signature lengths and prepared prefix; never replace the prescribed suite.
- RFC 9180 X25519/HKDF-SHA256/ChaCha20-Poly1305 interop, wrong key/info/AAD/tag rejection, descriptor signature and certificate verification. Ensure no AES substitutions in wrapping or vault objects.

## Browser flows

Full registration and phrase confirmation; password login; create organization; invite, accept pending, approve; create/edit/publish review; multiple per-member authorizations where configured; respond at `#respond/<id>`; reviewer decrypt and export. Cross-device phrase recovery, credential reset and restored encrypted vault; phrase rotation snapshot warning. Preserve exact pending issuance and submission bytes across crashes/retries. Anonymous requests carry no credentials/referrer, do not follow redirects and retry the identical submission, not newly encrypted ciphertext. Review keyboard/accessibility/responsive behavior with `@designer` and a file-specific goal.

Use actual exports in `web/crypto.js` and tests/vectors in `web/crypto.test.js`, not an implementation-progress snapshot. Export presence is not passing evidence.

Test descriptor signature/profile/deployment/org/membership-key checks and server publication validation of reviewer account association; do not claim the account is independently certificate-bound. Expired certificates must still support historical decoding with signature/profile checks, while publication/issuance enforce current validity and revocation. No browser test can establish trusted signing time or historical approval/non-revocation.

Test same-device unlock's nonextractable IndexedDB HKDF CryptoKey, in-memory ChaCha cache key and encrypted V/private state; logout must delete capability/cache and prevent pending writes restoring them. State explicitly that copied capabilities/profile backups, malicious served code and XSS are not defeated by password gating. Password/phrase changes preserve data, not repair old snapshots. Exercise the 256 KiB ciphertext boundary using serialized UTF-8 length plus 16-byte tag before issuance, including multibyte input and server rejection above the cap. Confirm `X-CSRF-Token`, `full`/`recovery` scopes and certificate `membership_id` responses.

## Operations and independent review

Compose build/start/health with real PostgreSQL; least-privilege application/migration DB roles; transactional migration rollback; encrypted backups and actual restore exercises, including server signing keys and receipt verification continuity. Inspect proxy, access/error logs and telemetry for anonymity leaks. Test secure cookie attributes, HTTPS, configured Origin and static locally bundled dependencies.

Independent **source-first** security review should focus on cryptographic transcripts/library use, replay/CAS/quota races, role boundaries, atomic acceptance, browser persistence and infrastructure metadata. Report findings and fixes; do not describe this plan or a focused review as a security audit. Explicitly retain limitations: timing/IP correlation, malicious served code, trusted operators, tiny anonymity sets, server issuer minting, CA substitution and recovery snapshot exposure.

## Executed evidence — 2026-11-05

Local evidence is retained outside the repository in
`/tmp/opencode/anonce-final`; fixture credentials/data are disposable, not production.
Commands below exited 0 unless a limitation is explicitly stated.

- `git diff --check`, read-only `gofmt -l`, and original-source SPDX checks:
  clean. Before staging, zero tracked files made the initial tracked-secret scan
  inconclusive; actual-index review is a separate publication gate.
- `ANONCE_TEST_DATABASE_URL=… ANONCE_TEST_ANON_DATABASE_URL=… go test -race ./... -count=1`:
  8 tests across 2 tested packages against PostgreSQL 17 `anonce_regression`,
  with separate member/anonymous roles; `go vet ./...` passed. This did not use
  or reset the live E2E database.
- Node 24.22.2/npm 11.21.2: `npm ci`, `npm run build`, `npm test`,
  `npm run test:interop` passed. Aggregate: 21 tests, 0 failures/skips before the
  final source-link change; the app owner separately reported 4 focused app tests
  passing afterward (not 25 distinct tests). Interop: 6 checks, including the
  published RFC 9474 vector, Go/browser framing, HKDF, ChaCha, blind RSA and HPKE.
  `npm audit --omit=dev` reported no vulnerabilities at execution time.
- `ANONCE_E2E_ORIGIN=https://localhost:18443 ANONCE_E2E_ALLOW_SELF_SIGNED=1 node scripts/e2e.mjs`
  under Node 24, using an execution-only observer: whole HTTPS journey passed,
  including registration, membership/publication, response, lost-reply exact retry,
  receipt, plaintext/export, reload unlock and original-phrase cross-device recovery.
  CSP console violations: 0; uncaught page errors: 0. Expected new-session 401s
  occurred. The subsequent source-link-only change had focused desktop/mobile
  configured-href checks reported passing; the whole journey was not rerun for it.
- A second execution-only browser wrapper simulated **only near-expiry metadata**
  (`expires_at = now + 60s`): 2 real renewal POSTs returned 200 and the journey
  passed, CSP/page errors both 0. This is not an actual-expired-certificate browser
  test; actual expiry checks belong to backend/helper coverage.
- `pg_dump -Fc` and `pg_restore --exit-on-error` into a new absent-checked
  `anonce_restore_1793857486` database passed. All 14 table counts and sorted
  SHA-256 row digests matched, including 4 immutable ciphertext/receipt records.
  Source E2E/regression databases were not dropped/reset. Matching fixture key
  continuity was preserved; encrypted off-host recovery was not exercised.
- Synthetic `docker compose config --quiet`, proxy-only build/offline Caddy
  validation and fresh-volume nonroot permission checks passed. Final
  `docker build --tag anonce-final:local .` passed. Image:
  `sha256:6ecbcfce9adc95f93706d2591cdda0824020845f8602d63910ed03d7bd3cafbf`.
  Actual UID65532, read-only filesystem, all capabilities dropped and
  no-new-privileges runtime returned 200 for health/readiness/root/config/app/UI.
  Served app/UI bytes matched frozen sources including source links. A copied
  fixture key owned by UID65532, mode0400, was readable; original key untouched.

## Dark interface and acceptance checks — 2026-11-05

This change uses a separate disposable PostgreSQL 18.6 instance and source copies,
not the deployment or databases described above. Execution uses isolated Docker
containers with no external network, an explicit empty-environment allowlist,
read-only source/tool mounts, scratch tmpfs storage, dropped capabilities and
CPU, memory, process, file-size, disk and wall-clock limits. Fixture roles have
no production credentials. Logs are retained in
`/tmp/opencode/anonce-current-checks.log` and follow-up logs beside it.

- Node 26.12.1: `node scripts/build.mjs` exited 0.
- `node --test web/api.test.js web/app.test.js web/crypto.test.js web/storage.test.js web/ui.test.js`
  exited 0: 31 tests passed, no failures or skips. This includes fixed-size
  issuance padding, remote JSONB retry reconstruction, per-record decryption
  failure isolation, exports, and recovery clipboard/download helper behavior.
- The first Go attempt used local Go 1.27.2, below `go.mod`'s required 1.27.3;
  backend/vet/interop checks could not run in that attempt. The cached 1.27.3
  toolchain is selected explicitly for the follow-up. The first browser harness
  also exposed an HTML MIME error in the test server; the harness was corrected.
- With Go 1.27.3 and both disposable database URLs configured,
  `go test -race -count=1 ./...` and `go vet ./...` exited 0. The server tests
  include assertions that accepted counts equal persisted rows after issuance,
  invalid fields/signatures, an invisible uncommitted write, rollback,
  concurrent duplicates, exact retries and conflicting replays.
- `node scripts/crypto-interop.mjs` exited 0: six interoperability groups passed,
  including the published RFC 9474 vector, framing, HKDF, ChaCha, blind RSA and
  HPKE, with the existing tamper-rejection checks.
- `node scripts/ui-check.mjs` exited 0 for dark computed color scheme,
  desktop/mobile overflow, phrase copy/download and unreadable response notice.
  After fixing replacement-phrase display following account recovery,
  `node --test web/ui.test.js` exited 0 again (4 tests, not additional distinct
  tests), and `node scripts/ui-check.mjs` exited 0 across registration, recovery
  and phrase rotation. Final UI evidence is in
  `/tmp/opencode/anonce-current-checks-ui.log`.

These checks are targeted regression evidence, not a full cryptographic audit.
The mock browser harness does not establish real HTTPS, account recovery or
end-to-end server behavior. Previous deployment evidence is historical, not a
deployment of the current changes.

## Remaining limitations

Fixed 50-item pagination and partial limit-parameter support remain. Registration,
credential changes and deletion are not universally retry-cached; durable core
blind-issuance/spend idempotency has specific tested coverage, not a global promise.
No public DNS/TLS deployment, independent audit or sensitive-production approval
is claimed. Malicious JavaScript/operators, timing correlation, offline password
guessing, issuer/CA trust, small groups and compromised vault snapshots retain
the architecture's stated limitations. Publication does not establish a public
deployment, release, or production approval.
