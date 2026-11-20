<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Security review

## Scope and assurance

- Review date: 2026-11-20; baseline commit: `5d5236d06302f218df459c56c1e14660e6b79e8d`.
- Automated source-first review of authentication, authorization, database roles,
  replay/quota transactions, cryptographic input validation, browser secrets and
  asynchronous lifecycle, deployment configuration, and dependencies.
- Targeted synthetic reproductions inform the findings below. This is not an
  independent security audit, proof of cryptographic correctness, or approval for
  sensitive production data. See the [security policy](../SECURITY.md).

## Findings and remediation

| Finding                                           | Severity           | Impact and preconditions                                                                                                                                                                                                                    | Remediation                                                                                                          |
| ------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Registration resumes after logout                 | Medium             | Credential derivation or registration completes after logout and automatic sign-in restores unlocked state.                                                                                                                                 | Keep registration and automatic sign-in in the original session generation.                                          |
| Pending work adopts a different account           | Medium             | Same-tab logout/account switch during response issuance or draft encryption can persist the prior account's authorization/private title under the new account or dispatch a mutation using the new identity.                                | Capture the original state and generation; check before requests, persistence, cache cleanup, and sensitive returns. |
| Sensitive rendering/export outlives its route     | Medium             | Late review retrieval, response retry, result pagination, or export can display/download private content after navigation or logout.                                                                                                        | Propagate the current-load predicate through sensitive renderers and nested success/error callbacks.                 |
| Container build uses an outdated standard library | Advisory-dependent | The Go 1.27.3 builder embeds its standard library in the application. CVE-2026-97054 concerns concurrent HTTP/1 body reads/header writes after a `MaxBytesReader` limit is exceeded; this application's exploitability was not established. | Synchronize the minimum Go version, CI, and Docker builder to vendor-fixed 1.27.4.                                   |
| PostgreSQL image includes older bundled libraries | Scanner-reported   | The PostgreSQL 18.6 image includes package versions with upstream fixes; image-wide severity does not establish database-request reachability.                                                                                              | Use the verified upstream `postgres:18.7-alpine3.24` image; some component matches remain below.                     |

- Deterministic regression cases exercise delayed credential derivation,
  encryption, issuance, receipt handling, decrypted returns, IndexedDB opening,
  and UI completion across session/route changes.
- Persistence guards run after encryption and after opening IndexedDB, immediately
  before starting a write transaction.
- Requests and transactions dispatched before invalidation cannot be undone.
  Guards reject stale continuations; they do not erase another tab's memory,
  copied data, or exported files.
- No concrete backend authorization bypass, token replay/quota bypass, SQL
  injection, remote malformed-input crash, or cryptographic forgery was established
  in the reviewed paths. This is not a claim that none exists.
- `max_responses` intentionally limits issued authorizations per member, not
  global accepted submissions; see [quota semantics](architecture.md).
- The application image explicitly installs Alpine's fixed `libcrypto3` and
  `libssl3` `3.5.9-r1` packages. This project-owned image change does not repair
  the separate PostgreSQL or Caddy images.

## Open upstream image risks

| Image/component                               | Unresolved advisory or limitation                                                                                       | Handling                                                                                                                                                                        |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Caddy 2.11.9: Go standard library and `x/net` | CVE-2026-97054 and CVE-2026-78661 have component fixes, but no newer stable Caddy image was verified during review.     | Track an upstream image release and confirm applicability with the vendor; do not imply the proxy was fixed by updating the app's Go compiler.                                  |
| Caddy 2.11.9: `go-jose/v3`                    | CVE-2026-116587 has no patched v3 version in the upstream advisory; a v4 fix does not update the bundled v3 dependency. | Requires upstream dependency/image remediation or a supported vendor assessment.                                                                                                |
| PostgreSQL 18.7: bundled `gosu`               | The bundled binary still reports Go 1.24.6 and matches CVE-2025-68121 and other Go advisories.                          | Supported Compose runs as `postgres`, avoiding the root privilege-drop path; this limits exposure but is not a blanket CVE dismissal. Keep upstream image updates under review. |
| PostgreSQL 18.7: OpenSSL libraries            | Scanner-reported fixed package versions are not all present in the updated image.                                       | Retain as an open vendor/package risk; do not patch/rebuild third-party service sources locally.                                                                                |
| Node 26.13.1 builder                          | Scanner matches remain in bundled npm dependencies; no newer same-line stable image was verified.                       | Build-stage contents are not copied into the runtime app, but build-environment exposure still requires maintenance.                                                            |
| Application image: zlib                       | CVE-2026-4738 is the remaining scanner match after the OpenSSL update; its advisory describes GDAL's `infback9` code.   | Affected GDAL code was not established in this image. Keep the attribution unresolved rather than claiming either exploitation or a clean scan.                                 |

- These are unresolved component matches, not proven application exploit paths.
  They prevent a clean-image or “all security gaps fixed” claim.
- Preserve unmodified upstream third-party service images. Any alternative vendor,
  image rebuild, or other architectural mitigation needs an explicit requirement
  and review rather than an undocumented fork.

## Remaining review and operational gates

- Container scans report bundled-component advisories separately from application
  reachability. Upstream image remediation and applicability must be tracked;
  package matches alone neither prove exploitation nor justify dismissing a risk.
- Upstream version tags are not immutable digests; future image contents and
  advisory databases may differ from those examined.
- Dependency scans do not cover unpublished vulnerabilities, malicious packages,
  or all transitive behavior. A host toolchain scan does not validate an older
  container compiler's embedded standard library.
- No live HTTPS multi-account browser penetration test, independent cryptographic
  audit, backup/restore or key-rotation exercise, or comprehensive Git-history
  secret scan is established by this review.
- Live browser authentication/publication/submission/export journeys remain
  unverified. HTTPS readiness, mocked UI checks, and module tests do not satisfy
  that release gate.
- Shared per-process API limits do not provide per-client fairness or
  denial-of-service protection.
- Large trusted-operator receipt-key configurations remain a startup-cost
  consideration within the existing file-size bound, not a proven remote attack.
- Malicious served code, compromised browser/device state, copied plaintext, and
  network/timing correlation remain [trust boundaries](../SECURITY.md#trust-boundaries).
- Keep exact commands, exit statuses, scanner reports, skipped checks, and
  current-revision results in private review/CI artifacts, not this document.
  Follow the [verification gates](../CONTRIBUTING.md#verification-and-release-gates).

## Vendor references

- [Go security release announcement](https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM).
- [go-jose advisory and affected versions](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q).
- [Official PostgreSQL Alpine image source](https://github.com/docker-library/postgres/blob/master/18/alpine3.24/Dockerfile).
