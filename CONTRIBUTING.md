<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Contributing to Anonce

Development happens at https://github.com/mandipnotroot/anonce-platform.
Contributions are welcome through issues and pull requests. Discuss substantial
architecture, protocol, dependency, or interface changes before starting work.
Report vulnerabilities privately through [SECURITY.md](SECURITY.md), not issues.

Read [AGENTS.md](AGENTS.md) before editing; its architecture, privacy,
cryptography, interface, and evidence requirements apply to contributions.
No specific coding assistant or editor is required. Use your own Git author
identity. Agree shared contracts and disjoint file scopes before parallel work.

## Local setup

Fork and clone the repository, then create a branch for your change. Install the
Go version declared in `go.mod` and the Node.js version used in
[CI](.github/workflows/ci.yml). Run `make browser`, `make test`, and `make vet`
for local checks; these do not start the application. Follow
[operations](docs/operations.md) for a disposable HTTPS environment.
Use only synthetic test data. Never commit local environment files or keys.

## Formatting

Use the Go toolchain declared in `go.mod`. Run `npm ci` to install the exact-pinned
local Prettier version from `package-lock.json`; do not use a global installation.
The repository Prettier configuration is authoritative for supported files.
Prettier is a development-only dependency that provides consistent formatting
across supported languages without adding runtime browser or server dependencies.

| Files                                  | Formatter and policy                                                                                                   |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Go (`.go`)                             | `gofmt`, through `make fmt` and `make fmt-check`.                                                                      |
| JavaScript (`.js`, `.mjs`), HTML, CSS  | Local Prettier, with explicit file paths.                                                                              |
| JSON, YAML (`.yaml`, `.yml`), Markdown | Local Prettier, with explicit file paths.                                                                              |
| PostgreSQL (`.sql`)                    | No automated formatter configured. Preserve surrounding SQL style and transactional migration boundaries.              |
| Shell (`.sh`)                          | No automated formatter configured. Preserve surrounding shell style; validate syntax with `bash -n path/to/script.sh`. |
| `Caddyfile`, `Caddyfile.local`         | Use `caddy fmt` from the project's pinned Caddy image/tool version when changing these files.                          |
| `Dockerfile`, `Makefile`, ignore files | Preserve surrounding style; keep required Make recipe tabs. No automated formatter configured.                         |

Format only the files you change. For example:

```sh
make fmt
make fmt-check
npm run format -- web/app.js docs/protocol.md
npm run format:check -- web/app.js docs/protocol.md
```

The Go targets cover tracked Go files; avoid committing unrelated changes if the
baseline becomes unformatted. Prettier commands require explicit paths. Do not
run repository-wide formatting as part of a functional change. Generated bundles,
dependencies, npm-managed lockfiles, secrets, and local environment files are not
formatter inputs. Change source files and regenerate outputs with their build tools.

CI enforces Go formatting. Prettier checks are explicit-file contributor checks;
CI does not yet enforce a repository-wide Prettier baseline. Formatting is separate
from syntax validation, tests, and cryptographic verification.

## Pull requests

Keep each pull request focused. Describe the problem, the change, and any known
limitations. Include exact test commands and results; explain skipped checks.
For interface changes, include screenshots at desktop and mobile widths and
check keyboard navigation. Update affected documentation, tests, and the
`Unreleased` changelog when behavior changes. A maintainer must review changes
before merging.

## Standards

Required standards:

- [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
- [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
- [JetBrains modern Go guidelines](https://github.com/JetBrains/go-modern-guidelines),
  limited to the Go version declared by the project.

Use `type(scope): description` commit subjects (`feat` for features, `fix` for
bug fixes). Mark breaking changes with `!` or a `BREAKING CHANGE:` footer.
Keep the changelog human-curated, newest first, with `Unreleased` and applicable
change categories; date and link releases when releases exist.

Keep changes focused and documentation honest. Record exact verification
commands, exit statuses, and skipped checks; do not claim unperformed tests or
security review. Update the [OpenAPI contract](docs/openapi.yaml) and
[protocol formats](docs/protocol.md) when their contracts change. Database
integration tests skip without their explicit test database environment variables;
never point them at production data. Follow the checks and release gates below.
Use the [private security reporting process](SECURITY.md) for vulnerabilities.

## Verification and release gates

Use the Go version in `go.mod` and the Node.js version pinned in CI. Run checks
with disposable synthetic data only. Record exact commands, exit statuses,
relevant results, and skipped checks with reasons in the pull request or CI
artifacts, not a checked-in execution diary. Results apply to the tested revision;
historical passes do not validate later changes.

| Check                                | Command                                                          | Preconditions and limits                                                                                                                                       |
| ------------------------------------ | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Go formatting                        | `make fmt-check`                                                 | Checks tracked Go files                                                                                                                                        |
| Web/document formatting              | `npm run format:check -- <changed supported files>`              | Supply explicit paths after formatting                                                                                                                         |
| Go race tests                        | `make test`                                                      | Database tests require both `ANONCE_TEST_DATABASE_URL` and `ANONCE_TEST_ANON_DATABASE_URL`, using distinct member and anonymous roles in a disposable database |
| Go static checks                     | `make vet`                                                       | Does not replace runtime tests                                                                                                                                 |
| Browser modules and interoperability | `make browser`                                                   | Installs pinned dependencies, builds assets, and runs module and Go/browser crypto tests                                                                       |
| Mock browser UI                      | `node scripts/ui-check.mjs` and `node scripts/ui-responsive.mjs` | Requires Playwright Chromium; mocked APIs do not validate live backend authorization or accessibility conformance                                              |
| Compose configuration                | `make compose-check`                                             | Requires configured variables; does not start services                                                                                                         |
| Container build                      | `make build`                                                     | Builds images; does not validate deployment                                                                                                                    |
| Live HTTPS browser E2E               | `npm run test:e2e`                                               | Set `ANONCE_E2E_ORIGIN` to an already-running disposable HTTPS deployment                                                                                      |

For a self-signed loopback E2E deployment only, set
`ANONCE_E2E_ALLOW_SELF_SIGNED=1`. The bypass accepts only `localhost`,
`127.0.0.1`, and `[::1]`. See [operations](docs/operations.md) for environment setup.
Database tests that skip without their URLs are not database or concurrency
evidence. CI configuration alone is not evidence that a check passed.

Select focused positive and negative tests for each change. Before a release,
establish current-revision evidence for:

- Authentication, recovery scope, credential/vault revision conflicts, challenge
  replay, and session revocation, including concurrent requests.
- Per-organization roles, approval/revocation, cross-account access, creator-only
  response decryption, and member content-key delivery before and after approval.
- Cryptographic vectors, malformed inputs, context/key substitution, receipt
  verification, key continuity, and browser-only secrets.
- Atomic quota enforcement, idempotent retries, closure races, rollback, and
  restart continuity against PostgreSQL with both restricted database roles.
- Live multiaccount browser journeys for registration, recovery, publication,
  response submission/retries, receipt verification, and creator decrypt/export.
  Check browser persistence, logout cleanup, keyboard access, mobile layouts,
  and assistive technology separately from module tests.
- Anonymous credential omission, identifying-log prevention, metadata boundaries,
  HTTPS/cookies/CSP, runtime key permissions, signing-key rotation, and encrypted
  off-host backup/restore.
- Independent source-first security review of transcripts, dependencies,
  authorization, concurrency, browser storage, and metadata handling.

These are required gates, not claims of completed testing, audit, or production
approval. Keep trust assumptions and product limitations in
[SECURITY.md](SECURITY.md), [architecture](docs/architecture.md), and the
[protocol](docs/protocol.md).

Original contributions are accepted under **AGPL-3.0-only** and must include
appropriate SPDX notices. Preserve third-party licensing and update
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) when dependencies change.
Do not add secrets or identifying
submission data. Preserve other contributors' work and never force-push shared
history.
