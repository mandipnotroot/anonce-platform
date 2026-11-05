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
never point them at production data. Recorded E2E results and remaining release
gates are documented in [verification evidence](docs/verification.md).
Use the [private security reporting process](SECURITY.md) for vulnerabilities.

Original contributions are accepted under **AGPL-3.0-only** and must include
appropriate SPDX notices. Preserve third-party licensing and update
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) when dependencies change.
Do not add secrets or identifying
submission data. Preserve other contributors' work and never force-push shared
history.
