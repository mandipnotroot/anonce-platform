<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Contributing to Anonce

Development happens at https://github.com/mandipnotroot/anonce-platform.
Read [AGENTS.md](AGENTS.md) before editing; its architecture, privacy,
cryptography, UI ownership, and evidence requirements apply to contributions.
Agree shared contracts and disjoint file scopes before parallel work.

Required standards:
- [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
- [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
- [JetBrains modern Go guidelines](https://github.com/JetBrains/go-modern-guidelines),
  limited to the Go version declared by the project.

Keep changes focused and documentation honest. Record exact verification
commands, exit statuses, and skipped checks; do not claim unperformed tests or
security review. See [README.md](README.md) for existing developer checks and
[operations](docs/operations.md) for disposable deployment requirements. Database
integration tests skip without their explicit test database environment variables;
never point them at production data. Final E2E/source gates remain in progress.
Use the [private security reporting process](SECURITY.md) for vulnerabilities.

Original contributions are accepted under **AGPL-3.0-only** and must include
appropriate SPDX notices. Preserve third-party licensing and update
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) when dependencies change.
Do not add secrets or identifying
submission data. Preserve other contributors' work and never force-push shared
history.
