<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Changelog

Notable changes are curated here following
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Future releases will follow [Semantic Versioning](https://semver.org/).
No version has been released.

## Unreleased

### Added
- Initial repository bootstrap: contributor rules, AGPL-3.0-only license,
  project status, contribution guidance, and private security reporting policy.
- Go/PostgreSQL backend and vanilla-browser flows for encrypted vaults, recovery,
  organizations/membership, signed review publication, blind authorizations,
  anonymous encrypted responses, receipts, and recipient decryption/export.
- Bundled established browser cryptography and versioned wire/API contracts.
- Transactional quota/replay/idempotency controls and separate database roles.
- Docker/Compose/Caddy deployment scaffold, nonroot runtime, backup guidance,
  CI checks, crypto interoperability and opt-in disposable database/browser tests.
- Visible corresponding-source links using the configured deployment source URL.
- Local HTTPS deployment for `anonce.local`, bound to all interfaces.

### Changed
- Simplify the web interface with self-hosted Geist typography, Lucide icons,
  restrained navigation, and plain review status text instead of badges.
- Use Alpine containers and current stable Go, Node.js, PostgreSQL, Caddy,
  Go dependencies, and CI actions. Keep existing exact npm pins, already current.

### Fixed
- Quote the Compose tmpfs mount so its security options remain a single entry.

Recorded validation does not constitute an independent audit, a release, or
approval for sensitive production data.
