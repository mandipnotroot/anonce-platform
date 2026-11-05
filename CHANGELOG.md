<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Changelog

Notable changes are curated here following
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Future releases will follow [Semantic Versioning](https://semver.org/).
No version has been released.

## Unreleased

### Added
- Browser-local recovery phrase copy and plain-text download controls.
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
- Use a dark-only interface with accessible focus states and responsive navigation.
- Report unreadable encrypted responses individually in reviewer results and exports.
- Simplify the web interface with self-hosted Geist typography, text navigation symbols,
  restrained navigation, and plain review status text instead of badges.
- Use Alpine containers and current stable Go, Node.js, PostgreSQL, Caddy,
  Go dependencies, and CI actions. Keep existing exact npm pins, already current.

### Fixed
- Preserve issuance retry bytes when restoring encrypted pending state from PostgreSQL JSONB.
- Extend response-count regression coverage for issuance, invalid submissions,
  rollback, concurrent duplicates and retries; counts reflect committed records only.
- Quote the Compose tmpfs mount so its security options remain a single entry.

### Security
- Pad authenticated issuance pending objects to a fixed plaintext size to prevent
  direct response-length linkage for new objects. Previously retained objects,
  timing correlation and other documented trust limitations remain out of scope.

Recorded validation does not constitute an independent audit, a release, or
approval for sensitive production data.
