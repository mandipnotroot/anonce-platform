<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Changelog

Notable changes are curated here following
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Future releases will follow [Semantic Versioning](https://semver.org/).
No version has been released.

## Unreleased

### Added
- Optional `ANONCE_DB_VOLUME` selection for fresh-database deployments without
  deleting the previous database or changing Caddy's TLS volumes.
- Direct organization membership by registered email alongside invite links,
  multiple organization admins, and owner-only admin appointment controls.
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
- Refine shared spacing, form controls, cards, tables, and responsive layouts
  across authentication, recovery, workspaces, reviews, and response flows.
  Shorten interface copy while retaining recovery and anonymity limitations.
- Replace usernames with unique normalized email addresses for registration,
  sign-in, and recovery. Show member emails to organization owners and admins;
  email addresses are not mailbox-verified.
- Distinguish the current organization workspace and review/membership statuses,
  with additional locally bundled Lucide icons and labeled icon actions.
- Share spacing, typography, and corner-radius tokens across cards, forms, and
  responsive layouts; match browser theme colors to light and dark preferences.
- Align the web interface with the reference design: centered header navigation,
  a constrained content area, a shared footer, and consistent light/dark cards
  and forms across desktop and mobile screens.
- Make contributor guidance independent of personal Git identities and coding
  tools, document pull request expectations, and align runtime requirements with CI.
- Use neutral light/dark surfaces, accessible focus states, responsive navigation,
  and a keyboard skip link without decorative gradients.
- Report unreadable encrypted responses individually in reviewer results and exports.
- Simplify the web interface with self-hosted Geist typography, locally bundled
  Lucide navigation icons, restrained navigation, and plain review status text.
- Use Alpine containers and current stable Go, Node.js, PostgreSQL, Caddy,
  Go dependencies, and CI actions. Keep existing exact npm pins, already current.

### Fixed
- Confirm organization, invitation, membership, review, password, recovery, and
  download actions with shared success toasts. Avoid duplicate password feedback
  and restore the sign-out button after failed requests.
- Hide completed response forms and separate receipt content and actions with
  consistent spacing, keeping long receipt values within narrow screens.
- Display complete signed response receipts as readable JSON instead of
  `[object Object]`, with copy and download controls after acceptance or retry.
- Show request and form failures in shared toast notifications instead of duplicate
  inline errors or browser alerts, with safe error-specific guidance and readable
  fallbacks for malformed server errors.
- Confirm successful clipboard copies through toasts and report failed copies
  without claiming success or displaying object-shaped error text.
- Balance mobile workspace navigation with equal-sized icon-and-label tabs,
  a compact Account label, and accessible current-page indicators while retaining
  the full desktop account and recovery label.
- Match navigation and source-link icon colors to the current light/dark theme.
- Separate adjacent cards, form controls, and recovery warnings; refresh button
  colors and disabled states, and add local action icons that persist during updates.
- Keep mobile navigation, recovery words, and share controls within narrow screens,
  and use theme-aware text colors on primary and danger buttons.
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
