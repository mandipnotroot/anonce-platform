<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Changelog

Notable changes are curated here following
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Future releases will follow [Semantic Versioning](https://semver.org/).
No version has been released.

## Unreleased

### Added

- Dedicated disposable PostgreSQL CI coverage with distinct member and anonymous
  roles, plus an opt-in guard that fails tests when required database URLs are
  missing. Container CI validates base/local Compose configurations and builds
  application and proxy images without deploying or publishing them.
- Browser-side encryption of review titles, descriptions, and complete questions,
  including drafts, with separate invitation-link content keys and answer keys.
  Secret links permit question reading, not membership or answer decryption.
  Signed descriptors replace plaintext content; no legacy-format migration is provided.
- Browser-local receipt verification with explicit public trust configuration,
  receipt-file import, and downloadable current/historical verification keys.
- Shared Go/browser receipt-v2 test vectors and negative cases for context,
  ciphertext replacement, trust configuration, and server-key continuity.
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

- Remove redundant page breadcrumbs and use the shared trash icon for question
  removal while preserving its accessible name. Keep mocked UI style checks
  independent of incidental pointer hover.
- Reuse one fresh, lazy vault download within each review-list request for
  creator-owned reviews instead of downloading the vault for every review.
  Separate list loads and standalone key lookups still fetch independently;
  no cross-page key or plaintext cache is added.
- Show immediate, accessible loading feedback when opening Overview and fetch
  reviews and pending responses concurrently after loading organizations. Keep
  fresh data without adding a cache, and test delayed requests, failures, and
  navigation away before requests finish.
- Show receipt-verification navigation according to the current session, including
  direct visits and refreshes, without loading the account vault or crypto state.
- Keep desktop navigation labels on one line for consistent tile heights. Extend
  mock browser checks for navigation sizing, short-viewport overflow, and focus
  after canceling membership revocation, button contrast, and mobile receipt
  action visibility. Complete recovery confirmation before navigating to later
  test flows, and remove duplicated receipt text when acceptance time is unavailable.
- Gate proxy startup on application readiness, allow 30 seconds for Compose
  shutdown, and force HTTP connections closed if the 15-second drain fails.
- Align organization-table selects with shared form controls, reuse theme-aware
  success colors, and standardize recovery-word and icon-button shapes and sizes.
- Extend mock browser screenshots to cover review creation and editing, response
  submission, receipts, overview, and the account page at desktop and mobile sizes.
- Remove redundant toolbar spacing declarations without changing toolbar layout.
- Replace generic documentation diagrams with browser/deployment trust boundaries
  and the publication, member key-delivery, blind-authorization, anonymous
  submission, and creator-only decryption flow.
- Replace secret review-content links with per-member HPKE key envelopes for all
  approved organization memberships at publication. Later-approved members do
  not receive historical keys. Answer decryption stays creator-only; dashboard
  completion is browser-local, not server-tracked participation. New account key
  bindings require fresh registration/schema initialization; no upgrade path is
  supplied. Live-browser verification remains a release gate.
- Standardize contributor formatting guidance by language, with tracked-file
  Go formatting checks in CI and exact-pinned, explicit-file Prettier commands.
  Existing source formatting and E2EE behavior are unchanged.
- Minimize review metadata disclosure: descriptor v3 omits account IDs, quotas,
  and schedules. Member responses use a creator flag and restrict review settings
  and activity counters to creators. Server-side quota/schedule enforcement remains
  unchanged; operational metadata is not E2EE. Earlier descriptors are unsupported.
- Rewrite project documentation around setup, browser workflows, trust boundaries,
  operations, and verification evidence; replace the prose API reference with an
  OpenAPI contract. This documentation change does not change application behavior
  or revalidate historical test results.
- Group organization names, roles, and status badges in compact list rows, with
  full-width Open actions on mobile, 44px tap targets, and theme-matched Approved icons.
- Download receipts as readable PNG cards containing the complete signed receipt
  in a QR code. Read receipt images locally before applying the existing signature
  checks; keep signing keys separate from receipt data.
- Make receipt verification file-first, with a visible desktop/mobile navigation
  link, optional JSON paste and signing-key details, and clearer result guidance.
  Keep receipt formats and cryptographic verification unchanged.
- Replace the raw submission receipt display with verified acceptance, time,
  download controls, and optional JSON details.
- Use receipt v2 to bind the encrypted response to its deployment, review,
  descriptor, and issuer without exporting token or full submission hashes.
  Public configuration v2 publishes an operator-approved receipt keyring.
- Move the current workspace name into the header without an uppercase label.
  Keep desktop navigation at the top while scrolling and mobile navigation at
  the bottom, with safe-area spacing and content clearance.
- Use soft charcoal dark-theme surfaces with teal accents.
  Standardize shared section, list, toolbar, and mobile form spacing,
  and shorten dashboard, account, and review setup copy.
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

### Removed

- Remove the checked-in verification diary and historical run logs. Consolidate
  repeatable test commands and release gates in the contribution guide; keep run
  results in pull requests or CI artifacts and product limits in architecture docs.

### Fixed

- Correctly convert Unix-second response acceptance times in the manage dashboard,
  avoiding invalid dates and handling timestamps outside the display range.
- Isolate established-member API request capacity from public and anonymous
  traffic with independently bounded request windows. Validate sessions before
  selecting member capacity, including session-bound challenge requests, without
  adding identifying tracking to anonymous endpoints.
- Prevent stale asynchronous session restoration and recovery from unlocking the
  browser workspace after logout. Keep delayed logout cleanup from clearing a
  newer session's state.
- Fix CI workflow validation by setting the disposable container-build key path
  at step runtime instead of using the unavailable job-level `runner` context.
- Enforce review creation roles on the server under the organization lock,
  including retries after demotion. Respondents retain response authorization
  access; existing creators retain access to their reviews.
- Preserve successful credential-change outcomes and new recovery words when
  automatic sign-in fails after the server commits the change. Prompt for manual
  sign-in instead of reporting the committed change as a failure.
- Warn before discarding an unacknowledged recovery phrase through navigation,
  sign-out, or another rotation. Keep recovery words browser-memory-only;
  browser unload prompts cannot guarantee preservation after reload or closure.
- Use the selected organization's approved membership to show review creation,
  creator metrics, and member-management controls. Hide unavailable actions from
  respondents and keep server-side permission enforcement unchanged.
- Clear organization-specific review state when switching workspaces and ignore
  stale review, pagination, and member-list responses. Restrict response-review
  controls to creators, show pending membership guidance, and keep recovery
  navigation limited to available flows.
- Honor hidden controls consistently and prevent navigation label clipping on
  narrow mobile screens.
- Decode receipt PNGs without blob image URLs blocked by the site's security
  policy, and load public signing keys when opening the verifier directly.
- Verify signed receipt context before returning cached acceptance or decrypting
  reviewer results; use only verified receipt timestamps.
- Reject unsafe server master-key files and bound reads of key material.
- Improve status badge text, icon sizing, and boundary visibility in both themes;
  remove doubled review-card spacing and distinguish icon-button interaction states.
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
