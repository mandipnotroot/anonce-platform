<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Security policy

## Supported versions

- Anonce is unreleased. Security fixes target the current development version;
  no released production version is supported.
- Do not use Anonce for sensitive production data. No independent security audit
  or production-readiness assurance is claimed.

## Reporting a vulnerability

- Submit a private [vulnerability report](https://github.com/mandipnotroot/anonce-platform/security/advisories/new).
  Do not disclose vulnerability details in public issues or pull requests.
- Include the affected revision, reproduction steps using synthetic data,
  expected and actual behavior, and potential impact.
- Do not include real credentials, private keys, recovery phrases, plaintext
  responses, or identifying submission data.
- If private reporting is unavailable, wait until a private channel is available.

## Handling reports

- Reports require maintainer assessment; no response or remediation deadline is
  promised.
- Keep details private while assessment and remediation are coordinated.
- Test only systems you own or have explicit permission to assess. Do not access
  other users' data or disrupt services.

## Security limitations

- Upstream container-component advisories remain unresolved.
- See [architecture and trust boundaries](docs/architecture.md),
  [protocol](docs/protocol.md), and [deployment guidance](docs/operations.md)
  for security assumptions and limitations.
- Required [verification gates](CONTRIBUTING.md#verification-and-release-gates)
  are not a claim of completed audit or production approval.
