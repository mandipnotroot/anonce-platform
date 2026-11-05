<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Security policy

Anonce is under development, with no released or supported production version.
Implementation is pre-release and not approved for sensitive production data.
No independent security audit or production-readiness claim is made. See
[architecture/threat boundaries](docs/architecture.md) and [protocol](docs/protocol.md).

## Report privately

GitHub private vulnerability reporting is enabled for this repository. Use
[Report a vulnerability](https://github.com/mandipnotroot/anonce-platform/security/advisories/new)
to share reproduction steps, affected behavior, impact, and suggested mitigations.
Do not post sensitive findings in public issues or include real credentials,
private keys, recovery phrases, or identifying submission information.
No response-time or remediation deadline is promised.

If the private form is unavailable, do not disclose vulnerability details
publicly; wait until a private reporting channel is available.

## Trust boundaries

Client private keys, review content keys, vault keys, password/recovery material, and question/response plaintext
must remain browser-only. Anonymous requests must omit credentials; submissions
must not acquire identifying fields or logs. Distinct server-only membership CA,
blind issuer, and receipt signing keys require protection at rest.

Secret response links grant review-content access to anyone holding the link.
Their fragment keys must never enter HTTP requests or logs. They do not decrypt
answers or grant response authorization. Browser history and copied links can
retain keys; this version does not provide content-key rotation or link revocation.

Browser-delivered code must be trusted. Anonce does not promise anonymity
against malicious served code or network/timing correlation. Cryptographic
design and implementation require verification before real sensitive use.
Operators/issuers and server CA substitution are also trust boundaries. Public
password-derived keys allow offline guessing. Phrase rotation does not invalidate
old encrypted snapshots or rotate vault key V; report compromise accordingly.
See [operations](docs/operations.md) for deployment/key handling and
[verification](docs/verification.md) for evidence and unresolved release gates.
