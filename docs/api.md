<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# HTTP API contract

Contract, not completion status. All paths below start with `/api`. Member mutation bodies use the challenge envelope in [protocol.md](protocol.md), except explicitly plain endpoints. Fields listed are decoded payload fields. All mutations have `request_id` unless explicitly plain; exact ID/hash retry returns cached result, changed payload conflicts. Enforce authorization before returning cached sensitive results.

## Common rules

Session cookie: `__Secure-anonce_session`, Secure, HttpOnly, SameSite=Strict, Path=/api/member, no Domain. Token is random 32 bytes; database stores only its hash with scope, epoch and expiry. Session response shape: `{account_id,scope,credential_epoch,csrf_token}`; scope is `full` for password login or `recovery` for recovery login. Require exact configured Origin and the `X-CSRF-Token` header for session-bound mutations, including logout. Recovery scope permits only vault access, credential reset and logout. Public/anonymous routes reject identifying credentials; browser uses credential omission, no-referrer and redirect error.

Default mutation proof is membership signing key. Registration/login/credential operations use the specialized proofs below. Check active membership and database role per route, not merely certificate validity. IDs/binary/decimal strings follow protocol.md. Reject unknown fields, duplicate fields, trailing JSON, invalid encodings and oversized requests; enforce bounded configured body/field limits before expensive crypto. Lists are `{items,next}`, query `after` and `limit` (default 50, bounded). Errors: `{error:{code,message}}`, HTTP 400 malformed, 401 unauthenticated, 403 forbidden, 404 absent, 409 CAS/idempotency/spend conflict, 410 expired or closed, 413 oversized, 429 throttled. Do not leak secrets in messages.

## Identity and vault

| Method/path | Payload or result; action/proof |
|---|---|
| GET `/public/config` | Deployment, configured origin, protocol/KDF settings and public trust/receipt keys; no secrets. |
| POST `/member/auth/params` | Plain `{email}` → `{account_id,credential_epoch,password_kdf,recovery_salt}`. |
| POST `/member/challenges` | Plain `{account_id,action,payload_hash}` → `{challenge_id,account_id,action,payload_hash,nonce,credential_epoch,expires_at}`. |
| POST `/member/register` | `{request_id,account_id,email,password_kdf,password_auth_public_key,recovery_salt,recovery_auth_public_key,password_wrap,recovery_wrap,membership_public_key,vault_objects}`; `register`, proposed password + recovery + membership proofs. |
| POST `/member/session` | `{request_id,account_id,method}`; method/action `login-password` or `login-recovery`, corresponding password/recovery proof. Returns session and sets cookie. |
| GET `/member/me` | Current session/account information. |
| DELETE `/member/session` | CSRF-protected logout; revoke session and clear cookie; no challenge envelope required. |
| GET `/member/vault` | Account's opaque wrappers and vault objects. |
| PUT `/member/vault/objects/{id}` | `{request_id,expected_revision,object}`; `vault-write`, CAS. Recovery-scoped vault writes use recovery proof instead of inaccessible membership proof. |
| POST `/member/credentials/password` | `{request_id,expected_epoch,password_kdf,password_auth_public_key,password_wrap}`; `password-change`, old password + new password proofs. |
| POST `/member/credentials/recovery` | `{request_id,expected_epoch,recovery_salt,recovery_auth_public_key,recovery_wrap}`; `recovery-rotate`, password + new recovery proofs. |
| POST `/member/credentials/reset` | `{request_id,expected_epoch,password_kdf,password_auth_public_key,password_wrap,recovery_salt,recovery_auth_public_key,recovery_wrap,vault_writes}`; `credential-reset`, recovery + new password + new recovery proofs. |

Credential changes atomically CAS epoch, replace indicated credentials/wrappers and revoke all prior sessions/challenges. Reset vault writes also CAS atomically. Password/phrase changes preserve V and existing encrypted data through wrapping; neither repairs compromised old snapshots. UI must warn that compromised snapshots remain decryptable; full compromise repair requires V/object and membership-key rotation. Same-device unlock is a trusted-origin capability, not password-gated protection; logout removes local capability/cache with pending-write guards but cannot revoke copies (see architecture.md).

## Organizations and certificates

Accounts use unique email addresses rather than usernames. Email input is trimmed
and lowercased, including the local part. Supported addresses are ASCII, at most
254 bytes, with a dotted domain; display names and quoted local parts are rejected.
Addresses are not mailbox-verified;
an address on an organization's domain is not proof of employment or domain ownership.
There is no SMTP delivery or automatic domain-based enrollment.

| Method/path | Payload/action; authorization |
|---|---|
| GET `/member/orgs` | List own memberships. |
| POST `/member/orgs` | `{request_id,name}`; `org-create`; authenticated member becomes owner. |
| GET `/member/orgs/{org}/members` | Owner/admin only; items include `id,account_id,email,role,state,status,certificate`. |
| POST `/member/orgs/{org}/members` | `{request_id,email,role}`; `member-add`; owner/admin adds an existing registered account as an approved member. Only owners may assign `admin`. |
| POST `/member/orgs/{org}/invites` | `{request_id,role,expires_at}`; `invite-create`; owner/admin; role `reviewer` or `respondent`; return bearer invite token. |
| POST `/member/invites/accept` | `{request_id,invite_token}`; `invite-accept`; creates pending membership, not immediate authorization. |
| POST `/member/orgs/{org}/members/{member}/approve` | `{request_id}`; `member-approve`; owner/admin; admins cannot target owners or admins. |
| POST `/member/orgs/{org}/members/{member}/revoke` | `{request_id}`; `member-revoke`; owner/admin; admins cannot target owners or admins. |
| POST `/member/orgs/{org}/members/{member}/role` | `{request_id,role}`; `member-role`; owner only; change an approved non-owner to `admin`, `reviewer`, or `respondent`. |
| GET `/member/orgs/{org}/certificate` | Own approved membership certificate; response includes `membership_id`. |
| POST `/member/orgs/{org}/certificate/renew` | `{request_id}`; `certificate-renew`; active approved membership, direct membership-key proof, no CSR; certificate response includes `membership_id`. |

Multiple admins may manage non-admin members. Member emails are visible only to
approved owners/admins, not through anonymous submission endpoints. Direct addition
does not create accounts or send email. An unknown address returns
`404 account_not_found`; use an invite link after the person registers instead.
An existing active or pending membership returns `409 already_member`. Direct
addition can reactivate a revoked non-owner membership with a fresh certificate;
admins cannot reactivate an admin. Duplicate registration returns `409 email_exists`.

## Reviews, issuance and anonymous acceptance

| Method/path | Payload/action; authorization |
|---|---|
| GET `/member/orgs/{org}/reviews` | Approved active organization member; list authorized reviews. |
| POST `/member/orgs/{org}/reviews` | `{request_id,title,max_responses}`; `review-create`; active approved member; returns draft revision and dedicated RSA public key. Default max_responses 1. |
| GET `/member/reviews/{id}` | Authorized organization member; draft visibility restricted to creator. |
| PUT `/member/reviews/{id}` | `{request_id,expected_revision,title,description,questions,max_responses,opens_at,closes_at}`; `review-update`; creator, draft only. |
| DELETE `/member/reviews/{id}` | `{request_id,expected_revision}`; `review-delete`; creator, draft only. |
| POST `/member/reviews/{id}/publish` | `{request_id,expected_revision,descriptor,descriptor_signature,vault_write:{expected_revision,object}}`; `review-publish`; creator, atomically freeze descriptor and save recipient secret ciphertext. |
| POST `/member/reviews/{id}/close` | `{request_id,expected_revision}`; `review-close`; creator, CAS. |
| GET `/public/reviews/{id}` | `{state,descriptor,descriptor_signature}`; published public material only. |
| POST `/member/reviews/{id}/issuances` | `{request_id,issuer_key_id,blinded_message,pending_state:{expected_revision,object}}`; `issue`; active approved member, open review, per-member slot quota. |
| GET `/member/reviews/{id}/issuances/{request}` | Original cached issuance, only issuing member; no new quota consumption. |
| POST `/anon/submissions` | Plain submission from protocol.md → original/new receipt. No session or membership link. |
| POST `/anon/receipts/lookup` | Plain `{review_id,issuer_key_id,serial}` → receipt if spent; otherwise 404. |
| GET `/member/reviews/{id}/submissions` | Creator only; paginated ciphertexts and receipts, no respondent identity. |

Each distinct issuance request reserves a unique per-member slot under member/review row locking and saves pending ciphertext and cached blind signature atomically. Exact retry does not consume another slot. `max_responses` is never a global review capacity; issued and accepted counters are separate. Existing authorization remains usable after membership revocation. On anonymous acceptance check exact prior spend before closed-state rejection, so response loss is safely recoverable. Different ciphertext for the same spent serial conflicts.

`max_responses` must be a positive integer per member. Ciphertext is capped at 256 KiB including tag; browser checks exact plaintext JSON UTF-8 byte length plus 16-byte tag before issuance. Publication validates the reviewer account/membership association in the server database; certificates do not independently bind `reviewer_account_id`. Publication/issuance enforce current certificate validity and membership revocation. Historical browser decoding retains certificate signature/profile checks but ignores current validity, without promising signing-time or historical approval/non-revocation evidence.
