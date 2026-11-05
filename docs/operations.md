<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Operations (pre-release)

Not production ready or approved for sensitive production data. Broad validation
and the final image's hardened local smoke passed; no public deployment launched.
Focused checks confirmed nonroot PostgreSQL initialization, proxy-volume writes,
offline Caddy configuration, and UID65532 secret reads with a synthetic fixture.
Historical disposable Node 24 HTTPS browser E2E passed the whole flow, lost-reply
retry and original-phrase recovery. The current build uses Node.js 26; see
[verification evidence](verification.md) for later checks and their limits.
Neither result certifies production safety or all branches.
Requires Docker Compose v2, DNS for one public domain, and inbound TCP 80/443
and optionally UDP 443. All user interactions remain browser-only.

## Deployment contracts

PostgreSQL 18 uses backend-owned initialization scripts in `db/init` by default;
`ANONCE_DB_INIT_DIR` can override that directory. Before startup, confirm it
contains nonempty reviewed scripts, not an empty placeholder. They must create distinct member and
anonymous login roles using the supplied role passwords, with no superuser,
database creation, or role creation permissions. Restrict anonymous grants to
its contract; no membership tables. `DATABASE_URL` uses the migration/member
role, never `anonce_admin`; `ANON_DATABASE_URL` uses the restricted anonymous role.
No shared-role fallback is acceptable. Initialization runs only on empty volumes.
Backend owns transactional, versioned migrations guarded by an advisory lock.
The role names are `anonce_member` and `anonce_anon`, using
`ANONCE_MEMBER_DB_PASSWORD` and `ANONCE_ANON_DB_PASSWORD`, respectively.
Confirm actual grants against the backend contract before deployment.

The binary is `./cmd/anonce`, listens on `ANONCE_ADDR=:8080`, serves
`ANONCE_WEB_DIR=/app/web`, and reads `ANONCE_KEY_FILE=/run/secrets/server_key`.
That file contains the unpadded base64url encoding of exactly 32 random bytes
for the server ChaCha master key, not client keys. Backend must set member
cookies with Path=/api/member and strict security headers, including a self-only
CSP permitting `wasm-unsafe-eval` where necessary, never general `unsafe-eval`.
Browser build uses `scripts/build.mjs` and emits `web/crypto.bundle.js`, retaining
the vanilla app/API/UI files. Docker copies both `scripts/` and `web/` for this build.

## First setup (review deployment prerequisites first)

### Local deployment

Use `ANONCE_DOMAIN=anonce.local` with the local override:

```sh
docker compose -p anonce-local -f compose.yaml -f compose.local.yaml up -d --build
```

HTTPS listens on all interfaces. Map `anonce.local` to the server's LAN IP
in each client's hosts file, and trust the local Caddy root CA in the browser.
The current local CA certificate is exported to `.env.local-ca.crt`.
Local credentials and keys stay in ignored `.env` and `secrets/` files.

### Configuration

Copy `.env.example` to `.env`; fill every blank with strong distinct credentials,
correct role URLs (URL-encode passwords), public domain, and reviewed init path.
Generate the server key locally using an operator CLI:

```sh
mkdir -p secrets
chmod 700 secrets
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > secrets/server_key
```

On a rootful Linux Docker host, provision the generated file explicitly:

```sh
sudo chown 65532:65532 secrets/server_key
sudo chmod 0400 secrets/server_key
```

The earlier `umask 077` alone leaves the key owned by the operator and unreadable
to container UID 65532. Compose bind secrets do not reliably implement `uid` or
`mode`. For rootless/user-namespace Docker, map ownership to the corresponding
host UID and verify readability before startup; do not use world-readable modes.
Preserve any existing key: never regenerate it during upgrades.
The proxy image removes its unnecessary low-port file capability and sets
/data and /config ownership to UID/GID 1000 at build time,
so fresh named volumes inherit writable ownership without a root runtime.
Existing root-owned volumes require an explicit offline ownership migration;
rebuilding alone does not change existing volume ownership.
Set `ANONCE_SOURCE_URL` to publicly accessible complete corresponding source for
the exact deployed version, including modifications and build instructions, to
satisfy AGPL network-source obligations. The repository URL alone is insufficient
if it does not contain the deployed version. Operators must verify that their
configured URL supplies the exact complete corresponding source.
The browser visibly offers this configured URL on desktop and mobile; operators
must ensure the destination actually supplies their corresponding source.

```sh
docker compose config --quiet
docker compose build
docker compose up -d
```

The local image/runtime checks do not establish public DNS, certificate issuance,
or production Compose deployment success.
Caddy terminates same-origin TLS; only Caddy publishes ports. PostgreSQL is on
an internal network. Caddy strips listed identity headers on anonymous routes;
backend must ignore transport identity and all unrecognized identity headers.
Do not add access logs, request tracing, or identifying database statement logs.
The host/network can still observe timing and addresses; this is not protection
against malicious served code or traffic correlation.

## Backup and restore

PostgreSQL 18 mounts `pgdata` at `/var/lib/postgresql`.

A disposable custom-format backup/restore exercise matched all 14 table counts
and sorted SHA-256 row digests, including ciphertext/receipt digests. This is not
evidence of encrypted off-host backup handling or production disaster recovery.

Stop writes (`docker compose stop app`) for a coordinated backup. With restrictive
local permissions, dump the database:

```sh
docker compose exec -T db pg_dump -U anonce_admin -d anonce -Fc > anonce.dump
```

Encrypt backups before off-host storage; restrict access and retention. Back up
the server key separately in encrypted storage: database-only recovery is not
sufficient. Preserve role initialization/configuration securely, too. Never
commit dumps or secrets. Test restores on an isolated environment with no public
ingress, using matching roles and the matching key:

```sh
docker compose exec -T db pg_restore -U anonce_admin -d anonce --exit-on-error < anonce.dump
```

Restore into a fresh initialized database, not over live data. Verify grants,
integrity, migration versions, and application behavior before reopening access.
