<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Operations (pre-release)

- **Not approved for sensitive production data.** Validate the current revision and deployment against the [release gates](../CONTRIBUTING.md#verification-and-release-gates).

| Prerequisite    | Contract                                                                                              |
| --------------- | ----------------------------------------------------------------------------------------------------- |
| Runtime         | Docker Compose v2; PostgreSQL `18.7-alpine3.24`; Go 1.27.4 and Node.js 26.13.1 image build toolchains |
| Public ingress  | DNS for one domain; inbound TCP 80/443; optionally allow UDP 443 for HTTP/3                           |
| Published ports | Compose publishes TCP 80/443 and UDP 443 through Caddy only                                           |
| User flows      | Browser-only, same-origin HTTPS                                                                       |

## Service ownership

- Docker Compose v2 is the supported container deployment entry point.
- Build and proxy configuration lives in `docker/`: `Dockerfile` and `Caddyfile`.
  The deployment `compose.yaml` and `.dockerignore` stay at the repository
  root; image builds use that root as their context.
- PostgreSQL and Caddy service code is maintained upstream.
- This project maintains the application, Compose configuration, database role
  initialization, Caddy configuration, image pins, and minimal deployment wrappers.
- PostgreSQL uses the upstream image. Its Compose wrapper checks for nonempty
  initialization scripts before invoking the upstream entrypoint.
- The Caddy image derives from the pinned upstream image without source patches.
  It only adjusts volume ownership and removes the low-port file capability to
  support the non-root runtime described below.
- Operators review security advisories, validate image updates, and maintain
  deployment security and backups.

## Deployment contracts

- PostgreSQL 18 uses backend-owned initialization scripts in `db/init` by default; `ANONCE_DB_INIT_DIR` can override that directory.
- Before startup, confirm it contains nonempty reviewed scripts, not an empty placeholder.
- They must create distinct member and anonymous login roles using the supplied role passwords, with no superuser, database creation, or role creation permissions.
- Restrict anonymous grants to its contract; no membership tables. `DATABASE_URL` uses the member role, never `anonce_admin`; `ANON_DATABASE_URL` uses the restricted anonymous role.
- Initialization runs only on empty volumes.
- Backend installs the current `db/schema.sql` in one transaction, guarded by an
  advisory lock. A schema-version marker makes repeated startup a no-op.
- The current schema version is 3. Initialization accepts an empty database or
  the current schema; unsupported schema markers or versions are rejected, not modified.
  Database upgrades and data transfer are unsupported.
  Use a new, unused `ANONCE_DB_VOLUME` for a fresh database.
  Preserve existing volumes and backups if their data matters.
- The role names are `anonce_member` and `anonce_anon`, using `ANONCE_MEMBER_DB_PASSWORD` and `ANONCE_ANON_DB_PASSWORD`, respectively.
- Confirm actual grants against the backend contract before deployment.

- The binary is `./cmd/anonce`, listens on `ANONCE_ADDR=:8080`, serves `ANONCE_WEB_DIR=/app/web`, and reads `ANONCE_KEY_FILE=/run/secrets/server_key`.
- That file contains the unpadded base64url encoding of exactly 32 random bytes for the server ChaCha master key, not client keys.
- Backend must set member cookies with Path=/api/member and strict security headers, including a self-only CSP permitting `wasm-unsafe-eval` where necessary, never general `unsafe-eval`.
- Browser build uses `scripts/build.mjs` and emits `web/crypto.bundle.js`, retaining the vanilla app/API/UI files.

## First setup (review deployment prerequisites first)

### Configuration

Copy `.env.example` to `.env`; fill every blank with strong distinct credentials,
correct role URLs (URL-encode passwords), deployment hostname, and reviewed init path.

| Variable                                               | Required / default                                           | Purpose                                                                 |
| ------------------------------------------------------ | ------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `ANONCE_DOMAIN`                                        | Required; e.g. `anonce.local` or `feedback.example.org`      | Hostname only; Compose derives `ANONCE_ORIGIN=https://<host>`           |
| `ANONCE_SOURCE_URL`                                    | Required                                                     | Exact complete corresponding deployed source                            |
| `POSTGRES_PASSWORD`                                    | Required; blank example                                      | Database administrator password                                         |
| `ANONCE_MEMBER_DB_PASSWORD`, `ANONCE_ANON_DB_PASSWORD` | Required; blank example                                      | Distinct initialization role passwords                                  |
| `DATABASE_URL`, `ANON_DATABASE_URL`                    | Required; blank example                                      | Matching member and restricted anonymous URLs; percent-encode passwords |
| `ANONCE_DB_INIT_DIR`                                   | Default `./db/init`                                          | Reviewed nonempty initialization scripts                                |
| `ANONCE_DB_VOLUME`                                     | Optional; `<Compose project>_pgdata`                         | Persistent database volume; a new unused name initializes empty data    |
| `ANONCE_SERVER_KEY_FILE`                               | Required; example `./secrets/server_key`                     | Host master-key file                                                    |
| `ANONCE_RECEIPT_TRUST_FILE`                            | Optional; empty                                              | Container path to separately mounted public trust document              |
| `ANONCE_ADDR`, `ANONCE_WEB_DIR`, `ANONCE_KEY_FILE`     | Compose fixes `:8080`, `/app/web`, `/run/secrets/server_key` | Internal runtime settings, not `.env` overrides in this Compose file    |

### Review and response limits

- Limits are optional; the browser receives effective values from `/api/public/config`.
- Text and JSON limits measure UTF-8 bytes, not characters. Response limits include
  the 16-byte authentication tag, before base64url encoding.

| Variable                       | Default / maximum | Minimum |
| ------------------------------ | ----------------: | ------: |
| `ANONCE_MAX_QUESTIONS`         |               500 |       1 |
| `ANONCE_MAX_REVIEW_BYTES`      |            524288 |    1024 |
| `ANONCE_MAX_DESCRIPTION_BYTES` |             65536 |       1 |
| `ANONCE_MAX_RESPONSE_BYTES`    |            524288 |    1024 |

- Only reductions within these protocol ceilings are supported. Description bytes
  must not exceed review bytes. Invalid settings fail startup before database access.
- Omit a setting to use its default; empty or malformed values are invalid.
- Question labels remain capped at 2000 bytes; each question permits at most 100
  choices with 1000-byte labels. The aggregate review limit still applies.
- Dependent protocol ceilings are fixed: descriptors 768 KiB, anonymous/public API
  bodies 1 MiB, and authenticated pending plaintext padding exactly 1 MiB.
- Lowering limits can prevent updates or new submissions using existing larger
  objects. Coordinate changes with active reviews and outstanding retries.

Generate the server key locally using an operator CLI:

- **Only generate a key for a new deployment.**
- **The command overwrites an existing file.**
- **Never regenerate the key during an upgrade or restore.**

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

- The earlier `umask 077` alone leaves the key owned by the operator and unreadable to container UID 65532.
- Compose bind secrets do not reliably implement `uid` or `mode`.
- For rootless/user-namespace Docker, map ownership to the corresponding host UID and verify readability before startup; do not use world-readable modes.

- Preserve any existing key: never regenerate it during upgrades.
- Startup opens the key without following a final-component symlink and requires a regular file owned by the effective runtime UID, with no group or other permission bits.
- The loader bounds input to 4096 bytes and requires a canonical base64url-encoded 32-byte key after trimming surrounding whitespace.
- Keep parent directories trusted; the loader does not reject symlinks in parent components.
- The proxy image removes its unnecessary low-port file capability and sets
  /data and /config ownership to UID/GID 1000 at build time,
  so fresh named volumes inherit writable ownership without a root runtime.
- Existing root-owned volumes require an explicit offline ownership migration;
  rebuilding alone does not change existing volume ownership.
- Set `ANONCE_SOURCE_URL` to publicly accessible complete corresponding source for the exact deployed version, including modifications and build instructions, to satisfy AGPL network-source obligations.
- The repository URL alone is insufficient if it does not contain the deployed version.
- The browser displays this URL on desktop and mobile; verify that it supplies
  the required source.

### Start the deployment

Use the same Compose file and Caddyfile for development and public deployment.
After configuring `.env` and key permissions above, select `ANONCE_DOMAIN`:

- Local: use `anonce.local` and map it to the Docker host on each client.
- Public: use a publicly resolvable domain, configure its DNS to reach the host,
  and permit inbound TCP 80/443.
- Caddy automatically uses its local CA for `.local` names and localhost, and
  public certificate automation for eligible public domains. No TLS mode flag
  or separate configuration file is needed.
- **Published ports bind all interfaces by default, not just loopback.**
  Restrict host firewall access before starting, especially for local testing.

```sh
docker compose config --quiet
docker compose up -d --build
```

#### Trust local HTTPS

- Local certificates are not publicly trusted. The container cannot install
  trust into host or client browsers automatically.
- Export only Caddy's public local root certificate: inspect the running `caddy` container's `/data` volume for its `pki/authorities/local/root.crt`, then use `docker compose cp caddy:<confirmed-path> ./anonce-local-ca.crt`.
- Do not copy `root.key` or the entire volume.
- Confirm the certificate fingerprint through a trusted operator channel before importing it into each client's trust store.
- This trusts certificates issued by that local CA; remove trust when done.

#### Persistent state and runtime boundaries

- Keep the same Compose project name to preserve Caddy's TLS volumes.
  Use the same project selection for every command; a changed hostname does not
  require a new project.
- A new unused `ANONCE_DB_VOLUME` initializes an empty database; rebuilding does not reset data.
- Before switching volumes, build images, stop writes, and take a protected backup.
- Preserve the previous image, volume, and matching server key for rollback.
- Do not delete the old volume or run `down -v`.

- The local image/runtime checks do not establish public DNS, certificate issuance,
  or production Compose deployment success.
- Caddy terminates same-origin TLS; only Caddy publishes ports.
- PostgreSQL is on an internal network.
- Compose waits for application readiness before starting Caddy.
- The application readiness probe checks both database roles; an unhealthy status after startup does not automatically restart the container or stop Caddy.
- Compose allows 30 seconds for application shutdown, including its 15-second HTTP drain.
- Caddy strips listed identity headers on anonymous routes; backend must ignore transport identity and all unrecognized identity headers.
- Do not add access logs, request tracing, or identifying database statement logs.
- The host/network can still observe timing and addresses; this is not protection
  against malicious served code or traffic correlation.

## Troubleshooting

- Use the same Compose project selection as startup.
- Never print resolved secret configuration or attach keys, dumps, or credentials to reports.

| Symptom                             | Safe check / action                                                                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Compose rejects configuration       | Run `docker compose config --quiet`; compare required variable names with `.env.example`, not a shared resolved-config dump         |
| Database initialization rejected    | Confirm the configured init directory contains reviewed nonempty scripts; initialization only runs on an empty volume               |
| Changed role password has no effect | Existing volumes do not rerun initialization; do not delete data to fix credentials                                                 |
| App fails to read key               | Check runtime UID mapping, regular-file ownership and mode `0400`; never fix with world-readable permissions                        |
| Local HTTPS untrusted/unreachable   | Check hosts mapping, firewall, published ports and verified local CA trust; do not disable public TLS validation                    |
| Proxy cannot write existing volumes | Check `/data` and `/config` ownership offline; rebuilding does not change existing root-owned volumes                               |
| Services not ready                  | Run `docker compose ps`; check database health, matching role URLs, configured origin and key access without exposing secret values |

## Backup and restore

PostgreSQL 18 mounts `pgdata` at `/var/lib/postgresql`.

Use the same Compose project selection as startup in every command below.
`anonce_admin` is the operator dump/restore role, not either runtime connection.

- Validate disposable restores against the backup using table counts and sorted
  SHA-256 row digests, including ciphertext and receipts.
- A local restore alone does not establish encrypted off-host backup handling or
  production disaster recovery.

- Stop writes (`docker compose stop app`) for a coordinated backup.
- With restrictive local permissions, dump the database:

```sh
docker compose stop app
umask 077
docker compose exec -T db pg_dump -U anonce_admin -d anonce -Fc > anonce.dump
```

- Encrypt backups before off-host storage; restrict access and retention.
- Back up the server key separately in encrypted storage: database-only recovery is not sufficient.
- Preserve role initialization/configuration securely, too.
- Never commit dumps or secrets.
- Test restores on an isolated environment with no public ingress, using matching roles and the matching key:

```sh
docker compose exec -T db pg_restore -U anonce_admin -d anonce --exit-on-error < anonce.dump
```

- Restore into a fresh initialized database, not over live data.
- Restore only a backup matching the current schema version; startup does not upgrade it.
- Verify grants, integrity, schema version, and application behavior before reopening access.

### Key continuity and rotation limits

- Restore the database and its matching server master key together.
- Preserve the deployment ID, membership CA public key, and receipt public key identity across restart and restore; verify that existing encrypted issuer keys still open.
- Table counts alone do not establish signing-key continuity or recoverability.

- Replacing the master-key file is not a rotation procedure: existing server and issuer private keys are encrypted under keys derived from that master key and deployment ID.
- A future master-key rotation must re-encrypt every affected key transactionally, retain public identities, and include a tested recovery plan.
- No automatic master-key rotation or production backup validation is provided.

### Receipt verification keys

- Without additional configuration, public configuration publishes only the current receipt public key.
- To retain verification of receipts signed by an explicitly approved historical key, set `ANONCE_RECEIPT_TRUST_FILE` to a bounded operator-controlled public trust document using the schema in [protocol.md](protocol.md).
- The document must include the deployment's current key and matching deployment ID.
- The loader accepts at most 1 MiB, requires a regular file owned by root or the effective service UID, rejects final-component symlinks, and rejects group/world write permission.
- Historical keys come from this file, not from database rows or receipt-supplied fields.
- This is verification-key configuration, not a signing-key rotation command.

- For optional Compose trust configuration, add a read-only bind mount to the
  `app` service in an operator-owned Compose override and set the variable to
  that container path. Setting the variable alone does not mount the file.
- Apply that override consistently to all Compose commands. It is separate from
  the shared local/public TLS configuration.
- Do not mount a private-key directory.
- Keep the file and its parent directories protected from untrusted writes.
- Distribute trust documents through an independently trusted channel; retain trusted copies with receipts.
- Removing a historical key makes its receipts unverifiable with that keyring; do not remove keys casually.
