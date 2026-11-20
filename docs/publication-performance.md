<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Publication performance

## What the benchmarks measure

- Component benchmarks and live publication measure different paths; do not add
  their timings together or treat either as a capacity guarantee.
- The [component benchmarks](member-key-delivery.md#publication-scale-benchmarks)
  isolate browser-compatible cryptography in Node and PostgreSQL storage.
- The live harness runs the actual browser `publishReview` flow through
  Chromium, HTTPS/Caddy, the Go service, and PostgreSQL. Recipient certificates,
  signed key bindings, HPKE encryption, uploads, and finalization are real.
- Synthetic membership provisioning, account registration, and draft creation
  are outside the publication timer. Fixture accounts are not usable test users;
  their private keys are discarded after generating valid public bindings.
- Rate limits remain enabled. The harness can wait after HTTP 429 and retry the
  same pending publication; this is harness-assisted recovery, not automatic
  product backoff or cross-device resume.
- One publication at a time measures latency, not concurrent-user capacity.
  Loopback networking does not represent remote networks or mobile devices.

## Reference workload and findings

- Application baseline: `a64a103`, with the benchmark tooling added separately.
  No publication implementation or default rate-limit changes are used.
- Environment: Linux x86-64, AMD Ryzen 9 7940HS exposed as 6 logical CPUs,
  approximately 5.8 GiB host RAM, Chromium 159.0.8154.6, Node 26.13.1,
  and the container limits below. PostgreSQL uses `18.7-alpine3.24`.
- Workload: one creator, unique valid synthetic recipient identities, and one
  short required text question. Sizes run sequentially in separate organizations
  on the same disposable deployment; the database is not reset between sizes.
- These are single-pass reference observations, not medians, percentiles, a
  regression threshold, or a general deployment capacity claim.

| Approved members | Live publication wall time | API requests | Sampled renderer JS heap peak |
| ---------------- | -------------------------- | ------------ | ----------------------------- |
| 1000             | 3.27 seconds               | 47           | 19.1 MiB                      |
| 10000            | 33.75 seconds              | 407          | 43.0 MiB                      |
| 100000           | 335.40 seconds             | 4007         | 46.0 MiB                      |

- Every observed API request returned HTTP 200; no HTTP 429 or harness wait was
  needed. Normal rate limits were enabled, but these observations do not test
  throttled recovery.
- Each publication had exactly the requested envelope count, zero remaining
  staging rows, decryptable creator content, and only the creator's own envelope
  in its review response. Anonymous database queries against member account,
  membership, and envelope tables were denied.
- Recipient pages and uploads never exceeded 100 entries. Plaintext marker
  scans and exact payload-field checks passed. These targeted checks do not
  prove absence of every possible metadata or plaintext leak.
- At 100000 members, request bodies totaled about 33.39 MB and decoded response
  bodies about 90.49 MB, excluding headers and transport overhead.
- The 100000-member request count comprises 1000 recipient pages, 1000 uploads,
  1002 challenges, one start, one finalize, and 1003 other authenticated reads.
  At the reference baseline, `reviewKeys` fetched vault data again for each
  recipient page.
- Observed request-to-body-completion totals at that size were approximately
  199.3 seconds for recipient pages, 90.1 seconds for other reads, 17.6 seconds
  for uploads, 11.5 seconds for challenges, 10.3 seconds for snapshot start,
  and 4.8 seconds for finalization. These include client observation overhead
  and are not isolated server or cryptographic CPU profiles.
- Around 1000 members is plausible for an interactive flow with feedback.
  Around 10000 members needs visible progress and reliable retry handling;
  100000 members takes over five minutes and is not a fast interactive
  experience. Product acceptance still needs an explicit latency target.
- These observations suggest profiling recipient transfer and repeated vault reads before
  assuming cryptography dominates. Node component timings do not establish
  the actual browser bottleneck. Reusing authenticated creator keys within one
  publication is a candidate optimization, not a result established by this
  reference run.

## Reproduce a live benchmark

1. Install the pinned dependencies with `npm ci` and install Playwright Chromium.
2. Generate a disposable server key and database passwords outside the repository.
   Follow the server-key file requirements in [operations](operations.md).
3. Set the variables required by
   `scripts/compose.publication-benchmark.yaml` in a private environment file.
   Use database name `anonce_publication_benchmark`; never use an existing
   deployment's credentials, keys, or volumes.
4. Start the standalone project from the repository root:

   ```sh
   docker compose -p anonce-publication-perf \
     -f scripts/compose.publication-benchmark.yaml \
     --env-file /absolute/benchmark.env up -d --build --wait
   ```

5. Export the matching host-side fixture configuration, then run:

   ```sh
   export ANONCE_E2E_ORIGIN=https://localhost:18443
   export ANONCE_E2E_ALLOW_SELF_SIGNED=1
   export ANONCE_BENCHMARK_KEY_FILE=/absolute/disposable-server-key
   # Set ANONCE_BENCHMARK_DATABASE_URL and
   # ANONCE_BENCHMARK_ANON_DATABASE_URL using the matching role passwords,
   # 127.0.0.1:15432, and database anonce_publication_benchmark.
   node scripts/publication-live-benchmark.mjs --run
   ```

   The default sizes are 1000, 10000, and 100000. To select a subset, set
   `ANONCE_BENCHMARK_SIZES=1000,10000`. The harness creates a new benchmark
   organization for each size and verifies exact envelope coverage afterward.

- The standalone configuration exposes only loopback HTTPS port 18443 and
  PostgreSQL port 15432. Run it standalone; do not merge it with `compose.yaml`
  or deployment-specific overrides.
- Unlike the deployment's internal-only database network, the benchmark uses a
  project-owned ordinary bridge so the host-side fixture can connect to the
  explicitly loopback-published PostgreSQL port. Do not copy this fixture
  connectivity configuration into a production deployment.
- PostgreSQL is limited to 1 CPU/1 GiB, the app to 1 CPU/512 MiB, and Caddy to
  0.5 CPU/256 MiB. The browser runs on the host and has no equivalent CPU limit.
- Set `ANONCE_BENCHMARK_UID` and `ANONCE_BENCHMARK_GID` to the host fixture
  user's IDs when they differ from 1000. This isolated app uses the same
  unprivileged UID as the fixture so both can read the owner-only disposable
  server-key file; production image user and key checks are unchanged.
- Fixtures require an explicit opt-in, loopback origin, the dedicated database
  name, and benchmark organization/account markers. They use the same server
  implementation to load the disposable CA; no key-export API is added.
- Keep raw execution logs and machine/resource metadata as review or CI
  artifacts, not checked-in execution diaries.
- When finished, remove only this disposable project's containers and volumes:

  ```sh
  docker compose -p anonce-publication-perf \
    -f scripts/compose.publication-benchmark.yaml \
    --env-file /absolute/benchmark.env down --volumes
  ```

## Interpretation limits

- Request-body and response-body byte counts are not total network traffic:
  HTTP headers, TLS framing, and transport overhead are separate.
- Browser heap observations are not whole-browser peak RSS, and sampled values
  can miss short-lived peaks.
- A successful publication proves only the exercised path and assertions.
  It does not establish production readiness, cryptographic audit, broad
  accessibility coverage, or multiuser throughput.
