# Migration rehearsal (owned, local, repeatable)

`make migration-rehearsal` runs the whole SQLite → PostgreSQL migration rehearsal
against a disposable, owned PostgreSQL candidate. It is engineering evidence
only: it does **not** authorize cutover, production contact or a 30-day claim.

## What the command does

One invocation performs, in order:

1. `provision` — starts the digest-pinned PostgreSQL image with loopback-only
   binding, 1 GiB memory/swap, 2 CPUs and tmpfs-only storage, then proves
   ownership from the live `docker inspect` result.
2. `schema_init` — creates `snaplink_mig_<name>_cand`, its
   `migration_guard.ownership` row and the canonical schema built by the
   supplied initializer.
3. `import` — binds the pinned snapshot's digest and the target shape to the
   supplied policy template, generates the schema contract and a one-hour
   candidate-only intent, then imports through the guard.
4. `verify` — re-reads the candidate under a read-only repeatable-read snapshot
   and compares content and sequence state with the source projection.
5. `replay_guard` (opt-in) — re-runs the import and requires it to be refused
   with all table counts unchanged.
6. `drift_check` (opt-in) — compares `schema_migrations*` row counts with what
   the import recorded; runtime store migrations must not add native history.
7. `readpath` (opt-in) — reads migrated rows through the server's own stores
   and compares them with expectations derived from the source.
8. `smoke` (opt-in) — boots the real `sso-server` against the candidate and
   probes `/health`, discovery and JWKS, then requires a clean SIGTERM exit and
   a closed port.
9. `write_check` (opt-in) — writes one audit row and requires the migrated
   sequence to advance past the historical maximum. This step mutates the
   disposable candidate and always runs last.
10. `close` — always attempted, including after a failed step: it re-proves
   ownership, removes only the owned container, verifies the port is refused and
   deletes private inputs.

## Required and optional inputs

| Variable | Required | Meaning |
| --- | --- | --- |
| `SNAPSHOT` | yes | pinned SQLite backup |
| `SNAPSHOT_SHA256` | yes | its exact digest |
| `POLICY_TEMPLATE` | yes | version 2 policy naming the conversion decisions; the source and target-shape digests are bound mechanically |
| `BASE_COMMIT` | yes | 40-hex commit the schema was reviewed from |
| `SCHEMA_INIT` | yes | prebuilt schema initializer for that revision |
| `REHEARSAL_ROOT` | yes | private `0700` working directory |
| `REHEARSAL_CONTAINER` / `REHEARSAL_LABEL` / `REHEARSAL_DATABASE` | yes | owned container identity and dedicated `snaplink_mig_*` database |
| `REPLAY_GUARD`, `DRIFT_CHECK`, `WRITE_CHECK` | no | enable the corresponding steps |
| `REHEARSAL_READPATH`, `REHEARSAL_READPATH_EXPECT` | no | prebuilt `cmd/migration-readpath` and its expectation JSON |
| `REHEARSAL_SSO_SERVER` | no | prebuilt `sso-server` for the smoke step. `SSO_*` names are avoided: the server maps them into its own config tree |

## Evidence

Everything lands in `REHEARSAL_ROOT`: `orchestration.json` (step verdicts and
cleanup outcome), `import-report.json`, `verify-report.json`,
`replay-guard.json`, `readpath-report.json`, `smoke-facts.json`,
`write-check.json` and `cleanup-receipt.json`, plus the generated `policy.json`,
`schema-contract.json` and `intent.json`.

## Guarantees and non-claims

Guaranteed: a scrubbed child environment for the server (rehearsal variables cannot become server config), fail-closed step ordering, a refused populated replay, and cleanup
of the owned container even when a step fails. A foreign container is never
provisioned over or removed.

Not claimed: a full row-by-row sweep (the read path samples rows and compares
per-table counts), TLS, multi-replica or Redis behaviour, authenticated HTTP
flows, cutover approval, or any production or 30-day observation. Credentials in
this dataset are bcrypt hashes, so an authenticated migration smoke requires a
known secret or a rotation rather than reading one out of the source.
