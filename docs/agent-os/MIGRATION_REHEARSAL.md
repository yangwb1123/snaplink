# Migration rehearsal (owned, local, repeatable)

`make migration-rehearsal` runs the whole SQLite → PostgreSQL migration rehearsal
against a disposable, owned PostgreSQL candidate. It is engineering evidence
only: it does **not** authorize cutover, production contact or a 30-day claim.

## What the command does

One invocation performs, in order:

1. `provision` — starts the digest-pinned PostgreSQL image with loopback-only
   binding, 1 GiB memory/swap and 2 CPUs, then proves ownership from the live
   `docker inspect` result. Storage is tmpfs by default; `DURABLE_STORAGE=1`
   uses one labelled named volume instead, so fsync/persistence behaviour can
   be exercised on a real filesystem. A volume is only adopted when it carries
   the rehearsal's own owner label, and it is removed on close.
2. `schema_init` — creates `snaplink_mig_<name>_cand`, its
   `migration_guard.ownership` row and the canonical schema built by the
   supplied initializer.
3. `import` — binds the pinned snapshot's digest and the target shape to the
   supplied policy template, generates the schema contract and a one-hour
   candidate-only intent, then imports through the guard.
4. `verify` — re-reads the candidate under a read-only repeatable-read snapshot
   and compares content, sequence state and the schema contract facets
   (including declared foreign keys) with the source projection.
5. `replay_guard` (opt-in) — re-runs the import and requires it to be refused
   with all table counts unchanged.
6. `concurrency_guard` (opt-in) — runs two imports against one fresh
   candidate at the same time and requires at most one to apply, with row
   counts equal to a single import.
7. `determinism` (opt-in) — imports the same snapshot into a second owned
   candidate and requires identical per-table content digests, so a
   nondeterministic projection or ordering cannot pass unnoticed.
8. `drift_check` (opt-in) — compares `schema_migrations*` row counts with what
   the import recorded; runtime store migrations must not add native history.
9. `readpath` (opt-in) — reads migrated rows through the server's own stores
   and compares them with expectations derived from the source.
10. `smoke` (opt-in) — boots the real `sso-server` against the candidate and
   probes `/health`, discovery and JWKS, then requires a clean SIGTERM exit and
   a closed port.
11. `write_check` (opt-in) — writes one audit row and requires the migrated
   sequence to advance past the historical maximum. This step mutates the
   disposable candidate and always runs last.
12. `close` — always attempted, including after a failed step: it re-proves
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
| `REPLAY_GUARD`, `CONCURRENCY_GUARD`, `DETERMINISM`, `AUTH_SMOKE`, `DRIFT_CHECK`, `WRITE_CHECK`, `DURABLE_STORAGE` | no | enable the corresponding steps |
| `REHEARSAL_READPATH`, `REHEARSAL_READPATH_EXPECT` | no | prebuilt `cmd/migration-readpath` and the expectation **file** it compares against (a JSON snapshot, not a case count) |
| `REHEARSAL_SSO_CTL` | no | prebuilt `sso-ctl`, used to hash the auth-smoke admin password |
| `REHEARSAL_SSO_SERVER` | no | prebuilt `sso-server` for the smoke and auth-smoke steps. `SSO_*` names are avoided: the server maps them into its own config tree |

Two inputs are rejected rather than guessed, and both failures are easy to
hit: `REHEARSAL_DATABASE` must match `snaplink_mig_[a-z0-9_]{1,32}` (anything
else fails `rehearsal_dedicated_candidate_database_required` before a container
is created), and `REHEARSAL_READPATH_EXPECT` is a file path (passing `40` makes
the read-path tool report `expectation unreadable`).

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
per-table counts), TLS, multi-replica or Redis behaviour, cutover approval, or
any production or 30-day observation. Credentials in this dataset are stored as
bcrypt hashes, so the authenticated HTTP smoke (`AUTH_SMOKE=1`) needs a known
secret from `REHEARSAL_SSO_CTL` rather than one read out of the source.

## Bootstrap admin credential (gap closed)

A rehearsal with `bootstrap.disabled: false`, `permissions.backend: postgres`
and `authenticators.password.enabled: true` boots on the migrated candidate and
seeds the admin user, the confidential `sso-admin` client, the public
`sso-admin-console` PKCE client and the `sso-admin` role.

`stepSeedAdminUser` now hands the generated password to the credential store
(`SetPassword`) before printing it, prints nothing when no store is wired, and
fails closed when the store rejects it. The role grant is applied to every configured admin
client scope (including the console) and is re-applied for a pre-existing admin
user, which a migrated deployment always has. Nothing is written into user
attributes, so there is no plaintext oracle to rotate away later.

Consequence: the authenticated HTTP surface **is** rehearsed. `AUTH_SMOKE=1`
requires the exact verdict `login 200 → token 200 → admin without token 401 →
admin with token 200` (the string `login 200` is the literal verdict key), and
refuses a missing credential or fact rather than reporting a partial pass. On a migrated candidate the seeded banner stays
silent by design, so the rehearsal accepts a known credential produced by
`REHEARSAL_SSO_CTL` (`sso-ctl hash --quiet`, password on stdin) instead of
reading one out of the source.

Still not claimed: password rotation policy, MFA, or any UI-driven login.

## Long-running observation (soak)

`ops/scripts/soak.py` reuses the rehearsal's provision/import/verify path and
then keeps a real `sso-server` up, appending one probe record per interval to
`<root>/observations.jsonl`. It is an observer, not a capacity test: one health
call, one login/token/admin sequence and row-count comparisons per cycle, with
nothing sent off the machine.

Decisions baked in (override on the command line, not by editing the script):

| Question | Default | Why |
| --- | --- | --- |
| What is observed | a dedicated rehearsal candidate (`snaplink_mig_*`) with a real `sso-server`, never the local systemd stack | the stack is someone's working environment; a soak that perturbs it is not reproducible |
| Candidate source | the pinned snapshot re-imported by the rehearsal path | the same import the migration ships, not a hand-built database |
| Outbound reporting | none | an unrequested external send is a side effect nobody approved |
| Window | explicit `--days` plus `--deadline`, no renewal on restart | a restart must not silently reset the budget |

Refusals: it will not start without `--authorize I-ACCEPT-THE-SOAK-BUDGET`, a
1–90 day budget, an interval of at least 60s, log ≤64 MiB and disk ≤2 GiB.
Stop conditions: server exit, health ≠ 200, authentication regression, a fixed
table changing, an append-only table shrinking, a schema-version change, or a
budget breach. Cleanup removes only the container it provisioned.

