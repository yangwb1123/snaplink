# Cutover to PostgreSQL (operator runbook)

The rehearsal proves the data moves; this is the part that moves the *service*.
It records the three failures that cost real time on the first attempt here, so
the next cutover does not repeat them.

## Order

1. Rehearse on a candidate (see `MIGRATION_REHEARSAL.md`), then verify with
   `remote-upgrade-verify.sql`: tables, row counts, schema versions and the
   previously missing families must all read PASS.
2. Build the new config from the live one: `identity.backend`,
   `identity.session_backend`, `oauth.backend`, `permissions.backend`,
   `self_service.password.backend` and `audit.backend` to `postgres`, plus the
   top-level `postgres.dsn`.
3. `-validate-only` the new config, then boot it **on a spare port** before
   touching the live one. A config that validates can still fail to serve.
4. Flip the release and the config, restart, then check `/health`, discovery,
   JWKS, one login → token → admin 401/200, and that a login writes a row.
5. Keep the previous release, the previous config and the previous database.

## Three failures that are not obvious

**1. A relative `bootstrap.state_path` cannot work under hardening.**
`ProtectHome=read-only` (or `ProtectSystem=strict`) makes the working directory
read-only, so the tracker write fails and the boot dies on the first *new*
bootstrap step — an upgrade that has been running for weeks will not start.
Point `state_path` at a writable absolute path.

**2. The tracker belongs to a database, not to a deployment.**
Switching `postgres.dsn` to another database while keeping the tracker makes
every already-applied step look done, so data-affecting steps are silently
skipped. On the first attempt this left the console client without
`offline_access`: logins that ask for it returned `400 invalid_scope` while the
server believed it had granted the scope. Give each database its own tracker
file.

**3. A newer `pg_dump` produces SQL an older server rejects.**
A PG16 client dumps `SET transaction_timeout = 0;`, which PG15 fails with
`unrecognized configuration parameter`. The restore stops after the preamble and
you get an empty database that still "succeeded". Dump in plain format, drop that
line, and assert the table count after the restore.

## Verification that is worth doing

- Row counts per table, before and after, compared explicitly (not eyeballed).
- One authenticated flow end to end, including the refresh token, because a
  missing scope surfaces exactly there.
- One write that proves the backend is the database and not a process cache:
  a login that increments `refresh_tokens` and `audit_events`.
- A restart, then the same counts. If they move, something was still in memory.

## What this does not cover

Multi-replica, TLS, Redis, connection pooling, backup/restore drills at scale,
or the 30-day behaviour. `remote_upgrade.sh` automates the mechanics but has only
been rehearsed against disposable candidates.

## Fourth failure: the restart itself can be denied

The cutover script swapped the release and the config, then `systemctl restart`
returned `Access denied` — the unit is system-scoped, so it needs elevation. The
script exited before its rollback branch, which left a new binary and a new
config installed while the old process kept running with the previous config in
memory. Nothing broke only because the service was restarted by hand moments
later.

Two rules follow: control the service through one helper that falls back to
`sudo -n`, and install an `ERR` trap that restores the previous binary and
config whenever any later step fails. Verify with `readlink current` **and** the
process start time, not just `/health` — the old process answers `/health` too.
