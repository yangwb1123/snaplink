// Package postgres implements the SDK's DURABLE storage SPIs against a
// Postgres-wire database — plain PostgreSQL (HA via Patroni / managed RDS /
// pgbouncer) or CockroachDB (natively distributed, multi-region). It is the
// "db cluster" half of the HA design: the system-of-record stores (users,
// clients, consent, permissions, tenants, audit, …) that must survive a total
// Redis/replica loss and be queryable, while the hot/ephemeral stores live in
// the redis module.
//
// Design choices (and why):
//
//   - database/sql + the pgx/v5 stdlib driver (not native pgxpool): the SQLite
//     backends this mirrors are written against database/sql, so reusing it
//     gives a 1:1 port — critical for faithfully reproducing the single-use /
//     family-reuse atomicity of the token stores. SQLSTATE is still reachable
//     via errors.As(*pgconn.PgError) for the serialization-failure (40001)
//     retry CockroachDB needs.
//   - dialect-aware [Run] migrate runner alongside platform/migrate (whose
//     BEGIN IMMEDIATE / sqlite_master are SQLite-only): Postgres serializes
//     concurrent replica boots with pg_advisory_xact_lock; CockroachDB (no
//     advisory locks) leans on SERIALIZABLE + a bounded 40001 retry. Both
//     discover version tables via information_schema and use $N placeholders.
//   - Unix-nanosecond int64 columns stay BIGINT (NOT timestamptz): preserves
//     the exact nanosecond round-trip and the oracle-resistant "expired is
//     indistinguishable from missing" expiry semantics the SQLite peer relies
//     on.
//
// Separate go.mod so pgx never enters the core module's dependency graph; the
// stores satisfy the SAME core SPIs as infrastructure/defaultimpl/sqlite, so
// cmd selects them with backend: postgres exactly like backend: sqlite.
package postgres
