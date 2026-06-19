// Package migrate is a minimal, dependency-free schema-migration runner
// for the SDK's SQLite backends.
//
// Until now every SQLite backend created its tables with a one-shot
// `CREATE TABLE IF NOT EXISTS` block at construction — no version
// tracking, no path to evolve a column or index on an already-deployed
// database. This runner adds versioned, ordered, forward-only
// migrations while keeping that adoption painless: the existing schema
// becomes migration version 1 (the "baseline"), so an already-populated
// database simply no-ops the idempotent baseline and gets stamped v1,
// while a fresh database has the schema created — both converge to the
// same recorded version.
//
// Design choices (and why):
//
//   - Per-namespace version table (schema_migrations_<namespace>): the
//     cluster-shared deployment points multiple SDK backends at one
//     SQLite file, so each backend MUST track its own version
//     independently or they'd clobber a shared table.
//   - Single BEGIN IMMEDIATE transaction wrapping all pending
//     migrations: takes the write lock up front so concurrent replicas
//     starting together serialize cleanly (the loser waits on
//     busy_timeout, then sees the work already done and no-ops) instead
//     of racing to double-apply.
//   - Forward-only: down migrations are a production foot-gun (a column
//     drop is data loss). Rollback is a restore-from-snapshot operation,
//     not a schema operation.
//
// The runner is deliberately not goose/golang-migrate: the repo's ethos
// is pure-Go with no external service deps, the surface needed here is
// small, and embedding SQL as Go strings (already how every backend
// declares its schema) keeps migrations co-located with the store.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// ErrSchemaTooNew is returned by CheckSchema when the live database schema is
// ahead of the binary's declared max version. This means an older binary is
// running against a forward-migrated database — a canary rollback without a
// matching schema downgrade (which doesn't exist; rollback is restore-from-
// snapshot). The operator must restore from snapshot or deploy the newer
// binary instead.
var ErrSchemaTooNew = errors.New("migrate: database schema is ahead of binary (rollback needed first)")

// busyTimeoutMS bounds how long a contended migration waits for the
// write lock before giving up. Generous because it only applies at
// startup, where several replicas may briefly contend; a wedged lock
// past this surfaces as a clear migration error rather than a hang.
const busyTimeoutMS = 10000

// Migration is one forward schema change. Exactly one of SQL or Func
// must be set:
//
//   - SQL: forward DDL, possibly multiple ';'-separated statements
//     (modernc.org/sqlite executes them in a single Exec, as every
//     backend's baseline schema already relies on).
//   - Func: a Go step for conditional or data migrations that plain DDL
//     can't express — e.g. "add this column only if it's missing"
//     (SQLite has no ADD COLUMN IF NOT EXISTS) or backfilling a new
//     column from old rows. It runs inside the same transaction as SQL
//     migrations, against the migration connection.
type Migration struct {
	Version int    // 1-based, strictly increasing across the slice
	Name    string // human label, recorded for auditability
	SQL     string // forward DDL (mutually exclusive with Func)
	Func    func(ctx context.Context, x Execer) error
}

// Execer is the subset of *sql.DB / *sql.Conn a Func migration needs.
// The runner passes the pinned migration connection, so a Func's
// statements run inside the migration's transaction.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// namespacePattern bounds what may be interpolated into the version
// table name. The namespace can't be a bind parameter (it's an
// identifier, not a value), so it must be validated to a safe charset
// to keep the table name injection-free.
var namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func versionTable(namespace string) (string, error) {
	if !namespacePattern.MatchString(namespace) {
		return "", fmt.Errorf("migrate: invalid namespace %q (want ^[a-z][a-z0-9_]*$)", namespace)
	}
	return "schema_migrations_" + namespace, nil
}

// validate checks the migration set is well-formed before any DB work:
// versions start at 1 and strictly increase (no duplicates, no
// zero/negative). Gaps are permitted (a deleted historical migration
// leaves a hole) but order must be monotonic so application order is
// unambiguous.
func validate(migrations []Migration) error {
	prev := 0
	for i, m := range migrations {
		if m.Version <= 0 {
			return fmt.Errorf("migrate: migration[%d] %q has non-positive version %d", i, m.Name, m.Version)
		}
		if m.Version <= prev {
			return fmt.Errorf("migrate: migration[%d] %q version %d not strictly greater than previous %d", i, m.Name, m.Version, prev)
		}
		hasSQL := m.SQL != ""
		hasFunc := m.Func != nil
		if hasSQL == hasFunc { // both set, or neither
			return fmt.Errorf("migrate: migration[%d] %q must set exactly one of SQL or Func", i, m.Name)
		}
		prev = m.Version
	}
	return nil
}

// Run applies every migration whose Version exceeds the namespace's
// currently-recorded version, in ascending order, inside one immediate
// transaction. It is idempotent: re-running with no new migrations is a
// no-op. Safe for concurrent callers against the same database (they
// serialize on the write lock).
func Run(ctx context.Context, db *sql.DB, namespace string, migrations []Migration) error {
	table, err := versionTable(namespace)
	if err != nil {
		return err
	}
	if err := validate(migrations); err != nil {
		return err
	}
	if len(migrations) == 0 {
		return nil
	}

	// Pin one connection so the manual BEGIN IMMEDIATE / COMMIT pair runs
	// on the same session (database/sql may otherwise spread statements
	// across pooled connections).
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate(%s): acquire conn: %w", namespace, err)
	}
	defer func() { _ = conn.Close() }()

	if err := beginImmediate(ctx, conn, namespace); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	current, err := ensureVersionTable(ctx, conn, namespace, table)
	if err != nil {
		return err
	}
	if err := applyPending(ctx, conn, namespace, table, current, migrations); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("migrate(%s): commit: %w", namespace, err)
	}
	committed = true
	return nil
}

// beginImmediate arms the pinned connection's busy timeout and opens the
// write transaction up front. Setting busy_timeout on THIS connection makes
// BEGIN IMMEDIATE wait for a contended write lock instead of failing fast —
// independent of DSN pragmas (the mattn-style `_busy_timeout` query param is
// a no-op under modernc.org/sqlite). BEGIN IMMEDIATE grabs the write lock now
// so two replicas booting together don't both read version 0 and double-apply.
func beginImmediate(ctx context.Context, conn *sql.Conn, namespace string) error {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeoutMS)); err != nil {
		return fmt.Errorf("migrate(%s): set busy_timeout: %w", namespace, err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("migrate(%s): begin: %w", namespace, err)
	}
	return nil
}

// ensureVersionTable creates the per-namespace version table if absent and
// returns the highest recorded version (0 on a fresh table). Runs inside the
// migration transaction opened by beginImmediate.
func ensureVersionTable(ctx context.Context, conn *sql.Conn, namespace, table string) (int, error) {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (
			version    INTEGER PRIMARY KEY,
			name       TEXT    NOT NULL,
			applied_at INTEGER NOT NULL
		)`, table)); err != nil {
		return 0, fmt.Errorf("migrate(%s): ensure version table: %w", namespace, err)
	}
	var current int
	if err := conn.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COALESCE(MAX(version), 0) FROM %s`, table)).Scan(&current); err != nil {
		return 0, fmt.Errorf("migrate(%s): read current version: %w", namespace, err)
	}
	return current, nil
}

// applyPending runs every migration whose Version exceeds current, in slice
// order, recording each in the version table. Runs inside the migration
// transaction so a mid-way failure rolls the whole batch back.
func applyPending(ctx context.Context, conn *sql.Conn, namespace, table string, current int, migrations []Migration) error {
	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if err := applyOne(ctx, conn, namespace, m); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf(`INSERT INTO %s (version, name, applied_at) VALUES (?, ?, ?)`, table),
			m.Version, m.Name, time.Now().UnixNano()); err != nil {
			return fmt.Errorf("migrate(%s): record v%d: %w", namespace, m.Version, err)
		}
	}
	return nil
}

// applyOne executes a single migration's forward step (Func or SQL). validate
// guarantees exactly one of the two is set.
func applyOne(ctx context.Context, conn *sql.Conn, namespace string, m Migration) error {
	if m.Func != nil {
		if err := m.Func(ctx, conn); err != nil {
			return fmt.Errorf("migrate(%s): apply v%d %q (func): %w", namespace, m.Version, m.Name, err)
		}
		return nil
	}
	if _, err := conn.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("migrate(%s): apply v%d %q: %w", namespace, m.Version, m.Name, err)
	}
	return nil
}

// NamespaceStatus is one backend's recorded schema state — the latest
// applied migration for that namespace.
type NamespaceStatus struct {
	Namespace string
	Version   int
	Name      string
	AppliedAt time.Time
}

// Status discovers every schema_migrations_<ns> table in the database
// and returns the latest-applied migration per namespace, sorted by
// namespace. It reads only what's recorded in the DB — no migration
// definitions needed — so an offline tool can report a database's
// schema state without importing the backend packages.
func Status(ctx context.Context, db *sql.DB) ([]NamespaceStatus, error) {
	const prefix = "schema_migrations_"
	rows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ? ORDER BY name`,
		prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("migrate: list version tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("migrate: scan version table name: %w", err)
		}
		tables = append(tables, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()

	out := make([]NamespaceStatus, 0, len(tables))
	for _, table := range tables {
		st := NamespaceStatus{Namespace: table[len(prefix):]}
		var appliedNs int64
		// The latest migration is the max-version row.
		err := db.QueryRowContext(ctx, fmt.Sprintf(
			`SELECT version, name, applied_at FROM %s ORDER BY version DESC LIMIT 1`, table),
		).Scan(&st.Version, &st.Name, &appliedNs)
		if err == sql.ErrNoRows {
			// Empty version table (created but nothing recorded) — report
			// version 0 so the namespace still surfaces.
			out = append(out, st)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("migrate: read status for %s: %w", st.Namespace, err)
		}
		st.AppliedAt = time.Unix(0, appliedNs)
		out = append(out, st)
	}
	return out, nil
}

// MaxVersion returns the highest version number declared in the provided
// migrations slice, or -1 when the slice is empty (no schema defined).
// Backends call this to advertise the schema version their binary expects
// so CheckSchema can refuse to serve when the live DB is ahead of it.
func MaxVersion(migrations []Migration) int {
	if len(migrations) == 0 {
		return -1
	}
	// validate() proves the slice is strictly increasing, so the last
	// element always carries the highest version. We do NOT call validate
	// here because MaxVersion is a pure read on the slice — callers that
	// need validation already route through Run.
	return migrations[len(migrations)-1].Version
}

// CheckSchema returns ErrSchemaTooNew when the live DB schema for namespace
// is AHEAD of binaryMax — meaning an older binary is running against a
// forward-migrated database (canary rollback without a schema downgrade).
// Returns nil when db_version <= binaryMax (safe to run) or when the DB
// has no migrations yet (fresh install). The boot path treats a non-nil
// error as fatal so the operator notices before the server ever starts
// accepting traffic with a schema it does not understand.
func CheckSchema(ctx context.Context, db *sql.DB, namespace string, binaryMax int) error {
	live, err := CurrentVersion(ctx, db, namespace)
	if err != nil {
		return err
	}
	if live > binaryMax {
		return fmt.Errorf("%w: namespace %q is at v%d but binary only knows up to v%d",
			ErrSchemaTooNew, namespace, live, binaryMax)
	}
	return nil
}

// CurrentVersion returns the highest applied migration version for the
// namespace, or 0 when no migrations have been recorded (including when
// the version table doesn't exist yet). Useful for a readiness gate
// that refuses to serve when the binary expects a newer schema than the
// database carries.
func CurrentVersion(ctx context.Context, db *sql.DB, namespace string) (int, error) {
	table, err := versionTable(namespace)
	if err != nil {
		return 0, err
	}
	// The version table is absent before the first Run; treat that as
	// version 0 rather than an error so callers can probe unconditionally.
	var exists string
	err = db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("migrate(%s): probe version table: %w", namespace, err)
	}
	var current int
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COALESCE(MAX(version), 0) FROM %s`, table)).Scan(&current); err != nil {
		return 0, fmt.Errorf("migrate(%s): read current version: %w", namespace, err)
	}
	return current, nil
}
