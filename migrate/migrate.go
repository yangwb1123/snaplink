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
	"fmt"
	"regexp"
	"time"
)

// busyTimeoutMS bounds how long a contended migration waits for the
// write lock before giving up. Generous because it only applies at
// startup, where several replicas may briefly contend; a wedged lock
// past this surfaces as a clear migration error rather than a hang.
const busyTimeoutMS = 10000

// Migration is one forward schema change. SQL may contain multiple
// statements separated by ';' (modernc.org/sqlite executes them in a
// single Exec, as every backend's baseline schema already relies on).
type Migration struct {
	Version int    // 1-based, strictly increasing across the slice
	Name    string // human label, recorded for auditability
	SQL     string // forward DDL; idempotent constructs (IF NOT EXISTS) recommended for the baseline
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
	defer conn.Close()

	// Set the busy timeout on THIS connection so BEGIN IMMEDIATE waits
	// for a contended write lock instead of failing fast — independent
	// of DSN pragmas (notably: the mattn-style `_busy_timeout` query
	// param is a no-op under modernc.org/sqlite). This is what lets
	// replicas booting together serialize on the migration rather than
	// erroring out.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeoutMS)); err != nil {
		return fmt.Errorf("migrate(%s): set busy_timeout: %w", namespace, err)
	}

	// BEGIN IMMEDIATE grabs the write lock now, so two replicas booting
	// together don't both read version 0 and double-apply.
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("migrate(%s): begin: %w", namespace, err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	if _, err := conn.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (
			version    INTEGER PRIMARY KEY,
			name       TEXT    NOT NULL,
			applied_at INTEGER NOT NULL
		)`, table)); err != nil {
		return fmt.Errorf("migrate(%s): ensure version table: %w", namespace, err)
	}

	var current int
	if err := conn.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COALESCE(MAX(version), 0) FROM %s`, table)).Scan(&current); err != nil {
		return fmt.Errorf("migrate(%s): read current version: %w", namespace, err)
	}

	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if _, err := conn.ExecContext(ctx, m.SQL); err != nil {
			return fmt.Errorf("migrate(%s): apply v%d %q: %w", namespace, m.Version, m.Name, err)
		}
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf(`INSERT INTO %s (version, name, applied_at) VALUES (?, ?, ?)`, table),
			m.Version, m.Name, time.Now().UnixNano()); err != nil {
			return fmt.Errorf("migrate(%s): record v%d: %w", namespace, m.Version, err)
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("migrate(%s): commit: %w", namespace, err)
	}
	committed = true
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
