package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// The schema-migration runner for the Postgres-wire backend. It reuses
// platform/migrate's Migration type + MaxVersion + ErrSchemaTooNew (pure,
// dialect-free) but replaces the SQLite-only mechanics: BEGIN IMMEDIATE ->
// pg_advisory_xact_lock (Postgres) / SERIALIZABLE+retry (CockroachDB),
// sqlite_master -> information_schema, "?" -> "$N", INTEGER applied_at ->
// BIGINT, and multi-statement DDL strings -> per-statement Exec (pgx's extended
// protocol rejects multi-statement Exec, and CockroachDB rejects multiple DDL
// in one explicit transaction).

const sqlStateSerializationFailure = "40001"

// serializableMaxRetries bounds the 40001 retry loop. Postgres holds the
// advisory lock so it won't emit 40001; only CockroachDB's serializable boots
// contend, and a handful of retries clears any realistic concurrency.
const serializableMaxRetries = 5

var namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func versionTable(namespace string) (string, error) {
	if !namespacePattern.MatchString(namespace) {
		return "", fmt.Errorf("postgres migrate: invalid namespace %q (want ^[a-z][a-z0-9_]*$)", namespace)
	}
	return "schema_migrations_" + namespace, nil
}

// advisoryKey derives a stable per-namespace bigint for pg_advisory_xact_lock
// so two replicas migrating the same namespace serialize, while different
// namespaces never block each other.
func advisoryKey(namespace string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("sso:migrate:" + namespace))
	return int64(h.Sum64()) //nolint:gosec // wrap to bigint is intentional; only identity matters
}

// isSerializationFailure reports whether err is a Postgres/CRDB 40001
// (serialization_failure / "restart transaction"), reachable through the pgx
// stdlib driver via errors.As.
func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == sqlStateSerializationFailure
}

// withRetry retries fn on a 40001 serialization failure (CockroachDB). For
// Postgres the advisory lock prevents 40001, so fn runs once.
func withRetry(fn func() error) error {
	var err error
	for range serializableMaxRetries {
		if err = fn(); err == nil || !isSerializationFailure(err) {
			return err
		}
	}
	return err
}

// Run applies every migration whose Version exceeds the namespace's recorded
// version, in ascending order, in one transaction. Idempotent and safe for
// concurrent replica boots (Postgres serializes on an advisory lock;
// CockroachDB on SERIALIZABLE + the 40001 retry).
func Run(ctx context.Context, db *sql.DB, namespace string, migrations []migrate.Migration, dialect Dialect) error {
	table, err := versionTable(namespace)
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return nil
	}
	return withRetry(func() error {
		return runOnce(ctx, db, namespace, table, migrations, dialect)
	})
}

func runOnce(ctx context.Context, db *sql.DB, namespace, table string, migrations []migrate.Migration, dialect Dialect) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("postgres migrate(%s): acquire conn: %w", namespace, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return fmt.Errorf("postgres migrate(%s): begin: %w", namespace, err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	// Postgres serializes concurrent boots on a per-namespace advisory lock
	// held until COMMIT. CockroachDB has no advisory locks; its SERIALIZABLE
	// default + the 40001 retry wrapping Run cover the same race.
	if dialect.normalized() != DialectCockroach {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryKey(namespace)); err != nil {
			return fmt.Errorf("postgres migrate(%s): advisory lock: %w", namespace, err)
		}
	}

	current, err := ensureVersionTable(ctx, conn, namespace, table)
	if err != nil {
		return err
	}
	if err := applyPending(ctx, conn, namespace, table, current, migrations); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("postgres migrate(%s): commit: %w", namespace, err)
	}
	committed = true
	return nil
}

func ensureVersionTable(ctx context.Context, conn *sql.Conn, namespace, table string) (int, error) {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (
			version    INTEGER PRIMARY KEY,
			name       TEXT    NOT NULL,
			applied_at BIGINT  NOT NULL
		)`, table)); err != nil {
		return 0, fmt.Errorf("postgres migrate(%s): ensure version table: %w", namespace, err)
	}
	var current int
	if err := conn.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COALESCE(MAX(version), 0) FROM %s`, table)).Scan(&current); err != nil {
		return 0, fmt.Errorf("postgres migrate(%s): read current version: %w", namespace, err)
	}
	return current, nil
}

func applyPending(ctx context.Context, conn *sql.Conn, namespace, table string, current int, migrations []migrate.Migration) error {
	for _, m := range migrations {
		if m.Version <= current {
			continue
		}
		if err := applyOne(ctx, conn, namespace, m); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx,
			fmt.Sprintf(`INSERT INTO %s (version, name, applied_at) VALUES ($1, $2, $3)`, table),
			m.Version, m.Name, time.Now().UnixNano()); err != nil {
			return fmt.Errorf("postgres migrate(%s): record v%d: %w", namespace, m.Version, err)
		}
	}
	return nil
}

// applyOne runs a migration's forward step. SQL migrations are split into
// individual statements (pgx's extended protocol rejects multi-statement Exec,
// and CockroachDB rejects multiple DDL in one explicit transaction).
func applyOne(ctx context.Context, conn *sql.Conn, namespace string, m migrate.Migration) error {
	if m.Func != nil {
		if err := m.Func(ctx, conn); err != nil {
			return fmt.Errorf("postgres migrate(%s): apply v%d %q (func): %w", namespace, m.Version, m.Name, err)
		}
		return nil
	}
	for _, stmt := range splitStatements(m.SQL) {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("postgres migrate(%s): apply v%d %q: %w", namespace, m.Version, m.Name, err)
		}
	}
	return nil
}

// splitStatements breaks a multi-statement DDL string on ';' into individual
// trimmed, non-empty statements. The SDK authors these baselines (plain CREATE
// TABLE / CREATE INDEX with no embedded semicolons), so a literal split is
// safe and avoids a SQL parser dependency.
func splitStatements(sqlText string) []string {
	parts := strings.Split(sqlText, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// CurrentVersion returns the highest applied migration version for namespace,
// or 0 when none recorded (including when the version table doesn't exist yet).
func CurrentVersion(ctx context.Context, db *sql.DB, namespace string) (int, error) {
	table, err := versionTable(namespace)
	if err != nil {
		return 0, err
	}
	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		   WHERE table_schema = current_schema() AND table_name = $1)`,
		table).Scan(&exists); err != nil {
		return 0, fmt.Errorf("postgres migrate(%s): probe version table: %w", namespace, err)
	}
	if !exists {
		return 0, nil
	}
	var current int
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COALESCE(MAX(version), 0) FROM %s`, table)).Scan(&current); err != nil {
		return 0, fmt.Errorf("postgres migrate(%s): read current version: %w", namespace, err)
	}
	return current, nil
}

// CheckSchema returns migrate.ErrSchemaTooNew when the live schema for
// namespace is AHEAD of binaryMax (an older binary against a forward-migrated
// DB). The boot path treats a non-nil error as fatal.
func CheckSchema(ctx context.Context, db *sql.DB, namespace string, binaryMax int) error {
	live, err := CurrentVersion(ctx, db, namespace)
	if err != nil {
		return err
	}
	if live > binaryMax {
		return fmt.Errorf("%w: namespace %q is at v%d but binary only knows up to v%d",
			migrate.ErrSchemaTooNew, namespace, live, binaryMax)
	}
	return nil
}
