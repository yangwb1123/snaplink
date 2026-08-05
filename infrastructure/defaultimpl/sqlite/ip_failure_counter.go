package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// ipFailureCounterSchema persists (ip_hash, subject_id, ts) for
// the brute-force shadow detector. Two indexes:
//   - (ip_hash, ts_unix_ns) for the count + distinct-subjects query
//     scoped to one IP.
//   - (ts_unix_ns) for PruneOlder.
const ipFailureCounterSchema = `
CREATE TABLE IF NOT EXISTS ip_failures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT    NOT NULL DEFAULT '',
    ip_hash      TEXT    NOT NULL,
    subject_id   TEXT    NOT NULL DEFAULT '',
    ts_unix_ns   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_failures_tenant_ip_ts
    ON ip_failures(tenant_id, ip_hash, ts_unix_ns);
CREATE INDEX IF NOT EXISTS idx_ip_failures_ts
    ON ip_failures(ts_unix_ns);
`

// ipFailureMigrations is the schema history. v1 is the original
// baseline; v2 backfills tenant_id onto a pre-existing database and
// swaps the IP index for the tenant-scoped one.
var ipFailureMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: ipFailureCounterSchema},
	{Version: 2, Name: "tenant_dimension", Func: addIPFailureTenantID},
}

// addIPFailureTenantID migrates a pre-tenant ip_failures table.
func addIPFailureTenantID(ctx context.Context, x migrate.Execer) error {
	has, err := ipFailureColumnExists(ctx, x, "tenant_id")
	if err != nil {
		return err
	}
	if !has {
		if _, err := x.ExecContext(ctx,
			`ALTER TABLE ip_failures ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if _, err := x.ExecContext(ctx,
		`DROP INDEX IF EXISTS idx_ip_failures_ip_ts`); err != nil {
		return err
	}
	_, err = x.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_ip_failures_tenant_ip_ts
		 ON ip_failures(tenant_id, ip_hash, ts_unix_ns)`)
	return err
}

// ipFailureColumnExists reports whether a column is present on
// ip_failures (SQLite PRAGMA introspection).
func ipFailureColumnExists(ctx context.Context, x migrate.Execer, column string) (bool, error) {
	rows, err := x.QueryContext(ctx, `PRAGMA table_info(ip_failures)`)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue any
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// IPFailureCounter is the SQLite-backed [anomaly.IPFailureCounter].
// Cluster-shared: brute-force counters keyed by IP work across
// replicas because every replica writes to the same SQLite file.
type IPFailureCounter struct {
	db *sql.DB
}

// NewIPFailureCounter opens dsn, migrates schema, returns the
// counter.
func NewIPFailureCounter(dsn string) (*IPFailureCounter, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "ip_failure_counter", ipFailureMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate ip_failures: %w", err)
	}
	return &IPFailureCounter{db: db}, nil
}

// NewIPFailureCounterWithDB wraps an existing *sql.DB.
func NewIPFailureCounterWithDB(db *sql.DB) (*IPFailureCounter, error) {
	if err := migrate.Run(context.Background(), db, "ip_failure_counter", ipFailureMigrations); err != nil {
		return nil, fmt.Errorf("sqlite: migrate ip_failures: %w", err)
	}
	return &IPFailureCounter{db: db}, nil
}

// Close releases the SQLite connection.
func (s *IPFailureCounter) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (s *IPFailureCounter) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health.
func (s *IPFailureCounter) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: ip failure counter closed")
	}
	return s.db.PingContext(ctx)
}

// Record persists a failure entry.
func (s *IPFailureCounter) Record(ctx context.Context, tenantID, ipHash, subjectID string, ts time.Time) error {
	if ipHash == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO ip_failures (tenant_id, ip_hash, subject_id, ts_unix_ns)
        VALUES (?, ?, ?, ?)`,
		tenantID, ipHash, subjectID, ts.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert ip_failure: %w", err)
	}
	return nil
}

// Count returns (total, distinct subjects) for ipHash after since.
func (s *IPFailureCounter) Count(ctx context.Context, tenantID, ipHash string, since time.Time) (int, int, error) {
	if ipHash == "" {
		return 0, 0, nil
	}
	args := []any{tenantID, ipHash}
	query := `SELECT COUNT(*), COUNT(DISTINCT NULLIF(subject_id, ''))
                FROM ip_failures
               WHERE tenant_id = ? AND ip_hash = ?`
	if !since.IsZero() {
		query += ` AND ts_unix_ns >= ?`
		args = append(args, since.UnixNano())
	}
	var total, distinct int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&total, &distinct); err != nil {
		return 0, 0, fmt.Errorf("sqlite: count ip_failures: %w", err)
	}
	return total, distinct, nil
}

// PruneOlder removes entries with ts < cutoff. Returns row count.
func (s *IPFailureCounter) PruneOlder(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("sqlite: ip failure counter closed")
	}
	if cutoff.IsZero() {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM ip_failures WHERE ts_unix_ns < ?`, cutoff.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sqlite: prune ip_failures: %w", err)
	}
	return res.RowsAffected()
}

var _ anomaly.IPFailureCounter = (*IPFailureCounter)(nil)
