package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/anomaly"
)

// ipFailureCounterSchema persists (ip_hash, subject_id, ts) for
// the brute-force shadow detector. Two indexes:
//   - (ip_hash, ts_unix_ns) for the count + distinct-subjects query
//     scoped to one IP.
//   - (ts_unix_ns) for PruneOlder.
const ipFailureCounterSchema = `
CREATE TABLE IF NOT EXISTS ip_failures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_hash      TEXT    NOT NULL,
    subject_id   TEXT    NOT NULL DEFAULT '',
    ts_unix_ns   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_failures_ip_ts
    ON ip_failures(ip_hash, ts_unix_ns);
CREATE INDEX IF NOT EXISTS idx_ip_failures_ts
    ON ip_failures(ts_unix_ns);
`

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
	if err := ensureSchema(db, "ip_failure_counter", ipFailureCounterSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate ip_failures: %w", err)
	}
	return &IPFailureCounter{db: db}, nil
}

// NewIPFailureCounterWithDB wraps an existing *sql.DB.
func NewIPFailureCounterWithDB(db *sql.DB) (*IPFailureCounter, error) {
	if err := ensureSchema(db, "ip_failure_counter", ipFailureCounterSchema); err != nil {
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

// Ping reports SQLite connection health.
func (s *IPFailureCounter) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: ip failure counter closed")
	}
	return s.db.PingContext(ctx)
}

// Record persists a failure entry.
func (s *IPFailureCounter) Record(ctx context.Context, ipHash, subjectID string, ts time.Time) error {
	if ipHash == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO ip_failures (ip_hash, subject_id, ts_unix_ns)
        VALUES (?, ?, ?)`,
		ipHash, subjectID, ts.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert ip_failure: %w", err)
	}
	return nil
}

// Count returns (total, distinct subjects) for ipHash after since.
func (s *IPFailureCounter) Count(ctx context.Context, ipHash string, since time.Time) (int, int, error) {
	if ipHash == "" {
		return 0, 0, nil
	}
	args := []any{ipHash}
	query := `SELECT COUNT(*), COUNT(DISTINCT NULLIF(subject_id, ''))
                FROM ip_failures
               WHERE ip_hash = ?`
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
