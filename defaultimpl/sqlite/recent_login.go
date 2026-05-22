package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
)

// recentLoginSchema persists per-subject login history for behavioral
// anomaly detectors (impossible travel, velocity, new device, new
// country). Compound index on (subject_id, ts_unix_ns DESC) so
// the Recent query — "newest N entries for this subject newer than
// since" — is one index scan with backward order.
//
// Field shape mirrors [sso.LoginEntry] verbatim. The expires_at
// index supports the retention scheduler's PruneOlder call (mirrors
// the audit / push retention pattern).
const recentLoginSchema = `
CREATE TABLE IF NOT EXISTS recent_logins (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id            TEXT    NOT NULL,
    client_id             TEXT    NOT NULL DEFAULT '',
    outcome               TEXT    NOT NULL,
    ip_hash               TEXT    NOT NULL DEFAULT '',
    country_code          TEXT    NOT NULL DEFAULT '',
    latitude              REAL    NOT NULL DEFAULT 0,
    longitude             REAL    NOT NULL DEFAULT 0,
    ua_fingerprint_hash   TEXT    NOT NULL DEFAULT '',
    ts_unix_ns            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recent_logins_subject_ts
    ON recent_logins(subject_id, ts_unix_ns DESC);
CREATE INDEX IF NOT EXISTS idx_recent_logins_ts
    ON recent_logins(ts_unix_ns);
`

// RecentLoginStore is the SQLite-backed [sso.RecentLoginStore].
// Cluster-shared: detectors on replica B see entries appended by
// replica A. Schema migration via CREATE TABLE IF NOT EXISTS at
// construction.
type RecentLoginStore struct {
	db *sql.DB
}

// NewRecentLoginStore opens dsn, migrates the schema, returns the
// store. Caller owns Close().
func NewRecentLoginStore(dsn string) (*RecentLoginStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), recentLoginSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate recent_logins: %w", err)
	}
	return &RecentLoginStore{db: db}, nil
}

// NewRecentLoginStoreWithDB wraps an existing *sql.DB. Caller owns
// the connection lifecycle.
func NewRecentLoginStoreWithDB(db *sql.DB) (*RecentLoginStore, error) {
	if _, err := db.ExecContext(context.Background(), recentLoginSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate recent_logins: %w", err)
	}
	return &RecentLoginStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *RecentLoginStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *RecentLoginStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: recent login store closed")
	}
	return s.db.PingContext(ctx)
}

// Append persists entry. Empty SubjectID → ErrInvalidLoginEntry.
func (s *RecentLoginStore) Append(ctx context.Context, entry *sso.LoginEntry) error {
	if entry == nil || entry.SubjectID == "" {
		return sso.ErrInvalidLoginEntry
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO recent_logins (
            subject_id, client_id, outcome,
            ip_hash, country_code, latitude, longitude,
            ua_fingerprint_hash, ts_unix_ns
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.SubjectID, entry.ClientID, entry.Outcome,
		entry.IPHash, entry.CountryCode, entry.Latitude, entry.Longitude,
		entry.UAFingerprintHash, entry.Timestamp.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert recent_login: %w", err)
	}
	return nil
}

// Recent returns up to limit most-recent entries for subjectID
// newer than since. Backend cap = 100 when limit <= 0 (matches the
// SPI contract).
func (s *RecentLoginStore) Recent(ctx context.Context, subjectID string, since time.Time, limit int) ([]*sso.LoginEntry, error) {
	if subjectID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	var args []any
	query := `
        SELECT subject_id, client_id, outcome,
               ip_hash, country_code, latitude, longitude,
               ua_fingerprint_hash, ts_unix_ns
          FROM recent_logins
         WHERE subject_id = ?`
	args = append(args, subjectID)
	if !since.IsZero() {
		query += ` AND ts_unix_ns >= ?`
		args = append(args, since.UnixNano())
	}
	query += ` ORDER BY ts_unix_ns DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: recent recent_logins: %w", err)
	}
	defer rows.Close()
	var out []*sso.LoginEntry
	for rows.Next() {
		var (
			e    sso.LoginEntry
			tsNs int64
		)
		if err := rows.Scan(
			&e.SubjectID, &e.ClientID, &e.Outcome,
			&e.IPHash, &e.CountryCode, &e.Latitude, &e.Longitude,
			&e.UAFingerprintHash, &tsNs,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan recent_login: %w", err)
		}
		e.Timestamp = time.Unix(0, tsNs).UTC()
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows recent_logins: %w", err)
	}
	return out, nil
}

// PruneOlder deletes entries with ts < cutoff and returns the row
// count. Zero cutoff → no-op (mirrors the audit/sqlite Sink.Prune
// contract).
func (s *RecentLoginStore) PruneOlder(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("sqlite: recent login store closed")
	}
	if cutoff.IsZero() {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM recent_logins WHERE ts_unix_ns < ?`, cutoff.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sqlite: prune recent_logins: %w", err)
	}
	return res.RowsAffected()
}

var _ sso.RecentLoginStore = (*RecentLoginStore)(nil)
