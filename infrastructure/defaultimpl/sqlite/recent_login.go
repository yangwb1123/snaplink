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

// recentLoginSchema persists per-subject login history for behavioral
// anomaly detectors (impossible travel, velocity, new device, new
// country). Compound index on (subject_id, ts_unix_ns DESC) so
// the Recent query — "newest N entries for this subject newer than
// since" — is one index scan with backward order.
//
// Field shape mirrors [anomaly.LoginEntry] verbatim. The expires_at
// index supports the retention scheduler's PruneOlder call (mirrors
// the audit / push retention pattern).
const recentLoginSchema = `
CREATE TABLE IF NOT EXISTS recent_logins (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id             TEXT    NOT NULL DEFAULT '',
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

CREATE INDEX IF NOT EXISTS idx_recent_logins_tenant_subject_ts
    ON recent_logins(tenant_id, subject_id, ts_unix_ns DESC);
CREATE INDEX IF NOT EXISTS idx_recent_logins_ts
    ON recent_logins(ts_unix_ns);
`

// recentLoginMigrations is the schema history. v1 is the original
// baseline (pre-tenant shape); v2 backfills tenant_id onto a
// pre-existing database — SQLite has no ADD COLUMN IF NOT EXISTS, so
// the Func checks first — and swaps the subject index for the
// tenant-scoped one. A fresh database already has both from the v1
// baseline DDL above and skips the adds.
var recentLoginMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: recentLoginSchema},
	{Version: 2, Name: "tenant_dimension", Func: addRecentLoginTenantID},
}

// addRecentLoginTenantID migrates a pre-tenant recent_logins table:
// adds the tenant_id column when missing and replaces the
// cross-tenant subject index with the (tenant_id, subject_id, ts)
// index.
func addRecentLoginTenantID(ctx context.Context, x migrate.Execer) error {
	has, err := recentLoginColumnExists(ctx, x, "tenant_id")
	if err != nil {
		return err
	}
	if !has {
		if _, err := x.ExecContext(ctx,
			`ALTER TABLE recent_logins ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	// The old cross-tenant index would shadow the new one for the
	// tenant-less partition; drop it when present.
	if _, err := x.ExecContext(ctx,
		`DROP INDEX IF EXISTS idx_recent_logins_subject_ts`); err != nil {
		return err
	}
	_, err = x.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_recent_logins_tenant_subject_ts
		 ON recent_logins(tenant_id, subject_id, ts_unix_ns DESC)`)
	return err
}

// recentLoginColumnExists reports whether a column is present on
// recent_logins (SQLite PRAGMA introspection).
func recentLoginColumnExists(ctx context.Context, x migrate.Execer, column string) (bool, error) {
	rows, err := x.QueryContext(ctx, `PRAGMA table_info(recent_logins)`)
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

// RecentLoginStore is the SQLite-backed [anomaly.RecentLoginStore].
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
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "recent_login", recentLoginMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate recent_logins: %w", err)
	}
	return &RecentLoginStore{db: db}, nil
}

// NewRecentLoginStoreWithDB wraps an existing *sql.DB. Caller owns
// the connection lifecycle.
func NewRecentLoginStoreWithDB(db *sql.DB) (*RecentLoginStore, error) {
	if err := migrate.Run(context.Background(), db, "recent_login", recentLoginMigrations); err != nil {
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

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (s *RecentLoginStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *RecentLoginStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: recent login store closed")
	}
	return s.db.PingContext(ctx)
}

// Append persists entry. Empty SubjectID → ErrInvalidLoginEntry.
func (s *RecentLoginStore) Append(ctx context.Context, entry *anomaly.LoginEntry) error {
	if entry == nil || entry.SubjectID == "" {
		return anomaly.ErrInvalidLoginEntry
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO recent_logins (
            tenant_id, subject_id, client_id, outcome,
            ip_hash, country_code, latitude, longitude,
            ua_fingerprint_hash, ts_unix_ns
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.TenantID, entry.SubjectID, entry.ClientID, entry.Outcome,
		entry.IPHash, entry.CountryCode, entry.Latitude, entry.Longitude,
		entry.UAFingerprintHash, entry.Timestamp.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert recent_login: %w", err)
	}
	return nil
}

// Recent returns up to limit most-recent entries for subjectID within
// tenantID, newer than since. Backend cap = 100 when limit <= 0
// (matches the SPI contract).
func (s *RecentLoginStore) Recent(ctx context.Context, tenantID, subjectID string, since time.Time, limit int) ([]*anomaly.LoginEntry, error) {
	if subjectID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	var args []any
	query := `
        SELECT tenant_id, subject_id, client_id, outcome,
               ip_hash, country_code, latitude, longitude,
               ua_fingerprint_hash, ts_unix_ns
          FROM recent_logins
         WHERE tenant_id = ? AND subject_id = ?`
	args = append(args, tenantID, subjectID)
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
	defer func() { _ = rows.Close() }()
	var out []*anomaly.LoginEntry
	for rows.Next() {
		var (
			e    anomaly.LoginEntry
			tsNs int64
		)
		if err := rows.Scan(
			&e.TenantID, &e.SubjectID, &e.ClientID, &e.Outcome,
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

var _ anomaly.RecentLoginStore = (*RecentLoginStore)(nil)
