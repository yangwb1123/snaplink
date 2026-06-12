package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/security"
)

// subjectClientIndexSchema covers the OIDC BCL fan-out lookup —
// "given subject X, which clients should I POST logout_token to?".
// Composite PK enforces (subject, client_id) uniqueness so
// RecordAccess is naturally idempotent via ON CONFLICT DO UPDATE
// (refreshes last_seen without insert-time error juggling).
const subjectClientIndexSchema = `
CREATE TABLE IF NOT EXISTS subject_client_index (
    subject   TEXT    NOT NULL,
    client_id TEXT    NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (subject, client_id)
);

CREATE INDEX IF NOT EXISTS idx_subject_client_index_subject
    ON subject_client_index(subject);
`

// SubjectClientIndex is the SQLite-backed implementation of
// [security.SubjectClientIndex]. Replaces memory_subject_client_index.go
// for multi-replica deployments — BCL fan-out can now reach every
// client a subject has touched across the cluster, not just those
// whose last issuance landed on the replica handling the logout.
type SubjectClientIndex struct {
	db *sql.DB
}

// NewSubjectClientIndex opens dsn, migrates the schema, and returns
// the index.
func NewSubjectClientIndex(dsn string) (*SubjectClientIndex, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "subject_client_index", subjectClientIndexSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate subject_client_index: %w", err)
	}
	return &SubjectClientIndex{db: db}, nil
}

// NewSubjectClientIndexWithDB wraps an existing *sql.DB
// (shared-pool deployments).
func NewSubjectClientIndexWithDB(db *sql.DB) (*SubjectClientIndex, error) {
	if err := ensureSchema(db, "subject_client_index", subjectClientIndexSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate subject_client_index: %w", err)
	}
	return &SubjectClientIndex{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *SubjectClientIndex) Close() error {
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
func (s *SubjectClientIndex) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *SubjectClientIndex) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: subject_client_index closed")
	}
	return s.db.PingContext(ctx)
}

// RecordAccess upserts (subject, client_id). Refreshes last_seen so
// a future TTL-based eviction can see which entries are still
// active. Idempotent per the SPI contract.
func (s *SubjectClientIndex) RecordAccess(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO subject_client_index (subject, client_id, last_seen)
        VALUES (?, ?, ?)
        ON CONFLICT (subject, client_id) DO UPDATE SET last_seen = excluded.last_seen`,
		subject, clientID, time.Now().UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: record access: %w", err)
	}
	return nil
}

// ListClients returns every client_id seen for subject. Order is
// last_seen DESC so callers iterating with bounded fan-out budget
// hit the most-recently-active clients first.
func (s *SubjectClientIndex) ListClients(ctx context.Context, subject string) ([]string, error) {
	if subject == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT client_id FROM subject_client_index
         WHERE subject = ?
         ORDER BY last_seen DESC`, subject)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list clients: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, fmt.Errorf("sqlite: scan client_id: %w", err)
		}
		out = append(out, cid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows iter: %w", err)
	}
	return out, nil
}

// Forget removes the (subject, client_id) pair. nil-safe on unknown
// pairs (DELETE just affects zero rows).
func (s *SubjectClientIndex) Forget(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        DELETE FROM subject_client_index
         WHERE subject = ? AND client_id = ?`,
		subject, clientID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: forget: %w", err)
	}
	return nil
}

var _ security.SubjectClientIndex = (*SubjectClientIndex)(nil)
