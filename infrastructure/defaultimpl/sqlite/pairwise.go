package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/snaplink/sso/shared/security"
)

// pairwiseSubjectSchema covers the OIDC Core §8 per-sector subject
// reverse lookup. Pairwise sub is opaque + one-way (SHA-256 of
// sector + local + salt), so resource handlers need a (pairwise →
// local) map to load the local user record from a bearer token's
// `sub` claim. Memory backend forks per replica — a token issued on
// replica A can't be resolved at /userinfo on replica B.
const pairwiseSubjectSchema = `
CREATE TABLE IF NOT EXISTS pairwise_subjects (
    pairwise_sub TEXT PRIMARY KEY,
    local_sub    TEXT NOT NULL
);
`

// PairwiseSubjectStore is the SQLite-backed implementation of
// [security.PairwiseSubjectStore]. Replaces memory pairwise for
// multi-replica deployments — the mapping is durable + shared so
// every replica resolves bearer tokens consistently.
type PairwiseSubjectStore struct {
	db *sql.DB
}

// NewPairwiseSubjectStore opens dsn, migrates the schema, and
// returns the store.
func NewPairwiseSubjectStore(dsn string) (*PairwiseSubjectStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "pairwise", pairwiseSubjectSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate pairwise_subjects: %w", err)
	}
	return &PairwiseSubjectStore{db: db}, nil
}

// NewPairwiseSubjectStoreWithDB wraps an existing *sql.DB
// (shared-pool deployments).
func NewPairwiseSubjectStoreWithDB(db *sql.DB) (*PairwiseSubjectStore, error) {
	if err := ensureSchema(db, "pairwise", pairwiseSubjectSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate pairwise_subjects: %w", err)
	}
	return &PairwiseSubjectStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *PairwiseSubjectStore) Close() error {
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
func (s *PairwiseSubjectStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *PairwiseSubjectStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: pairwise subject store closed")
	}
	return s.db.PingContext(ctx)
}

// MapPairwise upserts the (pairwise_sub → local_sub) mapping.
// Idempotent per the SPI contract — calling twice for the same pair
// just overwrites the same value.
func (s *PairwiseSubjectStore) MapPairwise(ctx context.Context, pairwiseSub, localSub string) error {
	if pairwiseSub == "" || localSub == "" {
		return errors.New("pairwise: empty sub")
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO pairwise_subjects (pairwise_sub, local_sub)
        VALUES (?, ?)
        ON CONFLICT (pairwise_sub) DO UPDATE SET local_sub = excluded.local_sub`,
		pairwiseSub, localSub,
	)
	if err != nil {
		return fmt.Errorf("sqlite: map pairwise: %w", err)
	}
	return nil
}

// LocalSubject implements PairwiseSubjectStore. Returns
// ErrPairwiseUnknown when no mapping exists — resource handlers
// reject the bearer token with the same wire shape they use for
// unknown tokens.
func (s *PairwiseSubjectStore) LocalSubject(ctx context.Context, pairwiseSub string) (string, error) {
	if pairwiseSub == "" {
		return "", security.ErrPairwiseUnknown
	}
	row := s.db.QueryRowContext(ctx, `
        SELECT local_sub FROM pairwise_subjects WHERE pairwise_sub = ?`,
		pairwiseSub,
	)
	var local string
	if err := row.Scan(&local); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", security.ErrPairwiseUnknown
		}
		return "", fmt.Errorf("sqlite: pairwise lookup: %w", err)
	}
	return local, nil
}

var _ security.PairwiseSubjectStore = (*PairwiseSubjectStore)(nil)
