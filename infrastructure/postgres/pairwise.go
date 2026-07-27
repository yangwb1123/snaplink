package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/security"
)

// pairwiseSubjectSchema is the baseline pairwise_subjects table (Postgres
// dialect). It covers the OIDC Core §8 per-sector subject reverse lookup:
// pairwise sub is opaque + one-way (SHA-256 of sector + local + salt), so
// resource handlers need a (pairwise -> local) map to load the local user
// record from a bearer token's `sub` claim. Both columns are TEXT; pairwise_sub
// is the primary key so MapPairwise upserts via ON CONFLICT and stays
// idempotent across re-issuances. The memory backend forks per replica — a
// token issued on replica A can't be resolved at /userinfo on replica B — which
// is exactly why this durable, shared store exists.
const pairwiseSubjectSchema = `
CREATE TABLE IF NOT EXISTS pairwise_subjects (
    pairwise_sub TEXT PRIMARY KEY,
    local_sub    TEXT NOT NULL
);
`

var pairwiseMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: pairwiseSubjectSchema},
}

// PairwiseSubjectStore is the Postgres-backed implementation of
// [security.PairwiseSubjectStore]. Replaces the memory pairwise store for
// multi-replica deployments — the mapping is durable + shared so every replica
// resolves bearer tokens consistently.
type PairwiseSubjectStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewPairwiseSubjectStore opens cfg.DSN, migrates the schema, and returns the
// store.
func NewPairwiseSubjectStore(cfg Config) (*PairwiseSubjectStore, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewPairwiseSubjectStoreWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewPairwiseSubjectStoreWithDB wraps an existing shared *sql.DB. The caller
// owns the connection lifecycle (shared-pool deployments).
func NewPairwiseSubjectStoreWithDB(db *sql.DB, dialect Dialect) (*PairwiseSubjectStore, error) {
	if err := Run(context.Background(), db, "pairwise", pairwiseMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate pairwise_subjects: %w", err)
	}
	return &PairwiseSubjectStore{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool store built via
// NewPairwiseSubjectStoreWithDB should be closed by whoever owns the pool, not
// here — but Close is safe either way (database/sql Close is idempotent).
func (s *PairwiseSubjectStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (s *PairwiseSubjectStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *PairwiseSubjectStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: pairwise subject store closed")
	}
	return s.db.PingContext(ctx)
}

// MapPairwise upserts the (pairwise_sub -> local_sub) mapping. Idempotent per
// the SPI contract — calling twice for the same pair just overwrites the same
// value, atomically via ON CONFLICT.
func (s *PairwiseSubjectStore) MapPairwise(ctx context.Context, pairwiseSub, localSub string) error {
	if pairwiseSub == "" || localSub == "" {
		return errors.New("pairwise: empty sub")
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO pairwise_subjects (pairwise_sub, local_sub)
        VALUES ($1, $2)
        ON CONFLICT (pairwise_sub) DO UPDATE SET local_sub = EXCLUDED.local_sub`,
		pairwiseSub, localSub,
	)
	if err != nil {
		return fmt.Errorf("postgres: map pairwise: %w", err)
	}
	return nil
}

// LocalSubject implements PairwiseSubjectStore. Returns ErrPairwiseUnknown when
// no mapping exists — resource handlers reject the bearer token with the same
// wire shape they use for unknown tokens (oracle resistance).
func (s *PairwiseSubjectStore) LocalSubject(ctx context.Context, pairwiseSub string) (string, error) {
	if pairwiseSub == "" {
		return "", security.ErrPairwiseUnknown
	}
	row := s.db.QueryRowContext(ctx, `
        SELECT local_sub FROM pairwise_subjects WHERE pairwise_sub = $1`,
		pairwiseSub,
	)
	var local string
	if err := row.Scan(&local); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", security.ErrPairwiseUnknown
		}
		return "", fmt.Errorf("postgres: pairwise lookup: %w", err)
	}
	return local, nil
}

var _ security.PairwiseSubjectStore = (*PairwiseSubjectStore)(nil)
