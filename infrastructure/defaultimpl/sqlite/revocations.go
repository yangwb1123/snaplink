package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/migrate"
)

// revocationSchema is the v1 baseline for the access-token revocation deny-set:
// one row per revoked token, keyed by the full token string, valued by its
// `exp` (unix seconds). A row is only needed until exp passes (the token is
// rejected on expiry anyway), so the store prunes lazily. Backs
// defaultimpl.RevocationStore so a revocation survives a process restart /
// rolling deploy — on boot each replica re-seeds its in-process deny-set from
// here (defaultimpl issuer SeedRevocations).
const revocationSchema = `
CREATE TABLE IF NOT EXISTS revocations (
    token TEXT    PRIMARY KEY,
    exp   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revocations_exp ON revocations(exp);
`

var revocationMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: revocationSchema},
}

// RevocationStore is the SQLite-backed defaultimpl.RevocationStore. On a SHARED
// database it is a multi-replica durable deny-set: every replica re-seeds its
// in-process map from here at boot, so a token revoked before a restart stays
// revoked. (Live cross-replica propagation is the separate cluster bus; this
// closes the orthogonal restart/late-join gap.)
type RevocationStore struct {
	db *sql.DB
}

// NewRevocationStore opens dsn, migrates, and returns the store.
func NewRevocationStore(dsn string) (*RevocationStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "revocations", revocationMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate revocations: %w", err)
	}
	return &RevocationStore{db: db}, nil
}

// NewRevocationStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewRevocationStoreWithDB(db *sql.DB) *RevocationStore {
	_ = migrate.Run(context.Background(), db, "revocations", revocationMigrations)
	return &RevocationStore{db: db}
}

// Close releases the connection. Idempotent.
func (s *RevocationStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *RevocationStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *RevocationStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: revocation store closed")
	}
	return s.db.PingContext(ctx)
}

// Revoke records token revoked until expUnix (idempotent upsert).
func (s *RevocationStore) Revoke(ctx context.Context, token string, expUnix int64) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO revocations (token, exp) VALUES (?, ?)
		 ON CONFLICT(token) DO UPDATE SET exp = excluded.exp`,
		token, expUnix); err != nil {
		return fmt.Errorf("sqlite: insert revocation: %w", err)
	}
	return nil
}

// Load returns every still-valid revocation (exp >= now), pruning expired rows
// first so the table + the returned map stay bounded.
func (s *RevocationStore) Load(ctx context.Context) (map[string]int64, error) {
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM revocations WHERE exp < ?`, now); err != nil {
		return nil, fmt.Errorf("sqlite: prune revocations: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT token, exp FROM revocations WHERE exp >= ?`, now)
	if err != nil {
		return nil, fmt.Errorf("sqlite: load revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]int64)
	for rows.Next() {
		var token string
		var exp int64
		if err := rows.Scan(&token, &exp); err != nil {
			return nil, fmt.Errorf("sqlite: scan revocation: %w", err)
		}
		out[token] = exp
	}
	return out, rows.Err()
}

// Prune drops entries whose exp is strictly before nowUnix.
func (s *RevocationStore) Prune(ctx context.Context, nowUnix int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM revocations WHERE exp < ?`, nowUnix); err != nil {
		return fmt.Errorf("sqlite: prune revocations: %w", err)
	}
	return nil
}
