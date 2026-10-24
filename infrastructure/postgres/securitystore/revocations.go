package securitystore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

const revocationSchema = `
CREATE TABLE IF NOT EXISTS revocations (token TEXT PRIMARY KEY, exp BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_revocations_exp ON revocations(exp);
`

// Startup must not return a partial deny-set or allocate an unbounded map.
const maxRevocations = 100_000
const maxRevocationTokenBytes = 16 << 20

var revocationMigrations = []migrate.Migration{{Version: 1, Name: "baseline", SQL: revocationSchema}}

func RevocationsMaxVersion() int { return migrate.MaxVersion(revocationMigrations) }

type RevocationStore struct{ *store }

func NewRevocationStoreWithDB(db *sql.DB, dialect pg.Dialect) (*RevocationStore, error) {
	s, err := openStore(db, dialect, "revocations", revocationMigrations)
	if err != nil {
		return nil, err
	}
	return &RevocationStore{store: s}, nil
}

func (s *RevocationStore) Revoke(ctx context.Context, token string, expiry int64) error {
	db, err := s.pool()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "INSERT INTO revocations(token,exp) VALUES($1,$2) ON CONFLICT(token) DO UPDATE SET exp=excluded.exp", token, expiry)
	if err != nil {
		return fmt.Errorf("postgres: insert revocation: %w", err)
	}
	return nil
}

func (s *RevocationStore) Prune(ctx context.Context, now int64) error {
	db, err := s.pool()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "DELETE FROM revocations WHERE exp<$1", now)
	return err
}

func (s *RevocationStore) Load(ctx context.Context) (map[string]int64, error) {
	now := time.Now().Unix()
	if err := s.Prune(ctx, now); err != nil {
		return nil, fmt.Errorf("postgres: prune revocations: %w", err)
	}
	db, err := s.pool()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, "SELECT token,exp FROM revocations WHERE exp>=$1 LIMIT $2", now, maxRevocations+1)
	if err != nil {
		return nil, fmt.Errorf("postgres: load revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return collectRevocations(rows)
}

func collectRevocations(rows *sql.Rows) (map[string]int64, error) {
	out, total := make(map[string]int64), 0
	for rows.Next() {
		var token string
		var expiry int64
		if err := rows.Scan(&token, &expiry); err != nil {
			return nil, err
		}
		if len(out) >= maxRevocations || len(token) > maxRevocationTokenBytes-total {
			return nil, fmt.Errorf("postgres: complete revocation deny-set exceeds startup budget")
		}
		total += len(token)
		out[token] = expiry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

var _ defaultimpl.RevocationStore = (*RevocationStore)(nil)
