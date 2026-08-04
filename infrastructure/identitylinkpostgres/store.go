// Package identitylinkpostgres provides the shared Postgres/CockroachDB
// identity-link store used by multi-replica deployments.
package identitylinkpostgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/identitylink"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

const identityLinkSchema = `
CREATE TABLE IF NOT EXISTS identity_links (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    provider    TEXT NOT NULL,
    subject     TEXT NOT NULL,
    status      TEXT NOT NULL,
    linked_at   BIGINT NOT NULL,
    unlinked_at BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_links_active_subject
    ON identity_links(provider, subject) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_identity_links_user_active
    ON identity_links(user_id, status, linked_at, id);
`

var identityLinkMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: identityLinkSchema},
}

// Store is the shared Postgres/CockroachDB implementation.
type Store struct {
	db *sql.DB
}

// NewWithDB migrates and wraps the process-wide database pool. The caller
// retains pool ownership.
func NewWithDB(db *sql.DB, dialect postgresbackend.Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("identitylink/postgres: database is required")
	}
	if err := postgresbackend.Run(context.Background(), db, "identity_links", identityLinkMigrations, dialect); err != nil {
		return nil, fmt.Errorf("identitylink/postgres: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// DB exposes the shared pool for health/schema reporting.
func (s *Store) DB() *sql.DB { return s.db }

// Ping reports whether the shared store is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identitylink/postgres: store closed")
	}
	return s.db.PingContext(ctx)
}

// MaxVersion is the highest schema version understood by this binary.
func MaxVersion() int { return migrate.MaxVersion(identityLinkMigrations) }

var _ identitylink.Store = (*Store)(nil)
var _ identitylink.AtomicMerger = (*Store)(nil)
