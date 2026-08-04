// Package sqlite provides the durable SQLite identitylink.Store.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/identitylink"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite"
)

const identityLinkSchema = `
CREATE TABLE IF NOT EXISTS identity_links (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    provider    TEXT NOT NULL,
    subject     TEXT NOT NULL,
    status      TEXT NOT NULL,
    linked_at   INTEGER NOT NULL,
    unlinked_at INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_links_active_subject
    ON identity_links(provider, subject) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_identity_links_user_active
    ON identity_links(user_id, status, linked_at, id);
`

var identityLinkMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: identityLinkSchema},
}

// Store is the durable SQLite identity-link store.
type Store struct {
	db *sql.DB
}

// New opens dsn, verifies connectivity, and applies the schema.
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("identitylink/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("identitylink/sqlite: ping: %w", err)
	}
	store, err := NewWithDB(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// NewWithDB migrates and wraps a caller-owned database handle.
func NewWithDB(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("identitylink/sqlite: database is required")
	}
	if err := migrate.Run(context.Background(), db, "identity_links", identityLinkMigrations); err != nil {
		return nil, fmt.Errorf("identitylink/sqlite: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the database for schema and storage-health reporting.
func (s *Store) DB() *sql.DB { return s.db }

// Ping reports whether the store is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identitylink/sqlite: store closed")
	}
	return s.db.PingContext(ctx)
}

// MaxVersion is the highest schema version understood by this binary.
func MaxVersion() int { return migrate.MaxVersion(identityLinkMigrations) }

var _ identitylink.Store = (*Store)(nil)
var _ identitylink.AtomicMerger = (*Store)(nil)
