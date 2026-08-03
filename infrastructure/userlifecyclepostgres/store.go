// Package userlifecyclepostgres provides the shared Postgres/CockroachDB
// user-lifecycle store used by multi-replica deployments.
package userlifecyclepostgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

const lifecycleSchema = `
CREATE TABLE IF NOT EXISTS user_lifecycle_records (
    user_id       TEXT   PRIMARY KEY,
    state         TEXT   NOT NULL,
    updated_at_ns BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_lifecycle_state
    ON user_lifecycle_records(state, user_id);
CREATE TABLE IF NOT EXISTS user_lifecycle_history (
    user_id          TEXT   NOT NULL REFERENCES user_lifecycle_records(user_id) ON DELETE CASCADE,
    sequence         BIGINT NOT NULL,
    from_state       TEXT   NOT NULL,
    to_state         TEXT   NOT NULL,
    reason           TEXT   NOT NULL,
    actor            TEXT   NOT NULL,
    transition_at_ns BIGINT NOT NULL,
    PRIMARY KEY (user_id, sequence)
);
`

var lifecycleMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: lifecycleSchema},
}

// Store is the shared Postgres/CockroachDB implementation.
type Store struct {
	db *sql.DB
}

// NewWithDB migrates and wraps the process-wide database pool. The caller
// retains pool ownership.
func NewWithDB(db *sql.DB, dialect postgresbackend.Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("userlifecycle/postgres: database is required")
	}
	if err := postgresbackend.Run(context.Background(), db, "user_lifecycle", lifecycleMigrations, dialect); err != nil {
		return nil, fmt.Errorf("userlifecycle/postgres: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// DB exposes the shared pool for health/schema reporting.
func (s *Store) DB() *sql.DB { return s.db }

// Ping reports whether the shared store is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("userlifecycle/postgres: store closed")
	}
	return s.db.PingContext(ctx)
}

// MaxVersion is the highest schema version understood by this binary.
func MaxVersion() int { return migrate.MaxVersion(lifecycleMigrations) }

var _ userlifecycle.Store = (*Store)(nil)
var _ userlifecycle.StateReader = (*Store)(nil)
