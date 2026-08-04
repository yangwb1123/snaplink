// Package tenantquota provides a durable PostgreSQL/CockroachDB implementation
// of core.TenantQuotaStore.
package tenantquota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

const schema = `
CREATE TABLE IF NOT EXISTS tenant_quota_state (
    tenant_id TEXT PRIMARY KEY CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    max_clients BIGINT NOT NULL DEFAULT 0 CHECK (max_clients >= 0),
    max_users BIGINT NOT NULL DEFAULT 0 CHECK (max_users >= 0),
    max_sessions BIGINT NOT NULL DEFAULT 0 CHECK (max_sessions >= 0),
    max_token_rate BIGINT NOT NULL DEFAULT 0 CHECK (max_token_rate >= 0),
    clients_limited BOOLEAN NOT NULL DEFAULT FALSE,
    users_limited BOOLEAN NOT NULL DEFAULT FALSE,
    sessions_limited BOOLEAN NOT NULL DEFAULT FALSE,
    token_rate_limited BOOLEAN NOT NULL DEFAULT FALSE,
    quota_revision BIGINT NOT NULL DEFAULT 0 CHECK (quota_revision >= 0),
    clients BIGINT NOT NULL DEFAULT 0 CHECK (clients >= 0),
    users BIGINT NOT NULL DEFAULT 0 CHECK (users >= 0),
    sessions BIGINT NOT NULL DEFAULT 0 CHECK (sessions >= 0),
    clients_generation BIGINT NOT NULL DEFAULT 0 CHECK (clients_generation >= 0),
    users_generation BIGINT NOT NULL DEFAULT 0 CHECK (users_generation >= 0),
    sessions_generation BIGINT NOT NULL DEFAULT 0 CHECK (sessions_generation >= 0),
    token_clock_second BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tenant_quota_resource_leases (
    tenant_id TEXT NOT NULL REFERENCES tenant_quota_state(tenant_id) ON DELETE CASCADE,
    resource TEXT NOT NULL CHECK (resource IN ('clients', 'users', 'sessions')),
    resource_id TEXT NOT NULL CHECK (resource_id <> '' AND resource_id = btrim(resource_id) AND octet_length(resource_id) <= 512),
    active BOOLEAN NOT NULL,
    PRIMARY KEY (tenant_id, resource, resource_id)
);
CREATE TABLE IF NOT EXISTS tenant_quota_token_windows (
    tenant_id TEXT NOT NULL REFERENCES tenant_quota_state(tenant_id) ON DELETE CASCADE,
    window_second BIGINT NOT NULL,
    quantity BIGINT NOT NULL CHECK (quantity > 0),
    PRIMARY KEY (tenant_id, window_second)
);
CREATE INDEX IF NOT EXISTS idx_tenant_quota_token_windows_expiry
    ON tenant_quota_token_windows(window_second, tenant_id);
`

const versionedResourceSchema = `
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS clients_limited BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS users_limited BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS sessions_limited BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS token_rate_limited BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS quota_revision BIGINT NOT NULL DEFAULT 0 CHECK (quota_revision >= 0);
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS clients_generation BIGINT NOT NULL DEFAULT 0 CHECK (clients_generation >= 0);
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS users_generation BIGINT NOT NULL DEFAULT 0 CHECK (users_generation >= 0);
ALTER TABLE tenant_quota_state ADD COLUMN IF NOT EXISTS sessions_generation BIGINT NOT NULL DEFAULT 0 CHECK (sessions_generation >= 0);
CREATE TABLE IF NOT EXISTS tenant_quota_resource_leases (
    tenant_id TEXT NOT NULL REFERENCES tenant_quota_state(tenant_id) ON DELETE CASCADE,
    resource TEXT NOT NULL CHECK (resource IN ('clients', 'users', 'sessions')),
    resource_id TEXT NOT NULL CHECK (resource_id <> '' AND resource_id = btrim(resource_id) AND octet_length(resource_id) <= 512),
    active BOOLEAN NOT NULL,
    PRIMARY KEY (tenant_id, resource, resource_id)
);
`

var migrations = []migrate.Migration{
	{Version: 1, Name: "tenant quota baseline", SQL: schema},
	{Version: 2, Name: "versioned quota resource leases", SQL: versionedResourceSchema},
}

// Store shares the caller-owned database pool with the other Postgres stores.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// NewWithDB migrates and returns a tenant quota store over db. The caller owns
// db and may share it with every other durable adapter.
func NewWithDB(db *sql.DB, dialect postgresbackend.Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("tenantquota/postgres: database is required")
	}
	if err := postgresbackend.Run(context.Background(), db, "tenant_quota", migrations, dialect); err != nil {
		return nil, fmt.Errorf("tenantquota/postgres: migrate: %w", err)
	}
	return newWithClock(db, time.Now), nil
}

func newWithClock(db *sql.DB, now func() time.Time) *Store {
	return &Store{db: db, now: now}
}

// DB returns the caller-owned shared pool.
func (s *Store) DB() *sql.DB { return s.db }

// Ping reports whether the backing pool is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("tenantquota/postgres: store closed")
	}
	return s.db.PingContext(ctx)
}

// MaxVersion is the highest schema migration understood by this binary.
func MaxVersion() int { return migrate.MaxVersion(migrations) }

const transactionRetries = 32

func runLocked(ctx context.Context, db *sql.DB, operation func(*sql.Tx) error) error {
	var err error
	for range transactionRetries {
		err = runLockedOnce(ctx, db, operation)
		if err == nil || !serializationFailure(err) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}

func runLockedOnce(ctx context.Context, db *sql.DB, operation func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func serializationFailure(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "40001"
}

var _ core.TenantQuotaStore = (*Store)(nil)
var _ core.TenantQuotaResourceStore = (*Store)(nil)
var _ core.TenantQuotaProjectionStore = (*Store)(nil)
var _ core.TenantQuotaWindowCleaner = (*Store)(nil)
