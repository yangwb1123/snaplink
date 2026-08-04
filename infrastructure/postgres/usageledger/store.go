// Package usageledger provides durable PostgreSQL/CockroachDB storage for
// invoice-grade usage facts, quota reservations, period rollups, and outbox
// delivery state.
package usageledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

const schema = `
CREATE TABLE IF NOT EXISTS usage_ledger_buckets (
    tenant_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    period_start_ns BIGINT NOT NULL,
    period_end_ns BIGINT NOT NULL CHECK (period_end_ns > period_start_ns),
    committed_quantity BIGINT NOT NULL DEFAULT 0 CHECK (committed_quantity >= 0),
    reserved_quantity BIGINT NOT NULL DEFAULT 0 CHECK (reserved_quantity >= 0),
    fact_count BIGINT NOT NULL DEFAULT 0 CHECK (fact_count >= 0),
    closed BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at_ns BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, dimension, period_start_ns, period_end_ns)
);
CREATE TABLE IF NOT EXISTS usage_ledger_facts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_system TEXT NOT NULL,
    dimension TEXT NOT NULL,
    quantity BIGINT NOT NULL CHECK (quantity > 0),
    period_start_ns BIGINT NOT NULL,
    period_end_ns BIGINT NOT NULL,
    idempotency_key TEXT NOT NULL,
    occurred_at_ns BIGINT NOT NULL,
    created_at_ns BIGINT NOT NULL,
    metadata JSONB NOT NULL,
    UNIQUE (tenant_id, source_system, dimension, idempotency_key),
    FOREIGN KEY (tenant_id, dimension, period_start_ns, period_end_ns)
        REFERENCES usage_ledger_buckets(tenant_id, dimension, period_start_ns, period_end_ns)
);
CREATE INDEX IF NOT EXISTS idx_usage_ledger_facts_period
    ON usage_ledger_facts(tenant_id, dimension, period_start_ns, period_end_ns, occurred_at_ns, id);
CREATE TABLE IF NOT EXISTS usage_ledger_reservations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_system TEXT NOT NULL,
    dimension TEXT NOT NULL,
    quantity BIGINT NOT NULL CHECK (quantity > 0),
    period_start_ns BIGINT NOT NULL,
    period_end_ns BIGINT NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'committed', 'released', 'expired')),
    limit_soft BIGINT NOT NULL CHECK (limit_soft >= 0),
    limit_hard BIGINT NOT NULL CHECK (limit_hard >= 0),
    limit_unlimited BOOLEAN NOT NULL,
    expires_at_ns BIGINT NOT NULL,
    fact_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    created_at_ns BIGINT NOT NULL,
    updated_at_ns BIGINT NOT NULL,
    UNIQUE (tenant_id, source_system, dimension, idempotency_key),
    FOREIGN KEY (tenant_id, dimension, period_start_ns, period_end_ns)
        REFERENCES usage_ledger_buckets(tenant_id, dimension, period_start_ns, period_end_ns)
);
CREATE INDEX IF NOT EXISTS idx_usage_ledger_reservations_expiry
    ON usage_ledger_reservations(status, expires_at_ns, id);
CREATE INDEX IF NOT EXISTS idx_usage_ledger_reservations_period
    ON usage_ledger_reservations(tenant_id, dimension, period_start_ns, period_end_ns, status);
CREATE TABLE IF NOT EXISTS usage_ledger_rollups (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    period_start_ns BIGINT NOT NULL,
    period_end_ns BIGINT NOT NULL,
    quantity BIGINT NOT NULL CHECK (quantity >= 0),
    fact_count BIGINT NOT NULL CHECK (fact_count >= 0),
    version BIGINT NOT NULL CHECK (version > 0),
    digest TEXT NOT NULL,
    closed_at_ns BIGINT NOT NULL,
    UNIQUE (tenant_id, dimension, period_start_ns, period_end_ns),
    FOREIGN KEY (tenant_id, dimension, period_start_ns, period_end_ns)
        REFERENCES usage_ledger_buckets(tenant_id, dimension, period_start_ns, period_end_ns)
);
CREATE TABLE IF NOT EXISTS usage_ledger_outbox (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_version BIGINT NOT NULL CHECK (aggregate_version > 0),
    idempotency_key TEXT NOT NULL,
    occurred_at_ns BIGINT NOT NULL,
    payload JSONB NOT NULL,
    payload_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'delivered', 'quarantined', 'dead')),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    next_attempt_at_ns BIGINT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_until_ns BIGINT NOT NULL,
    last_error TEXT NOT NULL,
    delivered_at_ns BIGINT NOT NULL,
    created_at_ns BIGINT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_usage_ledger_outbox_claim
    ON usage_ledger_outbox(status, next_attempt_at_ns, lease_until_ns, created_at_ns, id);
`

const sourceBindingSchema = `
CREATE TABLE IF NOT EXISTS usage_source_bindings (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    source_system TEXT NOT NULL,
    allowed_dimensions JSONB NOT NULL,
    enabled BOOLEAN NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at_ns BIGINT NOT NULL,
    updated_at_ns BIGINT NOT NULL CHECK (updated_at_ns >= created_at_ns)
);
CREATE INDEX IF NOT EXISTS idx_usage_source_bindings_client
    ON usage_source_bindings(client_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_usage_source_bindings_enabled_client
    ON usage_source_bindings(client_id) WHERE enabled;
`

var migrations = []migrate.Migration{
	{Version: 1, Name: "invoice usage ledger baseline", SQL: schema},
	{Version: 2, Name: "machine source identity bindings", SQL: sourceBindingSchema},
}

type Store struct {
	db *sql.DB
}

func NewWithDB(db *sql.DB, dialect postgresbackend.Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("usageledger/postgres: database is required")
	}
	if err := postgresbackend.Run(context.Background(), db, "usage_ledger", migrations, dialect); err != nil {
		return nil, fmt.Errorf("usageledger/postgres: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("usageledger/postgres: store closed")
	}
	return s.db.PingContext(ctx)
}

func MaxVersion() int { return migrate.MaxVersion(migrations) }

const transactionRetries = 32

// runLocked uses row locks as the concurrency boundary. PostgreSQL's default
// READ COMMITTED avoids SSI abort storms on a hot quota bucket; CockroachDB's
// default remains SERIALIZABLE and is retried on its restart signal.
func runLocked(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	var err error
	for range transactionRetries {
		err = runLockedOnce(ctx, db, fn)
		if err == nil || !serializationFailure(err) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}

func runLockedOnce(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func serializationFailure(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "40001"
}

func uniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

var _ ledger.Store = (*Store)(nil)
