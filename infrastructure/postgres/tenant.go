// Package postgres's tenant store is a Postgres-wire (PostgreSQL / CockroachDB)
// backed [tenant.Store] for multi-replica deployments. It shares Tenants +
// Domains across the cluster so admin SetTenantStatus on replica A surfaces on
// every replica (after the tenant-suspension cache TTL elapses + the operator
// triggers invalidation via Server.InvalidateTenantSuspensionCache).
//
// Two tables: tenants (keyed by id, plus a UNIQUE constraint on slug) and
// tenant_domains (keyed by hostname, FK -> tenants.id ON DELETE CASCADE so
// DeleteTenant wipes orphan domains natively — no per-connection PRAGMA needed,
// unlike the SQLite peer). Settings + Branding map[string]string columns are
// JSON-encoded TEXT; we never query into them, so full-row reads suffice. Time
// columns are BIGINT Unix-nanoseconds (NOT timestamptz — exact round-trip);
// bool columns are INTEGER 0/1 (kept, not BOOLEAN, so the scan path matches the
// sqlite peer byte-for-byte).
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// tenantSchema is the Postgres baseline for both tenant tables. Unlike the
// SQLite peer (which grew the tenants table across v1+v2+v3 ALTER migrations)
// the Postgres backend starts fresh, so the residency columns (home_region,
// allowed_regions_json, enforce_writes) land in the same baseline. The FK uses
// ON DELETE CASCADE so DeleteTenant cascades to tenant_domains without any
// connection-level foreign-keys pragma (Postgres enforces FKs always).
const tenantSchema = `
CREATE TABLE IF NOT EXISTS tenants (
    id                   TEXT    PRIMARY KEY,
    slug                 TEXT    NOT NULL UNIQUE,
    name                 TEXT    NOT NULL DEFAULT '',
    status               TEXT    NOT NULL DEFAULT 'active',
    settings_json        TEXT    NOT NULL DEFAULT '',
    home_region          TEXT    NOT NULL DEFAULT '',
    allowed_regions_json TEXT    NOT NULL DEFAULT '[]',
    enforce_writes       INTEGER NOT NULL DEFAULT 0,
    created_at           BIGINT  NOT NULL,
    updated_at           BIGINT  NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_domains (
    hostname          TEXT    PRIMARY KEY,
    tenant_id         TEXT    NOT NULL,
    default_client_id TEXT    NOT NULL DEFAULT '',
    is_apex           INTEGER NOT NULL DEFAULT 0,
    branding_json     TEXT    NOT NULL DEFAULT '',
    created_at        BIGINT  NOT NULL,
    updated_at        BIGINT  NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant_id
    ON tenant_domains(tenant_id);
`

// tenantMigrations keeps the SAME "tenant" namespace string the SQLite peer
// uses (migrate.Run(..., "tenant", ...)). The Postgres backend folds the
// sqlite v1+v2+v3 schema into one fresh baseline.
var tenantMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline_tenants", SQL: tenantSchema},
}

// TenantStore is the Postgres-backed [tenant.Store]. Concurrent readers safe;
// writes serialize on the row/constraint locks.
type TenantStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewTenantStore opens cfg.DSN, migrates the schema, and returns the store.
func NewTenantStore(cfg Config) (*TenantStore, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewTenantStoreWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewTenantStoreWithDB wraps an existing shared *sql.DB. The caller owns the
// connection lifecycle (shared-pool deployments).
func NewTenantStoreWithDB(db *sql.DB, dialect Dialect) (*TenantStore, error) {
	if err := Run(context.Background(), db, "tenant", tenantMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate tenant: %w", err)
	}
	return &TenantStore{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool store built via
// NewTenantStoreWithDB should be closed by whoever owns the pool, not here —
// but Close is safe either way (database/sql Close is idempotent).
func (s *TenantStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (s *TenantStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *TenantStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: tenant store closed")
	}
	return s.db.PingContext(ctx)
}

// --- Tenants ---

func (s *TenantStore) GetTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT slug, name, status, settings_json, home_region, allowed_regions_json, enforce_writes, created_at, updated_at
        FROM tenants WHERE id = $1`, id)
	t, err := scanTenant(id, row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrTenantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get tenant: %w", err)
	}
	return t, nil
}

func (s *TenantStore) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, slug, name, status, settings_json, home_region, allowed_regions_json, enforce_writes, created_at, updated_at
        FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanTenantRows(rows)
}

func (s *TenantStore) PutTenant(ctx context.Context, t *tenant.Tenant) error {
	if err := t.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC().UnixNano()
	cols, err := encodeTenantColumns(t, now)
	if err != nil {
		return err
	}
	// UPSERT: on conflict by id, preserve created_at (matches the memory peer's
	// behavior — operator updates don't reset the creation timestamp).
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO tenants (id, slug, name, status, settings_json, home_region, allowed_regions_json, enforce_writes, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (id) DO UPDATE SET
            slug = EXCLUDED.slug,
            name = EXCLUDED.name,
            status = EXCLUDED.status,
            settings_json = EXCLUDED.settings_json,
            home_region = EXCLUDED.home_region,
            allowed_regions_json = EXCLUDED.allowed_regions_json,
            enforce_writes = EXCLUDED.enforce_writes,
            updated_at = EXCLUDED.updated_at`,
		t.ID, t.Slug, t.Name, string(t.Status), cols.settingsJSON, t.HomeRegion, cols.allowedRegionsJSON, cols.enforceWrites, cols.createdAt, now,
	)
	if err != nil {
		// A different id reusing an existing slug collides on the slug UNIQUE
		// constraint (NOT the id ON CONFLICT target), surfacing as SQLSTATE
		// 23505. Admin RPCs map it to ErrTenantExists (matches the memory peer's
		// contract — different tenants can't share a slug).
		if isUniqueViolation(err) {
			return tenant.ErrTenantExists
		}
		return fmt.Errorf("postgres: put tenant: %w", err)
	}
	return nil
}

func (s *TenantStore) DeleteTenant(ctx context.Context, id string) error {
	// FOREIGN KEY ON DELETE CASCADE handles the tenant_domains side — same
	// orphan-prevention the memory peer enforces inline.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id); err != nil {
		return fmt.Errorf("postgres: delete tenant: %w", err)
	}
	return nil
}

var _ tenant.Store = (*TenantStore)(nil)
