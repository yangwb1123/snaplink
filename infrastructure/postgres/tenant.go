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
	"github.com/yangwb1123/snaplink/shared/core"
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

// tenantMembershipSchema belongs to an independent migration namespace because
// the optional roster can be enabled after the tenant tables already exist.
// Deliberately omit foreign keys: the memory and SQLite peers allow explicit
// membership edges independently of tenant/user record lifecycle.
const tenantMembershipSchema = `
CREATE TABLE IF NOT EXISTS tenant_memberships (
    tenant_id  TEXT   NOT NULL,
    user_id    TEXT   NOT NULL,
    role       TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_memberships_user_id
    ON tenant_memberships(user_id);
`

const tenantMembershipSchemaVersion = 1

var tenantMembershipMigrations = []migrate.Migration{
	{Version: tenantMembershipSchemaVersion, Name: "baseline_tenant_memberships", SQL: tenantMembershipSchema},
}

// TenantUserStore is the Postgres-backed explicit B2B roster. It wraps the
// caller-owned shared pool and must not close it.
type TenantUserStore struct {
	db *sql.DB
}

// NewTenantUserStoreWithDB migrates the membership namespace on an existing
// shared Postgres/CockroachDB pool and rejects a schema newer than this binary.
func NewTenantUserStoreWithDB(ctx context.Context, db *sql.DB, dialect Dialect) (*TenantUserStore, error) {
	if db == nil {
		return nil, errors.New("postgres: tenant membership store requires shared database")
	}
	if err := Run(ctx, db, "tenant_memberships", tenantMembershipMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate tenant memberships: %w", err)
	}
	version, err := TenantUserStoreSchemaVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	if version > tenantMembershipSchemaVersion {
		return nil, fmt.Errorf("%w: namespace %q is at v%d but binary only knows up to v%d",
			migrate.ErrSchemaTooNew, "tenant_memberships", version, tenantMembershipSchemaVersion)
	}
	return &TenantUserStore{db: db}, nil
}

// TenantUserStoreSchemaVersion reports the applied membership migration version.
func TenantUserStoreSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	table, err := versionTable("tenant_memberships")
	if err != nil {
		return 0, err
	}
	var version int
	if err := db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COALESCE(MAX(version), 0) FROM %s`, table)).Scan(&version); err != nil {
		return 0, fmt.Errorf("postgres: read tenant membership schema version: %w", err)
	}
	return version, nil
}

// Ping reports the health of the shared pool used by the membership store.
func (s *TenantUserStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: tenant membership store unavailable")
	}
	return s.db.PingContext(ctx)
}

// Add upserts one edge and refreshes the role and creation timestamp on updates.
func (s *TenantUserStore) Add(ctx context.Context, m *core.TenantMembership) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (tenant_id, user_id) DO UPDATE SET
            role = EXCLUDED.role,
            created_at = EXCLUDED.created_at`,
		m.TenantID, m.UserID, string(m.Role), m.CreatedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("postgres: add tenant membership: %w", err)
	}
	return nil
}

// Remove deletes an edge idempotently.
func (s *TenantUserStore) Remove(ctx context.Context, tenantID, userID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM tenant_memberships WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID); err != nil {
		return fmt.Errorf("postgres: remove tenant membership: %w", err)
	}
	return nil
}

// Get returns one edge or the oracle-safe shared ErrNoMembership sentinel.
func (s *TenantUserStore) Get(ctx context.Context, tenantID, userID string) (*core.TenantMembership, error) {
	var role string
	var createdAt int64
	err := s.db.QueryRowContext(ctx, `
        SELECT role, created_at FROM tenant_memberships
        WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID).Scan(&role, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrNoMembership
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get tenant membership: %w", err)
	}
	return &core.TenantMembership{
		TenantID: tenantID, UserID: userID, Role: core.TenantRole(role),
		CreatedAt: time.Unix(0, createdAt),
	}, nil
}

// ListByTenant returns a deterministic roster for one tenant.
func (s *TenantUserStore) ListByTenant(ctx context.Context, tenantID string) ([]*core.TenantMembership, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT user_id, role, created_at FROM tenant_memberships
        WHERE tenant_id = $1 ORDER BY user_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tenant memberships by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*core.TenantMembership
	for rows.Next() {
		var userID, role string
		var createdAt int64
		if err := rows.Scan(&userID, &role, &createdAt); err != nil {
			return nil, fmt.Errorf("postgres: scan tenant membership: %w", err)
		}
		out = append(out, &core.TenantMembership{
			TenantID: tenantID, UserID: userID, Role: core.TenantRole(role), CreatedAt: time.Unix(0, createdAt),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list tenant memberships by tenant: %w", err)
	}
	return out, nil
}

// ListByUser returns a deterministic list of the user's tenant memberships.
func (s *TenantUserStore) ListByUser(ctx context.Context, userID string) ([]*core.TenantMembership, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT tenant_id, role, created_at FROM tenant_memberships
        WHERE user_id = $1 ORDER BY tenant_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tenant memberships by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*core.TenantMembership
	for rows.Next() {
		var tenantID, role string
		var createdAt int64
		if err := rows.Scan(&tenantID, &role, &createdAt); err != nil {
			return nil, fmt.Errorf("postgres: scan tenant membership: %w", err)
		}
		out = append(out, &core.TenantMembership{
			TenantID: tenantID, UserID: userID, Role: core.TenantRole(role), CreatedAt: time.Unix(0, createdAt),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list tenant memberships by user: %w", err)
	}
	return out, nil
}

var _ core.TenantUserStore = (*TenantUserStore)(nil)
