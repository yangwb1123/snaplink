package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// permissionsMigrations is the ordered schema history. v1 is the baseline; the
// namespace string "permissions" is kept identical to the SQLite peer so a DB
// migrated by either backend reports the same version table.
var permissionsMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline_permissions", SQL: permissionsSchema},
}

// permissionsSchema is the Postgres baseline for the three permissions tables
// (roles, assignments, menus) mirroring the SQLite peer. All JSON arrays/maps
// are TEXT columns so the Go-side json marshalling stays byte-identical across
// backends; there are no boolean or nanosecond columns here.
const permissionsSchema = `
CREATE TABLE IF NOT EXISTS permissions_roles (
    client_id        TEXT NOT NULL,
    role_code        TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    permissions_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (client_id, role_code)
);

CREATE TABLE IF NOT EXISTS permissions_assignments (
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    roles_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS permissions_menus (
    client_id  TEXT PRIMARY KEY,
    menu_json  TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_permissions_assignments_client
    ON permissions_assignments(client_id);
`

// PermissionProvider is the Postgres-backed [permissions.Provider]
// (+ MenuLister + GroupMembershipWriter). It shares roles + assignments + menus
// across a multi-replica fleet so an admin AddRole/AssignRoles/SetMenus on one
// replica surfaces on every replica's next lookup. Semantics are pinned to the
// memory peer via permissionstest.ConformanceSuite.
type PermissionProvider struct {
	db      *sql.DB
	dialect Dialect
}

// NewPermissionProvider opens cfg.DSN, migrates the schema, and returns the
// provider.
func NewPermissionProvider(cfg Config) (*PermissionProvider, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	p, err := NewPermissionProviderWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return p, nil
}

// NewPermissionProviderWithDB wraps an existing shared *sql.DB. The caller owns
// the connection lifecycle (shared-pool deployments).
func NewPermissionProviderWithDB(db *sql.DB, dialect Dialect) (*PermissionProvider, error) {
	if err := Run(context.Background(), db, "permissions", permissionsMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate permissions: %w", err)
	}
	return &PermissionProvider{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool provider built via
// NewPermissionProviderWithDB should be closed by whoever owns the pool.
func (p *PermissionProvider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	err := p.db.Close()
	p.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (p *PermissionProvider) DB() *sql.DB { return p.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (p *PermissionProvider) Ping(ctx context.Context) error {
	if p == nil || p.db == nil {
		return errors.New("postgres: permission provider closed")
	}
	return p.db.PingContext(ctx)
}

// Compile-time interface assertions.
var (
	_ permissions.Provider              = (*PermissionProvider)(nil)
	_ permissions.MenuLister            = (*PermissionProvider)(nil)
	_ permissions.GroupMembershipWriter = (*PermissionProvider)(nil)
)
