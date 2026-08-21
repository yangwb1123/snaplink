// Package sqlite is a SQLite-backed [permissions.Provider] for
// multi-replica deployments. The in-memory peer loses state on
// restart and forks per-replica; this peer shares roles +
// assignments + menus across the cluster so admin
// AddRole/AssignRoles/SetMenus on one replica surface on every
// replica's next lookup.
//
// Four tables:
//
//   - roles(client_id, role_code) PK pair + name + description +
//     permissions (JSON array of permission codes).
//
//   - assignments(user_id, client_id) PK pair + roles (JSON array
//     of role codes). RemoveRole cascades a strip across this
//     table.
//
//   - menus(client_id) PK + tree (JSON-encoded MenuTree). Each
//     client has at most one menu tree.
//
//   - resources(id) PK + tenant/client/type/name uniqueness,
//     policy JSON, and dispatch columns for the runtime catalog.
//
//   - conflict declarations and session-active role rows for SSoD/DSoD.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite"
)

// migrations is the ordered schema history. v1 is the baseline (schema
// as shipped before versioned migrations) — pre-migration DBs no-op the
// IF NOT EXISTS statements and get stamped v1; future changes append.
var migrations = []migrate.Migration{
	{Version: 1, Name: "baseline_permissions", SQL: schema},
	{Version: 2, Name: "resource_catalog", SQL: resourceSchema},
	{Version: 3, Name: "separation_of_duty", SQL: sodSchema},
}

const schema = `
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

const resourceSchema = `
CREATE TABLE IF NOT EXISTS permissions_resources (
    id                         TEXT PRIMARY KEY,
    tenant_id                  TEXT NOT NULL DEFAULT '',
    client_id                  TEXT NOT NULL DEFAULT '',
    type                       TEXT NOT NULL,
    name                       TEXT NOT NULL,
    requires_auth              INTEGER NOT NULL DEFAULT 0,
    description                TEXT NOT NULL DEFAULT '',
    attributes_json            TEXT NOT NULL DEFAULT '{}',
    required_permissions_json  TEXT NOT NULL DEFAULT '[]',
    require_mode               TEXT NOT NULL DEFAULT '',
    created_at                 INTEGER NOT NULL,
    updated_at                 INTEGER NOT NULL,
    dispatch_key               TEXT NOT NULL DEFAULT '',
    dispatch_method            TEXT NOT NULL DEFAULT '',
    dispatch_segments          INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, client_id, type, name)
);

CREATE INDEX IF NOT EXISTS idx_permissions_resources_scope
    ON permissions_resources(tenant_id, client_id, type, name);

CREATE INDEX IF NOT EXISTS idx_permissions_resources_dispatch
    ON permissions_resources(tenant_id, client_id, dispatch_method, dispatch_segments);

CREATE INDEX IF NOT EXISTS idx_permissions_resources_dispatch_key
    ON permissions_resources(tenant_id, client_id, type, dispatch_key);
`

const sodSchema = `
CREATE TABLE IF NOT EXISTS permissions_conflict_sets (
    client_id  TEXT NOT NULL,
    mode       TEXT NOT NULL,
    set_index  INTEGER NOT NULL,
    role_code  TEXT NOT NULL,
    PRIMARY KEY (client_id, mode, set_index, role_code)
);

CREATE INDEX IF NOT EXISTS idx_permissions_conflicts_scope
    ON permissions_conflict_sets(client_id, mode, set_index);

CREATE TABLE IF NOT EXISTS permissions_active_roles (
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    session_id TEXT NOT NULL,
    role_code  TEXT NOT NULL,
    role_index INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id, session_id, role_code)
);

CREATE INDEX IF NOT EXISTS idx_permissions_active_session
    ON permissions_active_roles(user_id, client_id, session_id, role_index);
`

// Provider is the SQLite-backed [permissions.Provider].
type Provider struct {
	db *sql.DB
}

// New opens dsn, migrates the schema, returns the provider.
func New(dsn string) (*Provider, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("permissions/sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "permissions", migrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("permissions/sqlite: migrate: %w", err)
	}
	return &Provider{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB. Caller owns the connection
// lifecycle.
func NewWithDB(db *sql.DB) (*Provider, error) {
	if err := migrate.Run(context.Background(), db, "permissions", migrations); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: migrate: %w", err)
	}
	return &Provider{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (p *Provider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	err := p.db.Close()
	p.db = nil
	return err
}

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (p *Provider) DB() *sql.DB { return p.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (p *Provider) Ping(ctx context.Context) error {
	if p == nil || p.db == nil {
		return errors.New("permissions/sqlite: closed")
	}
	return p.db.PingContext(ctx)
}

// Compile-time interface assertions.
var (
	_ permissions.Provider              = (*Provider)(nil)
	_ permissions.MenuLister            = (*Provider)(nil)
	_ permissions.GroupMembershipWriter = (*Provider)(nil)
	_ permissions.ResourceProvider      = (*Provider)(nil)
	_ permissions.SoDProvider           = (*Provider)(nil)
	_ permissions.SessionRoleActivator  = (*Provider)(nil)
)
