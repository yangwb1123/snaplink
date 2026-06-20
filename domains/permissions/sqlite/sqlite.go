// Package sqlite is a SQLite-backed [permissions.Provider] for
// multi-replica deployments. The in-memory peer loses state on
// restart and forks per-replica; this peer shares roles +
// assignments + menus across the cluster so admin
// AddRole/AssignRoles/SetMenus on one replica surface on every
// replica's next lookup.
//
// Three tables:
//   - roles(client_id, role_code) PK pair + name + description +
//     permissions (JSON array of permission codes).
//   - assignments(user_id, client_id) PK pair + roles (JSON array
//     of role codes). RemoveRole cascades a strip across this
//     table.
//   - menus(client_id) PK + tree (JSON-encoded MenuTree). Each
//     client has at most one menu tree.
//
// Resources (the operator-managed catalog the MemoryProvider also
// exposes via memory_resources.go) are NOT covered here — they
// live behind a separate Provider extension interface that admin
// tooling exercises directly; operators wanting cluster-shared
// resources can bring a Redis / future SQLite resource store
// alongside this one.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/migrate"

	_ "modernc.org/sqlite"
)

// migrations is the ordered schema history. v1 is the baseline (schema
// as shipped before versioned migrations) — pre-migration DBs no-op the
// IF NOT EXISTS statements and get stamped v1; future changes append.
var migrations = []migrate.Migration{
	{Version: 1, Name: "baseline_permissions", SQL: schema},
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
)
