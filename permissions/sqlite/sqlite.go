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
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/snaplink/sso/migrate"
	"github.com/snaplink/sso/permissions"

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

// --- Role CRUD ---

// AddRole inserts a role. Returns [permissions.ErrRoleExists] when
// the (client_id, role_code) PK collides — matches the memory
// peer's contract so admin RPCs translate uniformly.
func (p *Provider) AddRole(ctx context.Context, clientID string, role permissions.Role) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal permissions: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
        INSERT INTO permissions_roles (client_id, role_code, name, description, permissions_json)
        VALUES (?, ?, ?, ?, ?)`,
		clientID, role.Code, role.Name, role.Description, string(perms),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
			return permissions.ErrRoleExists
		}
		return fmt.Errorf("permissions/sqlite: insert role: %w", err)
	}
	return nil
}

// UpdateRole overwrites an existing role. Returns
// [permissions.ErrRoleNotFound] when the role doesn't exist —
// the SQL UPDATE with RowsAffected = 0 surfaces as the sentinel
// (not a silent no-op the memory peer would have produced via the
// in-memory check).
func (p *Provider) UpdateRole(ctx context.Context, clientID string, role permissions.Role) error {
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal permissions: %w", err)
	}
	res, err := p.db.ExecContext(ctx, `
        UPDATE permissions_roles
        SET name = ?, description = ?, permissions_json = ?
        WHERE client_id = ? AND role_code = ?`,
		role.Name, role.Description, string(perms),
		clientID, role.Code,
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: update role: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("permissions/sqlite: update role rowsaffected: %w", err)
	}
	if n == 0 {
		return permissions.ErrRoleNotFound
	}
	return nil
}

// RemoveRole drops the role definition AND strips it from every
// user's assignment list under the same client. The strip is
// done row-by-row because SQLite has no native JSON array filter
// (and the typical assignment row holds <10 codes so a load /
// rewrite cycle is fine). Wrapped in a transaction so concurrent
// readers don't see a partial state.
func (p *Provider) RemoveRole(ctx context.Context, clientID, roleCode string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin remove role: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
        DELETE FROM permissions_roles WHERE client_id = ? AND role_code = ?`,
		clientID, roleCode,
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: delete role: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("permissions/sqlite: delete role rowsaffected: %w", err)
	}
	if n == 0 {
		return permissions.ErrRoleNotFound
	}

	// Walk every assignment under clientID + strip roleCode if
	// present. The assignment table is per-client-indexed so this
	// is a bounded scan.
	rows, err := tx.QueryContext(ctx, `
        SELECT user_id, roles_json FROM permissions_assignments WHERE client_id = ?`,
		clientID,
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: scan assignments: %w", err)
	}
	type pending struct {
		userID string
		roles  []string
	}
	var updates []pending
	for rows.Next() {
		var userID, rolesJSON string
		if err := rows.Scan(&userID, &rolesJSON); err != nil {
			_ = rows.Close()
			return fmt.Errorf("permissions/sqlite: scan assignment row: %w", err)
		}
		var roles []string
		if rolesJSON != "" {
			if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
				_ = rows.Close()
				return fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
			}
		}
		filtered := make([]string, 0, len(roles))
		dirty := false
		for _, r := range roles {
			if r == roleCode {
				dirty = true
				continue
			}
			filtered = append(filtered, r)
		}
		if dirty {
			updates = append(updates, pending{userID: userID, roles: filtered})
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("permissions/sqlite: assignment rows: %w", err)
	}

	for _, u := range updates {
		raw, err := json.Marshal(u.roles)
		if err != nil {
			return fmt.Errorf("permissions/sqlite: marshal updated assignment: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
            UPDATE permissions_assignments SET roles_json = ?
            WHERE user_id = ? AND client_id = ?`,
			string(raw), u.userID, clientID,
		); err != nil {
			return fmt.Errorf("permissions/sqlite: strip assignment: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("permissions/sqlite: commit remove role: %w", err)
	}
	return nil
}

// ListAllRoles returns every role under clientID.
func (p *Provider) ListAllRoles(ctx context.Context, clientID string) ([]permissions.Role, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT role_code, name, description, permissions_json
        FROM permissions_roles WHERE client_id = ? ORDER BY role_code`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []permissions.Role
	for rows.Next() {
		var code, name, description, permsJSON string
		if err := rows.Scan(&code, &name, &description, &permsJSON); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan role: %w", err)
		}
		r := permissions.Role{Code: code, Name: name, Description: description}
		if permsJSON != "" && permsJSON != "[]" {
			if err := json.Unmarshal([]byte(permsJSON), &r.Permissions); err != nil {
				return nil, fmt.Errorf("permissions/sqlite: unmarshal role permissions: %w", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: role rows: %w", err)
	}
	if out == nil {
		out = []permissions.Role{}
	}
	return out, nil
}

// --- Assignments ---

// AssignRoles replaces the user's role set under clientID. The
// memory peer treats this as a SET (not merge); same here.
func (p *Provider) AssignRoles(ctx context.Context, userID, clientID string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	raw, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal assignment: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
        INSERT INTO permissions_assignments (user_id, client_id, roles_json)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, client_id) DO UPDATE SET roles_json = excluded.roles_json`,
		userID, clientID, string(raw),
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: assign roles: %w", err)
	}
	return nil
}

// UnassignRoles removes the listed role codes from the user's
// assignment under clientID. Codes not currently assigned are
// silently ignored (matches the memory peer).
func (p *Provider) UnassignRoles(ctx context.Context, userID, clientID string, roles []string) error {
	if len(roles) == 0 {
		return nil
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin unassign: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var current string
	row := tx.QueryRowContext(ctx, `
        SELECT roles_json FROM permissions_assignments
        WHERE user_id = ? AND client_id = ?`,
		userID, clientID,
	)
	if err := row.Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("permissions/sqlite: load assignment: %w", err)
	}
	var have []string
	if current != "" {
		if err := json.Unmarshal([]byte(current), &have); err != nil {
			return fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
		}
	}
	remove := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		remove[r] = struct{}{}
	}
	filtered := make([]string, 0, len(have))
	for _, r := range have {
		if _, drop := remove[r]; drop {
			continue
		}
		filtered = append(filtered, r)
	}
	if len(filtered) == len(have) {
		// No change — skip the write to avoid the transaction
		// commit overhead.
		return tx.Commit()
	}
	raw, err := json.Marshal(filtered)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal filtered assignment: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE permissions_assignments SET roles_json = ?
        WHERE user_id = ? AND client_id = ?`,
		string(raw), userID, clientID,
	); err != nil {
		return fmt.Errorf("permissions/sqlite: store filtered assignment: %w", err)
	}
	return tx.Commit()
}

// AddRoleToUser grants roleCode to userID under clientID without
// disturbing the user's other roles. Idempotent: re-adding an already-
// held role is a no-op. Implements [permissions.GroupMembershipWriter]
// (SCIM Group add-member). The load-append-store runs inside one
// transaction so a concurrent membership write can't lose this grant —
// the memory peer holds its mutex for the same window.
func (p *Provider) AddRoleToUser(ctx context.Context, userID, clientID, roleCode string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: begin add role to user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var current string
	row := tx.QueryRowContext(ctx, `
        SELECT roles_json FROM permissions_assignments
        WHERE user_id = ? AND client_id = ?`,
		userID, clientID,
	)
	if err := row.Scan(&current); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("permissions/sqlite: load assignment: %w", err)
	}
	var have []string
	if current != "" {
		if err := json.Unmarshal([]byte(current), &have); err != nil {
			return fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
		}
	}
	for _, r := range have {
		if r == roleCode {
			// Already a member — no write, just close the txn cleanly.
			return tx.Commit()
		}
	}
	have = append(have, roleCode)
	raw, err := json.Marshal(have)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal assignment: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO permissions_assignments (user_id, client_id, roles_json)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, client_id) DO UPDATE SET roles_json = excluded.roles_json`,
		userID, clientID, string(raw),
	); err != nil {
		return fmt.Errorf("permissions/sqlite: store assignment: %w", err)
	}
	return tx.Commit()
}

// RemoveRoleFromUser revokes roleCode from userID under clientID, leaving
// the user's other roles intact. Idempotent: removing a role the user
// doesn't hold is a no-op. Implements
// [permissions.GroupMembershipWriter] (SCIM Group remove-member). This is
// the single-code peer of UnassignRoles, kept distinct so the extension
// interface reads symmetrically with AddRoleToUser.
func (p *Provider) RemoveRoleFromUser(ctx context.Context, userID, clientID, roleCode string) error {
	return p.UnassignRoles(ctx, userID, clientID, []string{roleCode})
}

// ListAssignments returns every (user, []roleCodes) tuple under
// clientID with at least one role.
func (p *Provider) ListAssignments(ctx context.Context, clientID string) ([]permissions.Assignment, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT user_id, roles_json FROM permissions_assignments WHERE client_id = ?
        ORDER BY user_id`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: list assignments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]permissions.Assignment, 0)
	for rows.Next() {
		var userID, rolesJSON string
		if err := rows.Scan(&userID, &rolesJSON); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: scan assignment: %w", err)
		}
		var roles []string
		if rolesJSON != "" {
			if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
				return nil, fmt.Errorf("permissions/sqlite: unmarshal assignment: %w", err)
			}
		}
		if len(roles) == 0 {
			continue
		}
		out = append(out, permissions.Assignment{UserID: userID, Roles: roles})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: assignment rows: %w", err)
	}
	return out, nil
}

// --- Menus ---

// SetMenus replaces the client's menu tree. Empty tree is a valid
// "no navigation" state.
func (p *Provider) SetMenus(ctx context.Context, clientID string, menus permissions.MenuTree) error {
	if menus == nil {
		menus = permissions.MenuTree{}
	}
	raw, err := json.Marshal(menus)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: marshal menus: %w", err)
	}
	_, err = p.db.ExecContext(ctx, `
        INSERT INTO permissions_menus (client_id, menu_json) VALUES (?, ?)
        ON CONFLICT(client_id) DO UPDATE SET menu_json = excluded.menu_json`,
		clientID, string(raw),
	)
	if err != nil {
		return fmt.Errorf("permissions/sqlite: store menus: %w", err)
	}
	return nil
}

// GetMenus returns the unfiltered menu tree for clientID. Implements
// [permissions.MenuLister] so snapshot/admin tooling can round-trip
// the tree without the per-user filter.
func (p *Provider) GetMenus(ctx context.Context, clientID string) (permissions.MenuTree, error) {
	var raw string
	err := p.db.QueryRowContext(ctx, `
        SELECT menu_json FROM permissions_menus WHERE client_id = ?`,
		clientID,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return permissions.MenuTree{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: load menus: %w", err)
	}
	if raw == "" || raw == "[]" {
		return permissions.MenuTree{}, nil
	}
	var out permissions.MenuTree
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("permissions/sqlite: unmarshal menus: %w", err)
	}
	return out, nil
}

// --- Runtime queries ---

// Roles returns every Role object assigned to userID under
// clientID. Resolves the role-code list to full Role records via
// a second per-code lookup — operators with many roles per user
// can switch to a JOIN-based query without changing the Provider
// contract.
func (p *Provider) Roles(ctx context.Context, userID, clientID string) ([]permissions.Role, error) {
	var rolesJSON string
	err := p.db.QueryRowContext(ctx, `
        SELECT roles_json FROM permissions_assignments
        WHERE user_id = ? AND client_id = ?`,
		userID, clientID,
	).Scan(&rolesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, permissions.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("permissions/sqlite: load roles: %w", err)
	}
	var codes []string
	if rolesJSON != "" {
		if err := json.Unmarshal([]byte(rolesJSON), &codes); err != nil {
			return nil, fmt.Errorf("permissions/sqlite: unmarshal roles: %w", err)
		}
	}
	if len(codes) == 0 {
		return nil, permissions.ErrUserNotFound
	}
	all, err := p.ListAllRoles(ctx, clientID)
	if err != nil {
		return nil, err
	}
	byCode := make(map[string]permissions.Role, len(all))
	for _, r := range all {
		byCode[r.Code] = r
	}
	out := make([]permissions.Role, 0, len(codes))
	for _, c := range codes {
		if r, ok := byCode[c]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// Permissions returns the union of permission codes from the
// user's assigned roles under clientID, deduplicated.
func (p *Provider) Permissions(ctx context.Context, userID, clientID string) ([]permissions.Permission, error) {
	roles, err := p.Roles(ctx, userID, clientID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, r := range roles {
		for _, code := range r.Permissions {
			seen[code] = struct{}{}
		}
	}
	// Sort for deterministic output (memory peer iterates a map so
	// its order is undefined; sqlite returning sorted is a tighter
	// contract, won't break consumers who tolerate the looser one).
	codes := make([]string, 0, len(seen))
	for c := range seen {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	out := make([]permissions.Permission, 0, len(codes))
	for _, c := range codes {
		out = append(out, permissions.Permission{Code: c})
	}
	return out, nil
}

// Menus returns the per-user-filtered menu tree.
func (p *Provider) Menus(ctx context.Context, userID, clientID string) (permissions.MenuTree, error) {
	full, err := p.GetMenus(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if len(full) == 0 {
		return permissions.MenuTree{}, nil
	}
	perms, err := p.Permissions(ctx, userID, clientID)
	if err != nil {
		// User has no roles → empty filtered menu (the memory peer
		// returns the same — UIs render nothing rather than break).
		return permissions.MenuTree{}, nil
	}
	return permissions.FilterMenuTree(full, perms), nil
}

// Compile-time interface assertions.
var (
	_ permissions.Provider              = (*Provider)(nil)
	_ permissions.MenuLister            = (*Provider)(nil)
	_ permissions.GroupMembershipWriter = (*Provider)(nil)
)
