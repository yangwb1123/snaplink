package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

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
