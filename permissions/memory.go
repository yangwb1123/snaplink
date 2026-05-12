package permissions

import (
	"context"
	"sync"
)

// MemoryProvider is a process-local Provider backed by static role/menu maps.
// Use it for development, single-node deployments, or as a reference impl
// when wiring a database-backed Provider.
//
// Data model:
//
//	rolesByClient[clientID][roleCode]              = Role
//	menusByClient[clientID]                        = MenuTree (unfiltered)
//	assignmentsByUser[userID][clientID]            = []roleCode
type MemoryProvider struct {
	mu                sync.RWMutex
	rolesByClient     map[string]map[string]Role
	menusByClient     map[string]MenuTree
	assignmentsByUser map[string]map[string][]string
}

func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{
		rolesByClient:     make(map[string]map[string]Role),
		menusByClient:     make(map[string]MenuTree),
		assignmentsByUser: make(map[string]map[string][]string),
	}
}

// AddRole registers a role definition for the given client.
func (m *MemoryProvider) AddRole(clientID string, role Role) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rolesByClient[clientID] == nil {
		m.rolesByClient[clientID] = make(map[string]Role)
	}
	m.rolesByClient[clientID][role.Code] = role
}

// SetMenus replaces the menu tree for the given client.
func (m *MemoryProvider) SetMenus(clientID string, menus MenuTree) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.menusByClient[clientID] = menus
}

// AssignRoles grants the user the given role codes within the given client app.
func (m *MemoryProvider) AssignRoles(userID, clientID string, roles []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.assignmentsByUser[userID] == nil {
		m.assignmentsByUser[userID] = make(map[string][]string)
	}
	m.assignmentsByUser[userID][clientID] = append([]string{}, roles...)
}

// Roles returns all role objects assigned to userID within clientID.
func (m *MemoryProvider) Roles(_ context.Context, userID, clientID string) ([]Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	codes := m.assignmentsByUser[userID][clientID]
	if len(codes) == 0 {
		return nil, ErrUserNotFound
	}
	defs := m.rolesByClient[clientID]
	out := make([]Role, 0, len(codes))
	for _, code := range codes {
		if r, ok := defs[code]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// Permissions returns the union of all permission codes from the user's
// assigned roles, deduplicated, as Permission structs.
func (m *MemoryProvider) Permissions(ctx context.Context, userID, clientID string) ([]Permission, error) {
	roles, err := m.Roles(ctx, userID, clientID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, r := range roles {
		for _, code := range r.Permissions {
			seen[code] = struct{}{}
		}
	}
	out := make([]Permission, 0, len(seen))
	for code := range seen {
		out = append(out, Permission{Code: code})
	}
	return out, nil
}

// Menus returns the client's menu tree filtered by the user's effective
// permission set. Nodes whose Permission isn't held are removed; branches
// that become empty (no children, no own permission) are pruned. Buttons are
// filtered the same way.
func (m *MemoryProvider) Menus(ctx context.Context, userID, clientID string) (MenuTree, error) {
	m.mu.RLock()
	full := m.menusByClient[clientID]
	m.mu.RUnlock()
	if full == nil {
		return MenuTree{}, nil
	}
	perms, err := m.Permissions(ctx, userID, clientID)
	if err != nil {
		// User has no roles → empty menu, not an error from the UI's POV.
		return MenuTree{}, nil
	}
	return filterMenus(full, perms), nil
}

func filterMenus(in MenuTree, perms []Permission) MenuTree {
	out := make(MenuTree, 0, len(in))
	for _, item := range in {
		// Recurse first so we know whether children survived.
		var kept []MenuItem
		if len(item.Children) > 0 {
			kept = filterMenus(item.Children, perms)
		}

		// Drop the item only if its own permission is denied AND no child survived.
		ownAllowed := item.Permission == "" || Matches(perms, item.Permission)
		if !ownAllowed && len(kept) == 0 {
			continue
		}

		buttons := filterButtons(item.Buttons, perms)
		out = append(out, MenuItem{
			ID:         item.ID,
			Name:       item.Name,
			Path:       item.Path,
			Icon:       item.Icon,
			Permission: item.Permission,
			Buttons:    buttons,
			Children:   kept,
		})
	}
	return out
}

func filterButtons(in []Button, perms []Permission) []Button {
	if len(in) == 0 {
		return nil
	}
	out := make([]Button, 0, len(in))
	for _, b := range in {
		if b.Permission == "" || Matches(perms, b.Permission) {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
