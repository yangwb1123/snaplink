package permissions

import (
	"context"
	"slices"
	"sync"
)

// MemoryProvider is a process-local Provider backed by static role/menu maps.
// Suitable for dev, single-node deployments, and as a reference impl when
// wiring a database-backed Provider. Implements the full Provider interface
// including the admin extensions (AddRole/RemoveRole/AssignRoles/...).
//
// Data model:
//
//	rolesByClient[clientID][roleCode]              = Role
//	menusByClient[clientID]                        = MenuTree (unfiltered)
//	assignmentsByUser[userID][clientID]            = []roleCode
//	resources[id]                                  = *Resource
//	resourceIndex[tenant|client|type|name]         = id   (uniqueness)
//
// Resource catalog methods + matching logic live in memory_resources.go.
type MemoryProvider struct {
	mu                sync.RWMutex
	rolesByClient     map[string]map[string]Role
	menusByClient     map[string]MenuTree
	assignmentsByUser map[string]map[string][]string
	resources         map[string]*Resource
	resourceIndex     map[string]string
}

func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{
		rolesByClient:     make(map[string]map[string]Role),
		menusByClient:     make(map[string]MenuTree),
		assignmentsByUser: make(map[string]map[string][]string),
		resources:         make(map[string]*Resource),
		resourceIndex:     make(map[string]string),
	}
}

// AddRole registers a role under clientID. Returns ErrRoleExists if the role
// code already exists for that client.
func (m *MemoryProvider) AddRole(_ context.Context, clientID string, role Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rolesByClient[clientID] == nil {
		m.rolesByClient[clientID] = make(map[string]Role)
	}
	if _, exists := m.rolesByClient[clientID][role.Code]; exists {
		return ErrRoleExists
	}
	m.rolesByClient[clientID][role.Code] = role
	return nil
}

// UpdateRole overwrites an existing role. Returns ErrRoleNotFound if the
// role code does not exist for that client.
func (m *MemoryProvider) UpdateRole(_ context.Context, clientID string, role Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.rolesByClient[clientID][role.Code]; !exists {
		return ErrRoleNotFound
	}
	m.rolesByClient[clientID][role.Code] = role
	return nil
}

// RemoveRole drops a role definition and rips it out of every user's
// assignment list under the same client.
func (m *MemoryProvider) RemoveRole(_ context.Context, clientID, roleCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.rolesByClient[clientID][roleCode]; !exists {
		return ErrRoleNotFound
	}
	delete(m.rolesByClient[clientID], roleCode)
	// Detach from any user assignments.
	for userID, byClient := range m.assignmentsByUser {
		if roles, ok := byClient[clientID]; ok {
			byClient[clientID] = slices.DeleteFunc(roles, func(r string) bool { return r == roleCode })
			m.assignmentsByUser[userID] = byClient
		}
	}
	return nil
}

// SetMenus replaces the menu tree for clientID.
func (m *MemoryProvider) SetMenus(_ context.Context, clientID string, menus MenuTree) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.menusByClient[clientID] = menus
	return nil
}

// GetMenus returns the raw (unfiltered) menu tree for clientID. Used by
// the snapshot exporter; runtime callers should use Menus instead so the
// per-user permission filter applies. Implements permissions.MenuLister.
func (m *MemoryProvider) GetMenus(_ context.Context, clientID string) (MenuTree, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	full := m.menusByClient[clientID]
	if full == nil {
		return MenuTree{}, nil
	}
	return append(MenuTree(nil), full...), nil
}

// AssignRoles grants the user the given role codes under clientID. The set
// becomes the new role list (not a merge) — to merge, fetch via Roles() and
// re-Assign.
func (m *MemoryProvider) AssignRoles(_ context.Context, userID, clientID string, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.assignmentsByUser[userID] == nil {
		m.assignmentsByUser[userID] = make(map[string][]string)
	}
	m.assignmentsByUser[userID][clientID] = append([]string{}, roles...)
	return nil
}

// UnassignRoles removes the given role codes from the user's assignment list
// under clientID. Roles not currently assigned are silently ignored.
func (m *MemoryProvider) UnassignRoles(_ context.Context, userID, clientID string, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byClient := m.assignmentsByUser[userID]
	if byClient == nil {
		return nil
	}
	cur := byClient[clientID]
	if len(cur) == 0 {
		return nil
	}
	remove := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		remove[r] = struct{}{}
	}
	byClient[clientID] = slices.DeleteFunc(cur, func(r string) bool {
		_, drop := remove[r]
		return drop
	})
	return nil
}

// ListAllRoles returns every role defined under clientID.
func (m *MemoryProvider) ListAllRoles(_ context.Context, clientID string) ([]Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	defs := m.rolesByClient[clientID]
	out := make([]Role, 0, len(defs))
	for _, r := range defs {
		out = append(out, r)
	}
	return out, nil
}

// ListAssignments returns every user with at least one role under clientID.
func (m *MemoryProvider) ListAssignments(_ context.Context, clientID string) ([]Assignment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Assignment, 0)
	for userID, byClient := range m.assignmentsByUser {
		if roles, ok := byClient[clientID]; ok && len(roles) > 0 {
			out = append(out, Assignment{UserID: userID, Roles: append([]string(nil), roles...)})
		}
	}
	return out, nil
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

// Permissions returns the union of permission codes from the user's assigned
// roles under clientID, deduplicated, as Permission structs.
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

// Menus returns clientID's menu tree filtered by the user's permission set.
// Nodes whose Permission isn't held are removed; branches that become empty
// (no children, no own permission) are pruned. Buttons are filtered the same way.
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
		var kept []MenuItem
		if len(item.Children) > 0 {
			kept = filterMenus(item.Children, perms)
		}
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
