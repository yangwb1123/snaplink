package permissions

import (
	"context"
	"slices"
	"sync"

	"github.com/yangwb1123/snaplink/shared/core"
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
//	ssodConflicts[clientID]                        = [][]roleCode (Static SoD)
//	dsodConflicts[clientID]                        = [][]roleCode (Dynamic SoD)
//	activeRoles[userID\x00clientID\x00sessionID]   = []roleCode (DSoD activation)
//
// Resource catalog methods + matching logic live in memory_resources.go.
// Separation of Duty (SoD) methods + matching logic live in memory_sod.go.
type MemoryProvider struct {
	mu                sync.RWMutex
	rolesByClient     map[string]map[string]Role
	menusByClient     map[string]MenuTree
	assignmentsByUser map[string]map[string][]string
	resources         map[string]*Resource
	resourceIndex     map[string]string

	// ssodConflicts backs SoDProvider: role-code sets that may never be
	// held by the same subject at once, enforced inline by AssignRoles
	// and AddRoleToUser below. dsodConflicts + activeRoles back
	// SessionRoleActivator and are an INDEPENDENT table — a role pair may
	// be DSoD-only (holdable together, exclusive only to activate).
	ssodConflicts map[string][][]string
	dsodConflicts map[string][][]string
	activeRoles   map[string][]string
}

func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{
		rolesByClient:     make(map[string]map[string]Role),
		menusByClient:     make(map[string]MenuTree),
		assignmentsByUser: make(map[string]map[string][]string),
		resources:         make(map[string]*Resource),
		resourceIndex:     make(map[string]string),
		ssodConflicts:     make(map[string][][]string),
		dsodConflicts:     make(map[string][][]string),
		activeRoles:       make(map[string][]string),
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
	m.rolesByClient[clientID][role.Code] = cloneRole(role)
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
	m.rolesByClient[clientID][role.Code] = cloneRole(role)
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
	// ...and any DSoD session activations: a membership mutation requires a
	// fresh activation, even for sessions that held another role too.
	m.clearClientActiveRoles(clientID)
	return nil
}

// SetMenus replaces the menu tree for clientID.
func (m *MemoryProvider) SetMenus(_ context.Context, clientID string, menus MenuTree) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.menusByClient[clientID] = cloneMenuTree(menus)
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
	if len(full) == 0 {
		// Keep the historical distinction between an absent tree and an
		// explicitly configured empty tree returned by this method.
		return append(MenuTree(nil), full...), nil
	}
	return cloneMenuTree(full), nil
}

// AssignRoles grants the user the given role codes under clientID. The set
// becomes the new role list (not a merge) — to merge, fetch via Roles() and
// re-Assign. Rejects the whole call with *ConflictError (see sod.go) when
// roles holds two-or-more codes from the same SoDProvider-declared SSoD
// conflict set — an unconfigured Provider (no declared sets) never trips
// this, so pre-SoD callers are unaffected.
func (m *MemoryProvider) AssignRoles(_ context.Context, userID, clientID string, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := findConflict(clientID, m.ssodConflicts[clientID], roles); c != nil {
		return c
	}
	if m.assignmentsByUser[userID] == nil {
		m.assignmentsByUser[userID] = make(map[string][]string)
	}
	m.assignmentsByUser[userID][clientID] = append([]string{}, roles...)
	m.clearActiveRoles(userID, clientID)
	return nil
}

// UnassignRoles removes the given role codes from the user's assignment list
// under clientID. Roles not currently assigned are silently ignored.
func (m *MemoryProvider) UnassignRoles(_ context.Context, userID, clientID string, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byClient := m.assignmentsByUser[userID]
	if byClient == nil {
		m.clearActiveRoles(userID, clientID)
		return nil
	}
	cur := byClient[clientID]
	if len(cur) == 0 {
		m.clearActiveRoles(userID, clientID)
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
	m.clearActiveRoles(userID, clientID)
	return nil
}

// AddRoleToUser grants roleCode to userID under clientID without
// disturbing the user's other roles (RFC 7644 §3.5.2 add-member maps
// here). Idempotent under the lock: re-adding an already-held role is a
// no-op. Implements [GroupMembershipWriter]. WHY a dedicated method
// rather than AssignRoles: AssignRoles replaces the whole set, so a SCIM
// "add one member" would have to read-modify-write and could race a
// concurrent membership change; doing the read+append under m.mu keeps
// the grant atomic. Same SSoD conflict check as AssignRoles (see sod.go),
// evaluated against the user's resulting FULL role set so an added role
// can't create a conflict with one already held.
func (m *MemoryProvider) AddRoleToUser(_ context.Context, userID, clientID, roleCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.assignmentsByUser[userID] == nil {
		m.assignmentsByUser[userID] = make(map[string][]string)
	}
	cur := m.assignmentsByUser[userID][clientID]
	if slices.Contains(cur, roleCode) {
		return nil
	}
	next := append(append([]string{}, cur...), roleCode)
	if c := findConflict(clientID, m.ssodConflicts[clientID], next); c != nil {
		return c
	}
	m.assignmentsByUser[userID][clientID] = next
	m.clearActiveRoles(userID, clientID)
	return nil
}

// RemoveRoleFromUser revokes roleCode from userID under clientID, leaving
// the user's other roles intact (RFC 7644 §3.5.2 remove-member maps
// here). Idempotent: removing a role the user doesn't hold is a no-op.
// Implements [GroupMembershipWriter].
func (m *MemoryProvider) RemoveRoleFromUser(_ context.Context, userID, clientID, roleCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byClient := m.assignmentsByUser[userID]
	if byClient == nil {
		return nil
	}
	cur := byClient[clientID]
	if len(cur) == 0 {
		m.clearActiveRoles(userID, clientID)
		return nil
	}
	byClient[clientID] = slices.DeleteFunc(cur, func(r string) bool { return r == roleCode })
	m.clearActiveRoles(userID, clientID)
	return nil
}

// ListAllRoles returns every role defined under clientID.
func (m *MemoryProvider) ListAllRoles(_ context.Context, clientID string) ([]Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	defs := m.rolesByClient[clientID]
	out := make([]Role, 0, len(defs))
	for _, r := range defs {
		out = append(out, cloneRole(r))
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
	if len(codes) == 0 && clientID != "" {
		// Fall back to the empty client ID (bootstrap default)
		codes = m.assignmentsByUser[userID][""]
	}
	if len(codes) == 0 {
		return nil, ErrUserNotFound
	}
	defs := m.rolesByClient[clientID]
	if len(defs) == 0 {
		defs = m.rolesByClient[""]
	}
	out := make([]Role, 0, len(codes))
	for _, code := range codes {
		if r, ok := defs[code]; ok {
			out = append(out, cloneRole(r))
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
	full := cloneMenuTree(m.menusByClient[clientID])
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
	return FilterMenuTree(in, perms)
}

// cloneRole isolates the mutable permission slice carried by a Role while
// preserving nil versus explicitly empty slices.
func cloneRole(in Role) Role {
	out := in
	if in.Permissions != nil {
		out.Permissions = make([]string, len(in.Permissions))
		copy(out.Permissions, in.Permissions)
	}
	return out
}

// cloneMenuTree returns a recursive copy so neither menu configuration inputs
// nor query results can mutate the provider's policy state.
func cloneMenuTree(in MenuTree) MenuTree {
	if in == nil {
		return nil
	}
	out := make(MenuTree, len(in))
	for i := range in {
		out[i] = cloneMenuItem(in[i])
	}
	return out
}

func cloneMenuItem(in MenuItem) MenuItem {
	out := in
	if in.Buttons != nil {
		out.Buttons = make([]Button, len(in.Buttons))
		copy(out.Buttons, in.Buttons)
	}
	out.Children = cloneMenuTree(in.Children)
	return out
}

// ListRolesPage implements permissions.PaginatedPermissionProvider: keyset
// pagination over a snapshot sorted by code (the fixed sort both the
// fallback path and this page share), clientID-scoped like ListAllRoles.
// totalHint is the exact row count.
func (m *MemoryProvider) ListRolesPage(_ context.Context, clientID string, q core.PageQuery) ([]Role, []byte, int, error) {
	m.mu.RLock()
	defs := m.rolesByClient[clientID]
	out := make([]Role, 0, len(defs))
	for _, r := range defs {
		out = append(out, cloneRole(r))
	}
	m.mu.RUnlock()
	keyID := func(r Role) (string, string) { return r.Code, r.Code }
	core.SortKeyset(out, q.Desc, keyID)
	return core.KeysetSlice(out, q, keyID)
}

// ListAssignmentsPage implements permissions.PaginatedPermissionProvider:
// keyset pagination over a snapshot sorted by user_id (the fixed sort both
// the fallback path and this page share), clientID-scoped like
// ListAssignments. totalHint is the exact row count.
func (m *MemoryProvider) ListAssignmentsPage(_ context.Context, clientID string, q core.PageQuery) ([]Assignment, []byte, int, error) {
	m.mu.RLock()
	out := make([]Assignment, 0)
	for userID, byClient := range m.assignmentsByUser {
		if roles, ok := byClient[clientID]; ok && len(roles) > 0 {
			out = append(out, Assignment{UserID: userID, Roles: append([]string(nil), roles...)})
		}
	}
	m.mu.RUnlock()
	keyID := func(a Assignment) (string, string) { return a.UserID, a.UserID }
	core.SortKeyset(out, q.Desc, keyID)
	return core.KeysetSlice(out, q, keyID)
}

// Compile-time check that MemoryProvider satisfies the optional
// GroupMembershipWriter extension (drives SCIM Group membership).
var _ GroupMembershipWriter = (*MemoryProvider)(nil)

// Compile-time check that MemoryProvider satisfies the optional pagination
// extension (keyset pushdown for the admin List RPCs).
var _ PaginatedPermissionProvider = (*MemoryProvider)(nil)
