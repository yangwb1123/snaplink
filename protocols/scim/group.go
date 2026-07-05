package scim

import (
	"context"
	"sort"

	"github.com/snaplink/sso/domains/permissions"
)

// GroupResource is the SCIM 2.0 core Group representation (RFC 7643 §4.2).
// Only the attributes this slice implements are modeled; unknown inbound
// attributes are ignored (RFC 7644 §3.3 lets a server drop attributes it
// doesn't support). The shape is faithful to the wire so off-the-shelf
// provisioning connectors (Okta, Azure AD, OneLogin) interoperate.
//
// A SCIM Group is mapped onto the existing permissions model: a Group IS
// a permissions.Role under a fixed clientID (the app the IdP provisions),
// its stable server-minted id is the Role.Code, displayName is the
// Role.Name, and members are the users assigned that role. An IdP group
// push therefore drives the same RBAC surface that /permissions/me,
// /roles/me, and login-embed read — no parallel group store.
type GroupResource struct {
	Schemas []string `json:"schemas"`
	ID      string   `json:"id,omitempty"`
	// ExternalID is the common RFC 7643 §3.1 attribute the INBOUND receiver
	// ignores today (a Group here is a permissions.Role, which has no
	// external-id column). protocols/scimprovision's OUTBOUND push sets it
	// to this server's own role code so a downstream SCIM app can resolve
	// "have I already provisioned this group" via
	// GET .../Groups?filter=externalId eq "..." without assuming the two
	// systems share an id space.
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName,omitempty"`
	Members     []GroupMember `json:"members,omitempty"`
	Meta        *Meta         `json:"meta,omitempty"`
}

// GroupMember is one element of the multi-valued "members" attribute
// (RFC 7643 §4.2). Value is the member's resource id (a User id here);
// Type is typically "User"; Ref is the optional "$ref" URL. Only Value is
// load-bearing for the role-assignment mapping.
type GroupMember struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
}

// GroupListResponse is the multi-valued GET envelope for Groups
// (RFC 7644 §3.4.2). Mirrors ListResponse but carries GroupResource so
// the Resources array marshals with group attributes.
type GroupListResponse struct {
	Schemas      []string        `json:"schemas"`
	TotalResults int             `json:"totalResults"`
	StartIndex   int             `json:"startIndex"`
	ItemsPerPage int             `json:"itemsPerPage"`
	Resources    []GroupResource `json:"Resources"`
}

// memberValues returns the de-duplicated, sorted set of member ids,
// dropping empties. Sorting yields a stable members array on read so a
// connector diffing successive GETs sees no spurious churn (the
// underlying assignment lookup has no defined order).
func (g *GroupResource) memberValues() []string {
	seen := make(map[string]struct{}, len(g.Members))
	for _, m := range g.Members {
		if m.Value != "" {
			seen[m.Value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// groupRole adapts the per-client permissions.Provider into a SCIM group
// view: a group's identity + displayName live as a Role, its membership
// as the set of users assigned that role under clientID. WHY a thin
// adapter rather than putting permissions calls in the handler: the
// member<->assignment inversion (read membership by scanning assignments,
// write it via single-role add/remove) is the only non-obvious mapping,
// so it is isolated and unit-testable here.
type groupRole struct {
	perms    permissions.Provider
	clientID string
	// invalidate, when wired, evicts the authz-policy-bundle cache + publishes
	// KindAuthzPolicyChange to peers after a role-DEFINITION mutation (create /
	// rename / delete). Without it a SCIM group change leaves stale role
	// definitions served from the per-replica bundle cache for the cache TTL,
	// authorizing under a de-provisioned role fleet-wide — the gRPC PermissionAdmin
	// path does this; the byte-equivalent SCIM path must too.
	invalidate func(clientID string)
}

// invalidateBundle fires the authz-policy-bundle cache invalidation after a role
// definition changed. Nil-safe (no-op when the invalidator was not wired).
func (gr *groupRole) invalidateBundle() {
	if gr != nil && gr.invalidate != nil {
		gr.invalidate(gr.clientID)
	}
}

// listRoleCodes returns every group (role code) defined under clientID.
func (gr groupRole) listRoles(ctx context.Context) ([]permissions.Role, error) {
	return gr.perms.ListAllRoles(ctx, gr.clientID)
}

// findRole returns the role whose Code == id, or ok=false. WHY a list
// scan: permissions.Provider exposes no get-by-code, and a deployment's
// role count is small (operator-defined groups), so scanning ListAllRoles
// is acceptable rather than widening the SPI for a point lookup.
func (gr groupRole) findRole(ctx context.Context, id string) (permissions.Role, bool, error) {
	all, err := gr.perms.ListAllRoles(ctx, gr.clientID)
	if err != nil {
		return permissions.Role{}, false, err
	}
	for _, r := range all {
		if r.Code == id {
			return r, true, nil
		}
	}
	return permissions.Role{}, false, nil
}

// members returns the sorted set of user ids assigned roleCode under
// clientID — the inversion of the per-user assignment table into a
// per-group membership list (RFC 7643 §4.2 members).
func (gr groupRole) members(ctx context.Context, roleCode string) ([]string, error) {
	assigns, err := gr.perms.ListAssignments(ctx, gr.clientID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range assigns {
		for _, code := range a.Roles {
			if code == roleCode {
				out = append(out, a.UserID)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// addMember grants roleCode to userID, preferring the atomic
// GroupMembershipWriter extension and falling back to a Roles +
// AssignRoles read-modify-write so groups work against any Provider.
func (gr groupRole) addMember(ctx context.Context, userID, roleCode string) error {
	if w, ok := gr.perms.(permissions.GroupMembershipWriter); ok {
		return w.AddRoleToUser(ctx, userID, gr.clientID, roleCode)
	}
	codes, err := gr.userRoleCodes(ctx, userID)
	if err != nil {
		return err
	}
	for _, c := range codes {
		if c == roleCode {
			return nil // already a member
		}
	}
	return gr.perms.AssignRoles(ctx, userID, gr.clientID, append(codes, roleCode))
}

// removeMember revokes roleCode from userID, preferring the atomic
// GroupMembershipWriter extension and falling back to UnassignRoles
// (which the base Provider already scopes to specific codes).
func (gr groupRole) removeMember(ctx context.Context, userID, roleCode string) error {
	if w, ok := gr.perms.(permissions.GroupMembershipWriter); ok {
		return w.RemoveRoleFromUser(ctx, userID, gr.clientID, roleCode)
	}
	return gr.perms.UnassignRoles(ctx, userID, gr.clientID, []string{roleCode})
}

// userRoleCodes returns the role codes currently assigned to userID under
// clientID, treating "no assignment" as an empty set (not an error) so
// the add-member fallback can append to a fresh user.
func (gr groupRole) userRoleCodes(ctx context.Context, userID string) ([]string, error) {
	roles, err := gr.perms.Roles(ctx, userID, gr.clientID)
	if err != nil {
		// ErrUserNotFound means the user holds no roles yet — a valid
		// starting point for the first add, not a failure.
		return nil, nil
	}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Code)
	}
	return out, nil
}

// RoleToGroup renders a stored Role + its membership into a SCIM Group
// resource. location is the absolute resource URL stamped into
// meta.location (RFC 7643 §3.1); pass "" to omit it. Group meta carries
// no created/lastModified because the permissions model has no role
// timestamps — those attributes are optional (RFC 7643 §3.1), and a
// connector that needs them can fall back to its own bookkeeping.
func RoleToGroup(role permissions.Role, memberIDs []string, location string) GroupResource {
	g := GroupResource{
		Schemas:     []string{SchemaGroup},
		ID:          role.Code,
		DisplayName: role.Name,
		Meta: &Meta{
			ResourceType: resourceTypeGroup,
			Location:     location,
		},
	}
	g.Members = make([]GroupMember, 0, len(memberIDs))
	for _, id := range memberIDs {
		g.Members = append(g.Members, GroupMember{Value: id, Type: resourceTypeUser})
	}
	return g
}

// FindRoleByCode looks up perms's role with the given roleCode under
// clientID — exported so protocols/scimprovision (the OUTBOUND push
// counterpart of this INBOUND receiver) resolves the SAME group identity
// this package's own /Groups handlers use, rather than a parallel lookup.
func FindRoleByCode(ctx context.Context, perms permissions.Provider, clientID, roleCode string) (permissions.Role, bool, error) {
	return groupRole{perms: perms, clientID: clientID}.findRole(ctx, roleCode)
}

// RoleMembers returns the sorted user ids assigned roleCode under clientID —
// exported for the same reason as FindRoleByCode.
func RoleMembers(ctx context.Context, perms permissions.Provider, clientID, roleCode string) ([]string, error) {
	return groupRole{perms: perms, clientID: clientID}.members(ctx, roleCode)
}
