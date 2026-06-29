package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/audit"
)

const groupClientID = "app-1"

// newGroupHandler builds a Handler with /Groups enabled over a real
// permissions.MemoryProvider (no mocks). Returns the handler + provider so
// tests can assert the role/assignment side effects directly.
func newGroupHandler(t *testing.T) (*Handler, *permissions.MemoryProvider, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	perms := permissions.NewMemoryProvider()
	sink := audit.NewMemorySink(64)
	var seq int
	gen := func() string {
		seq++
		return fmt.Sprintf("grp-%d", seq)
	}
	fixed := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	h := NewHandler(users, testBase,
		WithRecorder(audit.New(sink)),
		WithIDGenerator(gen),
		WithClock(func() time.Time { return fixed }),
		WithGroups(perms, groupClientID),
	)
	return h, perms, sink
}

func decodeGroupResource(t *testing.T, rec *httptest.ResponseRecorder) GroupResource {
	t.Helper()
	var g GroupResource
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatalf("decode group: %v; body=%s", err, rec.Body.String())
	}
	return g
}

// hasRole reports whether userID is assigned roleCode under groupClientID.
func hasRole(t *testing.T, perms *permissions.MemoryProvider, userID, roleCode string) bool {
	t.Helper()
	roles, err := perms.Roles(context.Background(), userID, groupClientID)
	if err != nil {
		return false
	}
	for _, r := range roles {
		if r.Code == roleCode {
			return true
		}
	}
	return false
}

// TestGroupRoundTrip exercises create -> get -> list -> replace -> delete,
// asserting the SCIM group view AND the underlying role/assignment state.
func TestGroupRoundTrip(t *testing.T) {
	h, perms, sink := newGroupHandler(t)

	// --- create with two members ---
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Engineering",
		"members": [{"value": "user-a"}, {"value": "user-b"}]
	}`
	rec := do(t, h, http.MethodPost, pathGroups, createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	created := decodeGroupResource(t, rec)
	if created.ID != "grp-1" {
		t.Fatalf("group id = %q, want grp-1", created.ID)
	}
	if created.DisplayName != "Engineering" {
		t.Errorf("displayName = %q", created.DisplayName)
	}
	if len(created.Schemas) != 1 || created.Schemas[0] != SchemaGroup {
		t.Errorf("schemas = %v", created.Schemas)
	}
	if created.Meta == nil || created.Meta.ResourceType != resourceTypeGroup {
		t.Fatalf("meta = %+v", created.Meta)
	}
	wantLoc := testBase + pathGroups + "/grp-1"
	if created.Meta.Location != wantLoc {
		t.Errorf("meta.location = %q, want %q", created.Meta.Location, wantLoc)
	}
	if len(created.Members) != 2 {
		t.Fatalf("members len = %d, want 2: %+v", len(created.Members), created.Members)
	}
	// The mapping MUST have driven the role model: both members assigned.
	if !hasRole(t, perms, "user-a", "grp-1") || !hasRole(t, perms, "user-b", "grp-1") {
		t.Error("group membership did not become role assignments")
	}
	// And the role itself exists with displayName as its Name.
	roles, _ := perms.ListAllRoles(context.Background(), groupClientID)
	if len(roles) != 1 || roles[0].Code != "grp-1" || roles[0].Name != "Engineering" {
		t.Errorf("role not created from group: %+v", roles)
	}
	assertSubjectAudited(t, sink, audit.EventAdminRoleAdded, "grp-1")

	// --- get ---
	rec = do(t, h, http.MethodGet, pathGroups+"/grp-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", rec.Code)
	}
	got := decodeGroupResource(t, rec)
	if got.DisplayName != "Engineering" || len(got.Members) != 2 {
		t.Errorf("get mismatch: %+v", got)
	}

	// --- list ---
	rec = do(t, h, http.MethodGet, pathGroups, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", rec.Code)
	}
	var lr GroupListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if lr.TotalResults != 1 || len(lr.Resources) != 1 || lr.Resources[0].ID != "grp-1" {
		t.Errorf("list = %+v", lr)
	}

	// --- replace: rename + drop user-b, add user-c ---
	replaceBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Eng",
		"members": [{"value": "user-a"}, {"value": "user-c"}]
	}`
	rec = do(t, h, http.MethodPut, pathGroups+"/grp-1", replaceBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	replaced := decodeGroupResource(t, rec)
	if replaced.DisplayName != "Eng" {
		t.Errorf("displayName = %q, want Eng", replaced.DisplayName)
	}
	if !hasRole(t, perms, "user-a", "grp-1") {
		t.Error("user-a should remain a member after replace")
	}
	if hasRole(t, perms, "user-b", "grp-1") {
		t.Error("user-b should have been removed by replace")
	}
	if !hasRole(t, perms, "user-c", "grp-1") {
		t.Error("user-c should have been added by replace")
	}
	assertSubjectAudited(t, sink, audit.EventAdminRoleUpdated, "grp-1")

	// --- delete ---
	rec = do(t, h, http.MethodDelete, pathGroups+"/grp-1", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", rec.Code)
	}
	assertSubjectAudited(t, sink, audit.EventAdminRoleRemoved, "grp-1")
	// Role + assignments gone.
	if hasRole(t, perms, "user-a", "grp-1") {
		t.Error("delete did not strip role assignment")
	}
	rec = do(t, h, http.MethodGet, pathGroups+"/grp-1", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", rec.Code)
	}
}

// TestPatchGroup_AddRemoveMember covers the IdP group-membership delta:
// add one member, then remove one, via PATCH on the members attribute.
func TestPatchGroup_AddRemoveMember(t *testing.T) {
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"Team","members":[{"value":"u1"}]}`)

	// add u2
	addBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"members","value":[{"value":"u2"}]}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, addBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("add member status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !hasRole(t, perms, "u1", id) || !hasRole(t, perms, "u2", id) {
		t.Error("add member did not assign role to u2 (or dropped u1)")
	}
	g := decodeGroupResource(t, rec)
	if len(g.Members) != 2 {
		t.Errorf("members after add = %d, want 2", len(g.Members))
	}

	// remove u1
	rmBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"members","value":[{"value":"u1"}]}
	]}`
	// NOTE: an unfiltered "remove members" drops ALL members per RFC 7644
	// §3.5.2.2; this slice rejects the filtered form, so to remove a single
	// member a connector sends "replace members" with the new set. Verify
	// the unfiltered remove clears everything (documented behavior).
	rec = do(t, h, http.MethodPatch, pathGroups+"/"+id, rmBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove members status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if hasRole(t, perms, "u1", id) || hasRole(t, perms, "u2", id) {
		t.Error("unfiltered remove members must drop all members")
	}
}

// TestPatchGroup_ReplaceMembers sets membership to exactly a new set (the
// connector path for removing a single member: re-send the full list).
func TestPatchGroup_ReplaceMembers(t *testing.T) {
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"T","members":[{"value":"a"},{"value":"b"},{"value":"c"}]}`)

	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"members","value":[{"value":"a"},{"value":"c"}]}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !hasRole(t, perms, "a", id) || hasRole(t, perms, "b", id) || !hasRole(t, perms, "c", id) {
		t.Error("replace members did not reconcile to {a,c}")
	}
}

// TestPatchGroup_ReplaceDisplayName covers a displayName rename via PATCH.
func TestPatchGroup_ReplaceDisplayName(t *testing.T) {
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"Before"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"displayName","value":"After"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeGroupResource(t, rec).DisplayName != "After" {
		t.Error("displayName not renamed")
	}
	roles, _ := perms.ListAllRoles(context.Background(), groupClientID)
	if len(roles) != 1 || roles[0].Name != "After" {
		t.Errorf("role name not updated: %+v", roles)
	}
}

// TestCreateGroup_MissingDisplayName: displayName is required.
func TestCreateGroup_MissingDisplayName(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	rec := do(t, h, http.MethodPost, pathGroups, `{"members":[{"value":"x"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestGroup_NotFound: get/replace/patch/delete on an unknown group are 404.
func TestGroup_NotFound(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	patchBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"x"}]}`
	cases := []struct {
		method string
		body   string
	}{
		{http.MethodGet, ""},
		{http.MethodPut, `{"displayName":"x"}`},
		{http.MethodPatch, patchBody},
		{http.MethodDelete, ""},
	}
	for _, tc := range cases {
		rec := do(t, h, tc.method, pathGroups+"/ghost", tc.body)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s /Groups/ghost = %d, want 404; body=%s", tc.method, rec.Code, rec.Body.String())
		}
	}
}

// TestReplaceGroup_ImmutableID: a PUT body with a different id is a
// mutability violation.
func TestReplaceGroup_ImmutableID(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	rec := do(t, h, http.MethodPut, pathGroups+"/"+id, `{"id":"other","displayName":"G"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeMutability {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeMutability)
	}
}

// TestGroupPatch_MemberValuePathRemove: a members value-filter remove
// (RFC 7644 §3.5.2 — the per-member delta Azure AD / Okta send) drops ONLY
// the targeted member, leaving the rest of the membership intact.
func TestGroupPatch_MemberValuePathRemove(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G","members":[{"value":"a"},{"value":"b"}]}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"members[value eq \"a\"]"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	g := decodeGroupResource(t, rec)
	got := g.memberValues()
	if len(got) != 1 || got[0] != "b" {
		t.Errorf("members after value-path remove = %v, want [b]", got)
	}
}

// TestGroupPatch_UnsupportedPath: a path that still can't be honored (a
// schema-URN-qualified path) is 400 invalidPath, not half-applied. Value-path
// filters themselves are supported (see TestGroupPatch_MemberValuePathRemove).
func TestGroupPatch_UnsupportedPath(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G","members":[{"value":"a"}]}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:Group:displayName","value":"X"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidPath {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidPath)
	}
}

// TestGroupsDisabled_404: with no WithGroups, /Groups routes 404 so the
// User surface isn't accidentally coupled to a permissions provider.
func TestGroupsDisabled_404(t *testing.T) {
	h, _, _ := newTestHandler(t) // no WithGroups
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		rec := do(t, h, m, pathGroups, `{"displayName":"x"}`)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s /Groups (groups disabled) = %d, want 404", m, rec.Code)
		}
	}
}

// TestSchemas_IncludesGroupWhenEnabled: GET /Schemas advertises Group only
// when WithGroups is wired.
func TestSchemas_IncludesGroupWhenEnabled(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	rec := do(t, h, http.MethodGet, pathSchemas, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), SchemaGroup) {
		t.Errorf("GET /Schemas omitted Group schema when groups enabled; body=%s", rec.Body.String())
	}
}

// seedGroup creates a group via the SCIM API and returns its id.
func seedGroup(t *testing.T, h *Handler, body string) string {
	t.Helper()
	rec := do(t, h, http.MethodPost, pathGroups, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed group status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	return decodeGroupResource(t, rec).ID
}

// baseOnlyProvider wraps a real permissions.MemoryProvider but exposes
// ONLY the base permissions.Provider interface — it deliberately does NOT
// promote AddRoleToUser/RemoveRoleFromUser, so the SCIM group handler
// must take its Roles + AssignRoles / UnassignRoles fallback path. This
// is not a mock: every call delegates to the real in-memory store; the
// wrapper only narrows the interface to prove the fallback works against
// any Provider.
type baseOnlyProvider struct {
	inner *permissions.MemoryProvider
}

func (p baseOnlyProvider) Permissions(ctx context.Context, u, c string) ([]permissions.Permission, error) {
	return p.inner.Permissions(ctx, u, c)
}
func (p baseOnlyProvider) Roles(ctx context.Context, u, c string) ([]permissions.Role, error) {
	return p.inner.Roles(ctx, u, c)
}
func (p baseOnlyProvider) Menus(ctx context.Context, u, c string) (permissions.MenuTree, error) {
	return p.inner.Menus(ctx, u, c)
}
func (p baseOnlyProvider) AddRole(ctx context.Context, c string, r permissions.Role) error {
	return p.inner.AddRole(ctx, c, r)
}
func (p baseOnlyProvider) UpdateRole(ctx context.Context, c string, r permissions.Role) error {
	return p.inner.UpdateRole(ctx, c, r)
}
func (p baseOnlyProvider) RemoveRole(ctx context.Context, c, code string) error {
	return p.inner.RemoveRole(ctx, c, code)
}
func (p baseOnlyProvider) AssignRoles(ctx context.Context, u, c string, r []string) error {
	return p.inner.AssignRoles(ctx, u, c, r)
}
func (p baseOnlyProvider) UnassignRoles(ctx context.Context, u, c string, r []string) error {
	return p.inner.UnassignRoles(ctx, u, c, r)
}
func (p baseOnlyProvider) SetMenus(ctx context.Context, c string, m permissions.MenuTree) error {
	return p.inner.SetMenus(ctx, c, m)
}
func (p baseOnlyProvider) ListAllRoles(ctx context.Context, c string) ([]permissions.Role, error) {
	return p.inner.ListAllRoles(ctx, c)
}
func (p baseOnlyProvider) ListAssignments(ctx context.Context, c string) ([]permissions.Assignment, error) {
	return p.inner.ListAssignments(ctx, c)
}

var _ permissions.Provider = baseOnlyProvider{}

// TestGroup_FallbackWithoutMembershipWriter proves /Groups membership
// works against a Provider that does NOT implement GroupMembershipWriter,
// via the Roles + AssignRoles / UnassignRoles fallback.
func TestGroup_FallbackWithoutMembershipWriter(t *testing.T) {
	if _, ok := interface{}(baseOnlyProvider{}).(permissions.GroupMembershipWriter); ok {
		t.Fatal("baseOnlyProvider must NOT implement GroupMembershipWriter (test would not exercise the fallback)")
	}
	inner := permissions.NewMemoryProvider()
	prov := baseOnlyProvider{inner: inner}
	users := defaultimpl.NewMemoryUserProvider()
	var seq int
	h := NewHandler(users, testBase,
		WithIDGenerator(func() string { seq++; return fmt.Sprintf("fg-%d", seq) }),
		WithGroups(prov, groupClientID),
	)

	id := seedGroup(t, h, `{"displayName":"FB","members":[{"value":"x"}]}`)
	// add a member through the fallback add path
	addBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"y"}]}]}`
	if rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, addBody); rec.Code != http.StatusOK {
		t.Fatalf("fallback add status = %d; body=%s", rec.Code, rec.Body.String())
	}
	for _, uid := range []string{"x", "y"} {
		roles, err := inner.Roles(context.Background(), uid, groupClientID)
		if err != nil {
			t.Fatalf("roles(%s): %v", uid, err)
		}
		found := false
		for _, r := range roles {
			if r.Code == id {
				found = true
			}
		}
		if !found {
			t.Errorf("fallback path did not assign role %s to %s", id, uid)
		}
	}
	// replace to {x} only -> y removed via UnassignRoles fallback
	repBody := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"members","value":[{"value":"x"}]}]}`
	if rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, repBody); rec.Code != http.StatusOK {
		t.Fatalf("fallback replace status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if roles, _ := inner.Roles(context.Background(), "y", groupClientID); len(roles) != 0 {
		t.Error("fallback replace did not remove y")
	}
}

// TestGroup_RoleMutationsInvalidateAuthzBundle is the cross-replica-publish
// regression guard: a SCIM group role create/delete (role-DEFINITION mutation)
// MUST fire the authz-policy-bundle invalidator so peers don't keep serving a
// de-provisioned role's permissions from a stale bundle cache. Mirrors the gRPC
// PermissionAdmin path.
func TestGroup_RoleMutationsInvalidateAuthzBundle(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	perms := permissions.NewMemoryProvider()
	var invalidated []string
	var seq int
	gen := func() string { seq++; return fmt.Sprintf("grp-%d", seq) }
	h := NewHandler(users, testBase,
		WithIDGenerator(gen),
		WithGroups(perms, groupClientID, func(cid string) { invalidated = append(invalidated, cid) }),
	)

	rec := do(t, h, http.MethodPost, pathGroups, `{"displayName":"admins"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", rec.Code, rec.Body.String())
	}
	if len(invalidated) != 1 || invalidated[0] != groupClientID {
		t.Fatalf("create did not invalidate authz bundle: %v", invalidated)
	}
	id := decodeResource(t, rec).ID

	rec = do(t, h, http.MethodDelete, pathGroups+"/"+id, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete group: %d %s", rec.Code, rec.Body.String())
	}
	if len(invalidated) != 2 || invalidated[1] != groupClientID {
		t.Fatalf("delete did not invalidate authz bundle: %v", invalidated)
	}
}
