package scim

import (
	"context"
	"net/http"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
)

// These tests cover the group handler + group PATCH branches the existing
// group_test.go does not reach: getGroup's 304, deleteGroup's If-Match path,
// decodeGroup's bad-JSON error, createGroup's id-conflict, the path-less PATCH
// merge object, displayName remove/add-via-path, the members add-via-path
// (per-member), the members value-filter remove over a type filter, and the
// planGroupOp error branches (bad op, no-target remove, non-string displayName,
// non-array members, add/replace on a filtered member path).

// TestGetGroup_IfNoneMatch304: a group GET whose If-None-Match equals the
// current version returns 304 + the ETag (getGroup's 304 branch).
func TestGetGroup_IfNoneMatch304(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"NM"}`)
	cur := decodeGroupResource(t, do(t, h, http.MethodGet, pathGroups+"/"+id, "")).Meta.Version

	rec := doH(t, h, http.MethodGet, pathGroups+"/"+id, "", map[string]string{"If-None-Match": cur})
	if rec.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match (match) status = %d, want 304; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("304 carried a body: %s", rec.Body.String())
	}
	if rec.Header().Get("ETag") != cur {
		t.Errorf("304 ETag = %q, want %q", rec.Header().Get("ETag"), cur)
	}
}

// TestDeleteGroup_IfMatchStale412: a DELETE with a stale If-Match is 412 and
// the group survives (deleteGroup's If-Match precondition branch).
func TestDeleteGroup_IfMatchStale(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"DG"}`)
	rec := doH(t, h, http.MethodDelete, pathGroups+"/"+id, "", map[string]string{"If-Match": `W/"stale"`})
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match DELETE = %d, want 412", rec.Code)
	}
	// The group still exists.
	if rec := do(t, h, http.MethodGet, pathGroups+"/"+id, ""); rec.Code != http.StatusOK {
		t.Errorf("group gone after a rejected If-Match DELETE: %d", rec.Code)
	}
}

// TestDeleteGroup_IfMatchCurrentProceeds: a matching If-Match lets DELETE through.
func TestDeleteGroup_IfMatchCurrent(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"DG2"}`)
	cur := decodeGroupResource(t, do(t, h, http.MethodGet, pathGroups+"/"+id, "")).Meta.Version
	rec := doH(t, h, http.MethodDelete, pathGroups+"/"+id, "", map[string]string{"If-Match": cur})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("matching If-Match DELETE = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDeleteGroup_IfMatchUnknownGroup: an If-Match DELETE on an unknown group
// is 404 (deleteGroup loads first when If-Match is present).
func TestDeleteGroup_IfMatchUnknownGroup(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	rec := doH(t, h, http.MethodDelete, pathGroups+"/ghost", "", map[string]string{"If-Match": `W/"x"`})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("If-Match DELETE on unknown group = %d, want 404", rec.Code)
	}
}

// TestCreateGroup_BadJSON: a malformed body is invalidSyntax (decodeGroup).
func TestCreateGroup_BadJSON(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	rec := do(t, h, http.MethodPost, pathGroups, `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

// TestCreateGroup_IDConflict: a custom id generator that always returns the
// same id makes the second create collide with the first (createGroup's
// ErrRoleExists -> 409 uniqueness branch).
func TestCreateGroup_IDConflict(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	// First create mints grp-1; force the next id to also be grp-1.
	if rec := do(t, h, http.MethodPost, pathGroups, `{"displayName":"First"}`); rec.Code != http.StatusCreated {
		t.Fatalf("first create = %d", rec.Code)
	}
	// Re-point the generator at the already-used id.
	WithIDGenerator(func() string { return "grp-1" })(h)
	rec := do(t, h, http.MethodPost, pathGroups, `{"displayName":"Clash"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("colliding create = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeUniqueness {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeUniqueness)
	}
}

// TestPatchGroup_PathlessMerge: a path-less PATCH whose value object carries
// displayName + members applies both (planGroupOp path-less branch).
func TestPatchGroup_PathlessMerge(t *testing.T) {
	t.Parallel()
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"Old","members":[{"value":"x"}]}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":{"displayName":"New","members":[{"value":"a"},{"value":"b"}]}}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	g := decodeGroupResource(t, rec)
	if g.DisplayName != "New" {
		t.Errorf("displayName = %q, want New", g.DisplayName)
	}
	if hasRole(t, perms, "x", id) || !hasRole(t, perms, "a", id) || !hasRole(t, perms, "b", id) {
		t.Error("path-less merge did not reconcile members to {a,b}")
	}
}

// TestPatchGroup_RemoveDisplayName: a "remove displayName" PATCH clears the
// role name (planGroupOp displayName-remove branch).
func TestPatchGroup_RemoveDisplayName(t *testing.T) {
	t.Parallel()
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"Named"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"displayName"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	roles, _ := perms.ListAllRoles(context.Background(), groupClientID)
	if len(roles) != 1 || roles[0].Name != "" {
		t.Errorf("displayName not cleared: %+v", roles)
	}
}

// TestPatchGroup_DisplayNamePathReplace: replace displayName via an explicit
// path (planGroupOp displayName replace branch with a path).
func TestPatchGroup_DisplayNameViaPathlessIsRejectedOnUnknown(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	// A path-less merge naming an unsupported attribute is invalidPath.
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":{"description":"nope"}}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidPath {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidPath)
	}
}

// TestPatchGroup_UnsupportedOp: an op verb outside add/replace/remove is
// invalidValue (planGroupOp default verb branch).
func TestPatchGroup_UnsupportedOp(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"move","path":"displayName","value":"x"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchGroup_RemoveWithoutPath: remove with no path is noTarget.
func TestPatchGroup_RemoveWithoutPath(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove"}]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeNoTarget {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeNoTarget)
	}
}

// TestPatchGroup_DisplayNameNonString: a non-string displayName value is
// invalidValue (both the path-less and pathed branches).
func TestPatchGroup_DisplayNameNonString(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	// pathed
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"displayName","value":99}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pathed status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("pathed scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
	// path-less
	body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":{"displayName":99}}
	]}`
	rec = do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("path-less status = %d, want 400", rec.Code)
	}
}

// TestPatchGroup_MembersNonArray: a members value that isn't an array is
// invalidValue (memberValuesFromRaw error).
func TestPatchGroup_MembersNonArray(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"members","value":"notarray"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchGroup_PathlessMembersNonArray covers the path-less members decode
// error branch.
func TestPatchGroup_PathlessMembersNonArray(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":{"members":"notarray"}}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestPatchGroup_PathlessMissingValue / non-object cover those planGroupOp
// branches.
func TestPatchGroup_PathlessMissingAndNonObject(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	// missing value
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing value status = %d, want 400", rec.Code)
	}
	// non-object value
	rec = do(t, h, http.MethodPatch, pathGroups+"/"+id,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":"scalar"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-object value status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("non-object scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

// TestPatchGroup_FilteredMemberAddRejected: add/replace on a value-path member
// selector is rejected — only remove is meaningful (planGroupOp value-path
// non-remove branch).
func TestPatchGroup_FilteredMemberAddRejected(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G","members":[{"value":"a"}]}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"members[value eq \"b\"]","value":[{"value":"b"}]}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidPath {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidPath)
	}
}

// TestPatchGroup_FilteredMemberRemoveByType: a value-path remove with a type
// filter removes matching current members (removeMembersMatching +
// memberElementAttrs type branch). All members carry type "User", so a
// type-eq-User filter clears them all.
func TestPatchGroup_FilteredMemberRemoveByType(t *testing.T) {
	t.Parallel()
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G","members":[{"value":"a"},{"value":"b"}]}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"members[type eq \"User\"]"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if hasRole(t, perms, "a", id) || hasRole(t, perms, "b", id) {
		t.Error("type-filter remove did not drop all User members")
	}
}

// TestPatchGroup_FilteredMemberRemoveNoMatchIsNoOp: a value-path remove that
// matches no current member is an idempotent no-op success (removeMembersMatching).
func TestPatchGroup_FilteredMemberRemoveNoMatch(t *testing.T) {
	t.Parallel()
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G","members":[{"value":"keep"}]}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"members[value eq \"absent\"]"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (idempotent no-op); body=%s", rec.Code, rec.Body.String())
	}
	if !hasRole(t, perms, "keep", id) {
		t.Error("no-match remove dropped an unrelated member")
	}
}

// TestPatchGroup_AddSingleMemberViaPath: an add over the bare members path with
// a one-element array appends that member individually (planGroupOp members add
// per-member branch).
func TestPatchGroup_AddSingleMemberViaPath(t *testing.T) {
	t.Parallel()
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G","members":[{"value":"a"}]}`)
	// add already-present 'a' (idempotent) plus a new 'c' -> exercises addMember
	// "already a member" short-circuit AND a fresh add.
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"members","value":[{"value":"a"},{"value":"c"}]}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !hasRole(t, perms, "a", id) || !hasRole(t, perms, "c", id) {
		t.Error("members add did not assign both a and c")
	}
}

// TestPatchGroup_UnfilteredMembersRemoveClearsAll covers the planGroupOp
// unfiltered members remove branch directly (drops the whole set).
func TestPatchGroup_UnfilteredMembersRemove(t *testing.T) {
	t.Parallel()
	h, perms, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G","members":[{"value":"a"},{"value":"b"}]}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"members"}
	]}`
	rec := do(t, h, http.MethodPatch, pathGroups+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if hasRole(t, perms, "a", id) || hasRole(t, perms, "b", id) {
		t.Error("unfiltered members remove did not clear the set")
	}
}

// TestReplaceGroup_MissingDisplayName: PUT with a blank displayName is
// invalidValue (replaceGroup validation branch).
func TestReplaceGroup_MissingDisplayName(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	rec := do(t, h, http.MethodPut, pathGroups+"/"+id, `{"members":[{"value":"x"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestReplaceGroup_BadJSON: a malformed PUT body is invalidSyntax.
func TestReplaceGroup_BadJSON(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	rec := do(t, h, http.MethodPut, pathGroups+"/"+id, `{bad`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

// TestGroupMethodNotAllowed: an undefined method on the /Groups collection and
// on a /Groups/{id} resource returns 405.
func TestGroupMethodNotAllowed(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	if rec := do(t, h, http.MethodDelete, pathGroups, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /Groups = %d, want 405", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, pathGroups+"/"+id, `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /Groups/{id} = %d, want 405", rec.Code)
	}
}

// TestGroupNestedPath: a nested /Groups/a/b path is not-found.
func TestGroupNestedPath(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	if rec := do(t, h, http.MethodGet, pathGroups+"/a/b", ""); rec.Code != http.StatusNotFound {
		t.Errorf("nested group path = %d, want 404", rec.Code)
	}
}

// TestGroupListFiltered exercises listGroups' filter + sort + pagination path
// together (the populated branches of listGroups) and asserts the audit on
// create lands as the reused role event.
func TestGroupListFilteredAudit(t *testing.T) {
	t.Parallel()
	h, _, sink := newGroupHandler(t)
	seedGroup(t, h, `{"displayName":"Alpha"}`)
	seedGroup(t, h, `{"displayName":"Beta"}`)
	rec := do(t, h, http.MethodGet, pathGroups+`?filter=`+
		"displayName%20eq%20%22Alpha%22", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var lr GroupListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	if lr.TotalResults != 1 || len(lr.Resources) != 1 || lr.Resources[0].DisplayName != "Alpha" {
		t.Errorf("filtered group list = %+v", lr)
	}
	// Both creates emitted the reused role-added event.
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventAdminRoleAdded})
	if len(events) < 2 {
		t.Errorf("role-added events = %d, want >=2", len(events))
	}
}

// TestGroupAddMember_AlreadyMemberFallback exercises the addMember fallback's
// "already a member" short-circuit through the baseOnlyProvider (no
// GroupMembershipWriter), re-adding an existing member.
func TestGroupAddMember_AlreadyMemberFallback(t *testing.T) {
	t.Parallel()
	inner := permissions.NewMemoryProvider()
	ctx := context.Background()
	// The role must be defined for userRoleCodes (which reads via Roles) to see
	// the assignment — mirroring createGroup's AddRole-then-addMember order.
	if err := inner.AddRole(ctx, groupClientID, permissions.Role{Code: "r1", Name: "R1"}); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	gr := groupRole{perms: baseOnlyProvider{inner: inner}, clientID: groupClientID}
	if err := gr.addMember(ctx, "u", "r1"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	// Re-add the same member: the fallback must short-circuit (already present).
	if err := gr.addMember(ctx, "u", "r1"); err != nil {
		t.Fatalf("idempotent re-add: %v", err)
	}
	codes, err := gr.userRoleCodes(ctx, "u")
	if err != nil {
		t.Fatalf("userRoleCodes: %v", err)
	}
	count := 0
	for _, c := range codes {
		if c == "r1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("role assigned %d times, want exactly 1 (idempotent)", count)
	}
}
