package scim

import (
	"context"
	"net/http"
	"testing"

	"github.com/snaplink/sso/audit"
)

// seedUser creates a user via the SCIM API and returns its id.
func seedUser(t *testing.T, h *Handler, body string) string {
	t.Helper()
	rec := do(t, h, http.MethodPost, pathUsers, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed user status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	return decodeResource(t, rec).ID
}

// TestPatchUser_DeprovisionActiveFalse is the Azure AD / Okta deprovision
// path: PATCH replace active=false. This is the highest-priority PATCH
// case (it's how IdPs disable an account), so it gets a dedicated test.
func TestPatchUser_DeprovisionActiveFalse(t *testing.T) {
	h, users, sink := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"deprovision@example.com","active":true}`)

	// The exact body Azure AD sends to disable a user.
	body := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "value": {"active": false}}]
	}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Active {
		t.Error("active still true after deprovision PATCH")
	}
	// Persisted, not just echoed.
	u, err := users.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.Attributes[attrActive] != activeFalse {
		t.Errorf("stored scim:active = %q, want %q", u.Attributes[attrActive], activeFalse)
	}
	assertSubjectAudited(t, sink, audit.EventAdminUserUpdated, id)
}

// TestPatchUser_PathedReplaceActive exercises the explicit-path form
// (path="active") that some connectors send instead of the value object.
func TestPatchUser_PathedReplaceActive(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"p@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"active","value":false}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Active {
		t.Error("active still true")
	}
}

// TestPatchUser_ReplaceAndRemoveAttrs covers userName/displayName replace,
// a name.sub replace, and remove of an optional attribute.
func TestPatchUser_ReplaceAndRemoveAttrs(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"old@example.com","displayName":"Old","externalId":"ext-1","name":{"givenName":"Old"}}`)

	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"userName","value":"new@example.com"},
		{"op":"replace","path":"name.givenName","value":"New"},
		{"op":"remove","path":"externalId"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.UserName != "new@example.com" {
		t.Errorf("userName = %q, want new@example.com", res.UserName)
	}
	if res.Name == nil || res.Name.GivenName != "New" {
		t.Errorf("name.givenName not replaced: %+v", res.Name)
	}
	if res.ExternalID != "" {
		t.Errorf("externalId not removed: %q", res.ExternalID)
	}
}

// TestPatchUser_AddToMultiValuedEmails verifies add on the multi-valued
// emails attribute APPENDS rather than replaces.
func TestPatchUser_AddToMultiValuedEmails(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"m@example.com","emails":[{"value":"m@example.com","primary":true,"type":"work"}]}`)

	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"emails","value":[{"value":"m2@home.example","type":"home"}]}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if len(res.Emails) != 2 {
		t.Fatalf("emails len = %d, want 2 (add must append): %+v", len(res.Emails), res.Emails)
	}
}

// TestPatchUser_NotFound: PATCH on an unknown id is 404, no upsert.
func TestPatchUser_NotFound(t *testing.T) {
	h, _, _ := newTestHandler(t)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/ghost", body)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestPatchUser_RemoveNonexistentIsNoOp: removing an attribute the user
// doesn't have succeeds (idempotent), and removing a multi-valued attr
// that's already empty is fine. Connectors re-send removes on retry.
func TestPatchUser_RemoveNonexistentIsNoOp(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"r@example.com"}`)
	// externalId was never set; remove must still 200.
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"externalId"},
		{"op":"remove","path":"emails"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (remove of absent is a no-op); body=%s", rec.Code, rec.Body.String())
	}
}

// TestPatchUser_RemoveWithoutPath: remove REQUIRES a path (RFC 7644
// §3.5.2.2) -> 400 noTarget.
func TestPatchUser_RemoveWithoutPath(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"np@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove"}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeNoTarget {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeNoTarget)
	}
}

// TestPatchUser_RemoveImmutableUserName: userName is required; removing it
// is rejected (a SCIM "remove" of a required attribute is invalidValue).
func TestPatchUser_RemoveRequiredUserName(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"keep@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"userName"}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_UnsupportedPath: a path the minimal parser can't honor
// (a value filter) is 400 invalidPath, not a silent no-op.
func TestPatchUser_UnsupportedPath(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"f@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"work\"].value","value":"x@example.com"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidPath {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidPath)
	}
}

// TestPatchUser_ReplaceImmutableID: PATCH targeting the read-only id
// attribute is a 400 mutability violation (RFC 7643 §7), not a no-op.
func TestPatchUser_ReplaceImmutableID(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"i@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"id","value":"hacked"}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeMutability {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeMutability)
	}
}

// TestPatchUser_UnsupportedOp: an op verb outside add/replace/remove is
// 400 invalidValue.
func TestPatchUser_UnsupportedOp(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"o@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"move","path":"active","value":false}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_EmptyOperations: a PATCH with no operations is malformed.
func TestPatchUser_EmptyOperations(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"e@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestPatchUser_CaseInsensitiveOpAndPath: SCIM op + attribute names are
// case-insensitive (RFC 7643 §2.1 / RFC 7644 §3.5.2).
func TestPatchUser_CaseInsensitiveOpAndPath(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"c@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"Active","value":false}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Active {
		t.Error("active still true after case-varied PATCH")
	}
}

// TestPatchUser_RootMergeIgnoresSchemas: a path-less value object that
// echoes "schemas" alongside a real attribute must apply the attribute,
// not fail on the protocol field (some connectors include it).
func TestPatchUser_RootMergeIgnoresSchemas(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"s@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"active":false}}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Active {
		t.Error("active still true; schemas echo must not block the deprovision")
	}
}

// TestPatchUser_AllOrNothing: a failing later op aborts the whole PATCH
// with NO partial write (the first op's change must not persist).
func TestPatchUser_AllOrNothing(t *testing.T) {
	h, users, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"keep@example.com","active":true}`)
	// op1 would set active=false; op2 is invalid (unsupported op) -> abort.
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"active","value":false},
		{"op":"move","path":"userName","value":"x@example.com"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// active must remain true: the failed PATCH wrote nothing.
	u, err := users.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.Attributes[attrActive] == activeFalse {
		t.Error("partial write: active=false persisted despite the PATCH aborting")
	}
}

// TestParsePatchPath_TableDriven locks the minimal path parser's accept /
// reject decisions directly.
func TestParsePatchPath_TableDriven(t *testing.T) {
	cases := []struct {
		in       string
		wantOK   bool
		wantAttr string
		wantSub  string
	}{
		{"active", true, "active", ""},
		{"userName", true, "username", ""},
		{"name.givenName", true, "name", "givenname"},
		{"", false, "", ""},
		{"emails[type eq \"work\"]", false, "", ""},
		{"urn:ietf:params:scim:schemas:core:2.0:User:active", false, "", ""},
		{"a.b.c", false, "", ""},
		{"name.", false, "", ""},
	}
	for _, tc := range cases {
		got, ok := parsePatchPath(tc.in)
		if ok != tc.wantOK {
			t.Errorf("parsePatchPath(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && (got.attr != tc.wantAttr || got.sub != tc.wantSub) {
			t.Errorf("parsePatchPath(%q) = {%q,%q}, want {%q,%q}", tc.in, got.attr, got.sub, tc.wantAttr, tc.wantSub)
		}
	}
}
