package scim

import (
	"context"
	"net/http"
	"testing"

	"github.com/snaplink/sso/platform/audit"
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

// TestPatchUser_PreservesNonSCIMState is the RFC 7644 §3.5.2 partial-update
// regression guard: a PATCH (and PUT) MUST NOT wipe server-managed state SCIM
// does not model -- the user's password_hash credential, federation Provider
// linkage, and OIDC claim attributes. The lossy load->Resource->User round-trip
// previously rebuilt Attributes from only "scim:" keys, so a routine deprovision
// or displayName sync silently destroyed the credential (password lockout) and
// the federation link.
func TestPatchUser_PreservesNonSCIMState(t *testing.T) {
	h, users, _ := newTestHandler(t)
	ctx := context.Background()
	id := seedUser(t, h, `{"userName":"keep@example.com","active":true,"displayName":"Before"}`)

	// Inject state SCIM never models, exactly as login + federation would persist
	// it on the SAME shared user record.
	u, err := users.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.Attributes == nil {
		u.Attributes = map[string]string{}
	}
	u.Attributes["password_hash"] = "$2a$10$deadbeefdeadbeefdeadbe"
	u.Attributes["password_hash_format"] = "bcrypt"
	u.Attributes["email_verified"] = "true"
	u.Provider = "okta"
	if err := users.CreateOrUpdate(ctx, u); err != nil {
		t.Fatalf("seed non-scim state: %v", err)
	}

	assertPreserved := func(stage string) {
		got, err := users.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("%s: get: %v", stage, err)
		}
		if got.Attributes["password_hash"] != "$2a$10$deadbeefdeadbeefdeadbe" {
			t.Errorf("%s: password_hash wiped (=%q) -- credential destroyed", stage, got.Attributes["password_hash"])
		}
		if got.Attributes["password_hash_format"] != "bcrypt" {
			t.Errorf("%s: password_hash_format wiped", stage)
		}
		if got.Attributes["email_verified"] != "true" {
			t.Errorf("%s: non-scim claim attribute wiped", stage)
		}
		if got.Provider != "okta" {
			t.Errorf("%s: Provider federation linkage wiped (=%q)", stage, got.Provider)
		}
	}

	// PATCH deprovision (the canonical Azure AD / Okta op).
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d; body=%s", rec.Code, rec.Body.String())
	}
	assertPreserved("after PATCH")

	// PUT full replace -- a SCIM client cannot re-supply password_hash / Provider.
	rec = do(t, h, http.MethodPut, pathUsers+"/"+id,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"keep@example.com","displayName":"After","active":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d; body=%s", rec.Code, rec.Body.String())
	}
	assertPreserved("after PUT")

	// Sanity: the SCIM-modeled change DID still apply through the preservation.
	if got, _ := users.GetByID(ctx, id); got.Name != "After" {
		t.Errorf("PUT displayName not applied through preservation: Name=%q", got.Name)
	}
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

// TestPatchUser_UnsupportedPath: a path the parser still can't honor (a
// schema-URN-qualified path) is 400 invalidPath, not a silent no-op. Note
// that value-path filters ARE now supported (see
// TestPatchUser_ValuePathFilter); a non-existent attribute behind a value
// filter is what stays unsupported here.
func TestPatchUser_UnsupportedPath(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"f@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:active","value":false}
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
		// Value-path filters are now accepted (RFC 7644 §3.5.2): the bracket
		// selects multi-valued element(s); an optional ".<sub>" follows.
		{"emails[type eq \"work\"]", true, "emails", ""},
		{"emails[type eq \"work\"].value", true, "emails", "value"},
		{"members[value eq \"u1\"]", true, "members", ""},
		// Malformed value-paths stay rejected.
		{"emails[]", false, "", ""},
		{"emails[type eq \"work\"].", false, "", ""},
		{"emails[type eq \"work\"]extra", false, "", ""},
		{"[type eq \"work\"]", false, "", ""},
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

// seedTwoEmailUser creates a user with a work + home email and returns its id.
func seedTwoEmailUser(t *testing.T, h *Handler) string {
	t.Helper()
	return seedUser(t, h, `{"userName":"vp@example.com","emails":[
		{"value":"work@example.com","type":"work","primary":true},
		{"value":"home@example.com","type":"home"}
	]}`)
}

// emailByType returns the value of the first email of the given type.
func emailByType(res Resource, typ string) string {
	for _, e := range res.Emails {
		if e.Type == typ {
			return e.Value
		}
	}
	return ""
}

// TestPatchUser_ValuePathFilter: a PATCH with a value-path filter sub-attr
// ("emails[type eq \"work\"].value") sets ONLY the matching element's value
// (RFC 7644 §3.5.2), leaving the non-matching element untouched.
func TestPatchUser_ValuePathFilter(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"work\"].value","value":"newwork@example.com"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if got := emailByType(res, "work"); got != "newwork@example.com" {
		t.Errorf("work email = %q, want newwork@example.com", got)
	}
	if got := emailByType(res, "home"); got != "home@example.com" {
		t.Errorf("home email = %q, want untouched home@example.com", got)
	}
}

// TestPatchUser_ValuePathReplaceElement: a value-path with NO sub-attribute
// replaces the whole matching element with the supplied object.
func TestPatchUser_ValuePathReplaceElement(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"home\"]","value":{"value":"h2@example.com","type":"home"}}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := emailByType(decodeResource(t, rec), "home"); got != "h2@example.com" {
		t.Errorf("home email = %q, want h2@example.com", got)
	}
}

// TestPatchUser_ValuePathRemoveElement: a value-path remove drops ONLY the
// matching element (RFC 7644 §3.5.2).
func TestPatchUser_ValuePathRemoveElement(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"emails[type eq \"home\"]"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if emailByType(res, "home") != "" {
		t.Error("home email still present after value-path remove")
	}
	if emailByType(res, "work") != "work@example.com" {
		t.Error("work email should survive a home-only remove")
	}
}

// TestPatchUser_ValuePathNoTarget: a value-path filter matching no element is
// a noTarget error (RFC 7644 §3.5.2 / Table 9), so the client learns nothing
// was changed rather than believing the op took.
func TestPatchUser_ValuePathNoTarget(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"other\"].value","value":"x@example.com"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeNoTarget {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeNoTarget)
	}
}
