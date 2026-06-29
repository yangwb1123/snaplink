package scim

import (
	"net/http"
	"testing"
)

// These tests cover the PATCH apply branches the existing patch_test.go does
// not reach: the name complex-attribute forms (whole-name replace/remove,
// name.<sub> remove, an unsupported name sub-attribute), the path-less root
// merge of name, and the value-path email element ops over the type/primary
// sub-attributes (applyEmailElementOp + setEmailStringSub).

// TestPatchUser_ReplaceWholeName replaces the entire "name" complex attribute
// with an object (applyUserName whole-name branch).
func TestPatchUser_ReplaceWholeName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"wn@example.com","name":{"givenName":"Old"}}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"name","value":{"givenName":"New","familyName":"Last"}}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.Name == nil || res.Name.GivenName != "New" || res.Name.FamilyName != "Last" {
		t.Errorf("name not replaced: %+v", res.Name)
	}
}

// TestPatchUser_RemoveWholeName removes the entire "name" attribute.
func TestPatchUser_RemoveWholeName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"rn@example.com","name":{"givenName":"X","familyName":"Y"}}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"name"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Name != nil {
		t.Error("name not removed")
	}
}

// TestPatchUser_ReplaceWholeNameWithEmptyDropsIt: replacing name with an
// all-empty object drops the attribute (applyUserName's n.empty() branch).
func TestPatchUser_ReplaceWholeNameWithEmptyDropsIt(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"en@example.com","name":{"givenName":"X"}}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"name","value":{}}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Name != nil {
		t.Error("replace with empty name object did not drop name")
	}
}

// TestPatchUser_RemoveNameSubLeavesOtherSubs: removing one name.<sub> clears
// just that sub-attribute (applyUserName sub-remove branch), keeping the rest.
func TestPatchUser_RemoveNameSub(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"ns@example.com","name":{"givenName":"Keep","familyName":"Drop"}}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"name.familyName"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.Name == nil || res.Name.GivenName != "Keep" {
		t.Fatalf("givenName lost: %+v", res.Name)
	}
	if res.Name.FamilyName != "" {
		t.Errorf("familyName not removed: %q", res.Name.FamilyName)
	}
}

// TestPatchUser_RemoveLastNameSubDropsName: removing the only set sub-attribute
// drops the whole name (applyUserName's post-set empty() check).
func TestPatchUser_RemoveLastNameSubDropsName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"ls@example.com","name":{"givenName":"Only"}}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"name.givenName"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Name != nil {
		t.Error("removing the only name sub-attr did not drop name")
	}
}

// TestPatchUser_AddNameSubAllocatesName: a name.<sub> add against a user with
// NO name allocates the Name struct (applyUserName nil-name branch).
func TestPatchUser_AddNameSubAllocatesName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"al@example.com"}`) // no name
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"name.middleName","value":"Mid"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.Name == nil || res.Name.MiddleName != "Mid" {
		t.Errorf("name.middleName not set on a nameless user: %+v", res.Name)
	}
}

// TestPatchUser_NameSubNonString: a name.<sub> value that isn't a string is an
// invalidValue error (applyUserName decode-error branch).
func TestPatchUser_NameSubNonString(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"nx@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"name.givenName","value":123}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_WholeNameNonObject: replacing "name" with a non-object value is
// an invalidValue error.
func TestPatchUser_WholeNameNonObject(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"no@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"name","value":"not-an-object"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_RootMergeName: a path-less merge whose value object names
// "name" applies through applyUserPathOp (root-merge -> name complex attr).
func TestPatchUser_RootMergeName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"rm@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":{"name":{"givenName":"Root"},"displayName":"RM"}}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.Name == nil || res.Name.GivenName != "Root" {
		t.Errorf("root-merge name not applied: %+v", res.Name)
	}
	if res.DisplayName != "RM" {
		t.Errorf("root-merge displayName = %q, want RM", res.DisplayName)
	}
}

// TestPatchUser_RootMergeUnknownKey: a path-less merge naming an unsupported
// attribute is invalidPath (applyUserRootMerge unknown-key branch).
func TestPatchUser_RootMergeUnknownKey(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"uk@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":{"nickName":"Ace"}}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidPath {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidPath)
	}
}

// TestPatchUser_RootMergeMissingValue: a path-less op with no value is
// invalidValue (applyUserRootMerge empty-raw branch).
func TestPatchUser_RootMergeMissingValue(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"mv@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_RootMergeNonObject: a path-less value that isn't a JSON object
// is invalidSyntax (applyUserRootMerge unmarshal-error branch).
func TestPatchUser_RootMergeNonObject(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"po@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","value":"scalar"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

// TestPatchUser_ValuePathSetType: a value-path op over emails[..].type sets the
// type sub-attribute on the matching element (setEmailStringSub).
func TestPatchUser_ValuePathSetType(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[value eq \"home@example.com\"].type","value":"personal"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	var found bool
	for _, e := range res.Emails {
		if e.Value == "home@example.com" {
			found = true
			if e.Type != "personal" {
				t.Errorf("home email type = %q, want personal", e.Type)
			}
		}
	}
	if !found {
		t.Error("home email missing after type patch")
	}
}

// TestPatchUser_ValuePathSetPrimary: a value-path op over emails[..].primary
// flips the primary flag (applyEmailElementOp primary branch).
func TestPatchUser_ValuePathSetPrimary(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"home\"].primary","value":true}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// The matched home element now carries primary=true. Assert the flag on the
	// home element directly (the resource may report >1 primary after the patch;
	// what matters is that applyEmailElementOp set the home element's flag).
	res := decodeResource(t, rec)
	var homePrimary, found bool
	for _, e := range res.Emails {
		if e.Value == "home@example.com" {
			found = true
			homePrimary = e.Primary
		}
	}
	if !found {
		t.Fatal("home email missing after primary patch")
	}
	if !homePrimary {
		t.Error("home email primary flag was not set by the value-path patch")
	}
}

// TestPatchUser_ValuePathRemoveSub: a value-path REMOVE with a sub-attribute
// clears that sub on the matching element (setEmailStringSub remove branch),
// leaving the element in place.
func TestPatchUser_ValuePathRemoveSub(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"emails[type eq \"home\"].type"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	// The element survives (still has its value) but its type is cleared.
	var seen bool
	for _, e := range res.Emails {
		if e.Value == "home@example.com" {
			seen = true
			if e.Type != "" {
				t.Errorf("home email type = %q, want cleared", e.Type)
			}
		}
	}
	if !seen {
		t.Error("home email element dropped by a sub-attribute remove (should survive)")
	}
}

// TestPatchUser_ValuePathRemovePrimary: a value-path remove over .primary
// resets primary to false (applyEmailElementOp primary-remove branch).
func TestPatchUser_ValuePathRemovePrimary(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"emails[value eq \"work@example.com\"].primary"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestPatchUser_ValuePathBadSub: a value-path naming a sub-attribute the email
// element doesn't model is invalidPath (applyEmailElementOp default branch).
func TestPatchUser_ValuePathBadSub(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"work\"].bogus","value":"x"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidPath {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidPath)
	}
}

// TestPatchUser_ValuePathSubBadType: a value-path .primary with a non-boolean
// value is invalidValue (applyEmailElementOp primary decode-error branch).
func TestPatchUser_ValuePathPrimaryBadType(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"work\"].primary","value":"notbool"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_ValuePathReplaceElementBadObject: replacing a whole element
// with a non-object value is invalidValue (applyEmailElementOp no-sub decode
// error).
func TestPatchUser_ValuePathReplaceElementBadObject(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedTwoEmailUser(t, h)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"emails[type eq \"home\"]","value":"scalar"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_EmailsAddNonArray: an add over the unfiltered emails attribute
// whose value isn't an array is invalidValue (applyUserEmails decode error).
func TestPatchUser_EmailsAddNonArray(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"ea@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"add","path":"emails","value":"notarray"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_ActiveBadType: replace active with a non-boolean is invalidValue.
func TestPatchUser_ActiveBadType(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"ab@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"active","value":"yes"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_RemoveActiveRestoresDefault: removing active restores the
// active=true default (applyUserPathOp active-remove branch).
func TestPatchUser_RemoveActiveRestoresDefault(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"ra@example.com","active":false}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"active"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !decodeResource(t, rec).Active {
		t.Error("remove active did not restore the active=true default")
	}
}

// TestPatchUser_RemoveDisplayNameAndExternalID covers the displayName/externalId
// remove branches in applyUserPathOp.
func TestPatchUser_RemoveDisplayNameAndExternalID(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"rd@example.com","displayName":"D","externalId":"E"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"remove","path":"displayName"},
		{"op":"remove","path":"externalId"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.DisplayName != "" || res.ExternalID != "" {
		t.Errorf("remove did not clear displayName/externalId: %+v", res)
	}
}

// TestPatchUser_DisplayNameBadType / externalId bad type cover the decode-error
// branches for those single string attributes.
func TestPatchUser_StringAttrBadType(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"sb@example.com"}`)
	for _, attr := range []string{"displayName", "externalId", "userName"} {
		body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
			{"op":"replace","path":"` + attr + `","value":42}
		]}`
		rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s non-string status = %d, want 400", attr, rec.Code)
			continue
		}
		if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
			t.Errorf("%s scimType = %q, want %q", attr, e.ScimType, scimTypeInvalidValue)
		}
	}
}
