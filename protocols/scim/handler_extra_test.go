package scim

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
)

// These tests cover the User handler branches the main suite does not reach:
// PUT/PATCH userName-uniqueness conflicts (409), PUT/PATCH blank-userName +
// bad-JSON validation, and the pagination parameter edges (non-integer
// startIndex, count clamped to maxPageSize, startIndex<1 clamp).

// TestReplaceUser_DuplicateUserName: a PUT that renames a user to a userName
// already held by ANOTHER user is a 409 uniqueness conflict (replaceUser's
// userNameExists branch).
func TestReplaceUser_DuplicateUserName(t *testing.T) {
	h, _, _ := newTestHandler(t)
	seedUser(t, h, `{"userName":"taken@example.com"}`)
	id := seedUser(t, h, `{"userName":"other@example.com"}`)
	rec := do(t, h, http.MethodPut, pathUsers+"/"+id, `{"userName":"taken@example.com"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeUniqueness {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeUniqueness)
	}
}

// TestReplaceUser_BlankUserName: a PUT body with a blank userName is invalidValue.
func TestReplaceUser_BlankUserName(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"u@example.com"}`)
	rec := do(t, h, http.MethodPut, pathUsers+"/"+id, `{"userName":"   "}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestReplaceUser_BadJSON: a malformed PUT body is invalidSyntax.
func TestReplaceUser_BadJSON(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"u@example.com"}`)
	rec := do(t, h, http.MethodPut, pathUsers+"/"+id, `{bad`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

// TestPatchUser_DuplicateUserName: a PATCH that renames userName onto another
// user's is a 409 (patchUser's userNameExists branch).
func TestPatchUser_DuplicateUserName(t *testing.T) {
	h, _, _ := newTestHandler(t)
	seedUser(t, h, `{"userName":"a@example.com"}`)
	id := seedUser(t, h, `{"userName":"b@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"userName","value":"a@example.com"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeUniqueness {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeUniqueness)
	}
}

// TestPatchUser_BlankUserNameRejected: a PATCH that blanks userName is
// invalidValue (patchUser post-apply required check).
func TestPatchUser_BlankUserNameRejected(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"keep@example.com"}`)
	// Replace userName with whitespace -> blank after trim.
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"userName","value":"   "}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPatchUser_BadJSON: a malformed PATCH body is invalidSyntax (decodePatch).
func TestPatchUser_BadJSON(t *testing.T) {
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"u@example.com"}`)
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

// TestPagination_BadStartIndex: a non-integer startIndex is a 400 invalidValue.
func TestPagination_BadStartIndex(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathUsers+"?startIndex=abc", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

// TestPagination_NegativeCount: a negative count is a 400 invalidValue.
func TestPagination_NegativeCount(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathUsers+"?count=-3", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestPagination_StartIndexBelowOneClamps: startIndex<1 is clamped to 1
// (paginationParams clamp branch), returning the first page.
func TestPagination_StartIndexBelowOneClamps(t *testing.T) {
	h, _, _ := newTestHandler(t)
	for i := 0; i < 3; i++ {
		seedUser(t, h, `{"userName":"c`+string(rune('a'+i))+`@example.com"}`)
	}
	rec := do(t, h, http.MethodGet, pathUsers+"?startIndex=0", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var lr ListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	if lr.StartIndex != 1 {
		t.Errorf("startIndex = %d, want clamped to 1", lr.StartIndex)
	}
}

// TestPagination_CountClampedToMax: a count above maxPageSize is clamped down,
// so itemsPerPage never exceeds the cap (paginationParams max clamp).
func TestPagination_CountClampedToMax(t *testing.T) {
	h, _, _ := newTestHandler(t)
	for i := 0; i < 3; i++ {
		seedUser(t, h, `{"userName":"m`+string(rune('a'+i))+`@example.com"}`)
	}
	rec := do(t, h, http.MethodGet, pathUsers+"?count=99999", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var lr ListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	// Only 3 users exist, so itemsPerPage is 3 (well under the clamp), but the
	// request must not error on an over-cap count.
	if lr.TotalResults != 3 {
		t.Errorf("totalResults = %d, want 3", lr.TotalResults)
	}
}

// TestRelPathPassThroughAndNoLocation: a handler mounted with an EMPTY base
// path dispatches on the bare SCIM-relative URL (relPath pass-through branch)
// and omits meta.location (locationFor empty-base branch).
func TestRelPathPassThroughAndNoLocation(t *testing.T) {
	h := NewHandler(defaultimpl.NewMemoryUserProvider(), "",
		WithIDGenerator(func() string { return "nb-1" }))
	r := httptest.NewRequest(http.MethodPost, "/Users", strings.NewReader(`{"userName":"nb@example.com"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	// With no base path, meta.location is omitted (locationFor empty-base branch).
	if res.Meta != nil && res.Meta.Location != "" {
		t.Errorf("meta.location = %q, want empty with no base path", res.Meta.Location)
	}
}

// TestCreate_CaseInsensitiveDuplicateUserName: posting "Alice@example.com" when
// "alice@example.com" already exists is a 409 (RFC 7643 §8.7.1: caseExact=false).
func TestCreate_CaseInsensitiveDuplicateUserName(t *testing.T) {
	h, _, _ := newTestHandler(t)
	if rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"alice@example.com"}`); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"Alice@example.com"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeUniqueness {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeUniqueness)
	}
}

// TestCreate_UserNameNormalizedToLowercase: a mixed-case userName is stored and
// returned as lowercase (RFC 7643 §8.7.1: server owns the canonical lowercase form).
func TestCreate_UserNameNormalizedToLowercase(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"Alice@Example.COM"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	got := decodeResource(t, rec).UserName
	if got != "alice@example.com" {
		t.Errorf("userName = %q, want %q", got, "alice@example.com")
	}
}

// TestReplaceUser_CaseInsensitiveDuplicateUserName: a PUT that renames a user to a
// userName held by another user with different case is a 409 (RFC 7643 §8.7.1).
func TestReplaceUser_CaseInsensitiveDuplicateUserName(t *testing.T) {
	h, _, _ := newTestHandler(t)
	seedUser(t, h, `{"userName":"taken@example.com"}`)
	id := seedUser(t, h, `{"userName":"other@example.com"}`)
	rec := do(t, h, http.MethodPut, pathUsers+"/"+id, `{"userName":"TAKEN@EXAMPLE.COM"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeUniqueness {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeUniqueness)
	}
}

// TestPatchUser_CaseInsensitiveDuplicateUserName: a PATCH that sets userName to a
// value differing only in case from another user's is a 409 (RFC 7643 §8.7.1).
func TestPatchUser_CaseInsensitiveDuplicateUserName(t *testing.T) {
	h, _, _ := newTestHandler(t)
	seedUser(t, h, `{"userName":"a@example.com"}`)
	id := seedUser(t, h, `{"userName":"b@example.com"}`)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"replace","path":"userName","value":"A@EXAMPLE.COM"}
	]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeUniqueness {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeUniqueness)
	}
}
