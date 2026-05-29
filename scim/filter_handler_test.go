package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// createUserNamed POSTs a minimal user with the given userName and returns
// its server-assigned id. It uses the handler so the stored shape matches
// production exactly.
func createUserNamed(t *testing.T, h *Handler, userName string, active bool) string {
	t.Helper()
	body := `{"schemas":["` + SchemaUser + `"],"userName":"` + userName + `","active":` + boolText(active) + `}`
	rec := do(t, h, http.MethodPost, pathUsers, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %q status = %d; body=%s", userName, rec.Code, rec.Body.String())
	}
	return decodeResource(t, rec).ID
}

// listUsersFiltered issues GET /Users?filter=<raw> and decodes the
// ListResponse. raw is URL-escaped here so the spaces/quotes in a filter
// survive transport.
func listUsersFiltered(t *testing.T, h *Handler, raw string) (*httptest.ResponseRecorder, ListResponse) {
	t.Helper()
	rec := do(t, h, http.MethodGet, pathUsers+"?"+queryFilter+"="+url.QueryEscape(raw), "")
	var lr ListResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
			t.Fatalf("decode filtered list: %v; body=%s", err, rec.Body.String())
		}
	}
	return rec, lr
}

// TestListUsersFilterRoundTrip is the headline acceptance test: the
// userName eq round-trip a connector uses to reconcile a single user.
func TestListUsersFilterRoundTrip(t *testing.T) {
	h, _, _ := newTestHandler(t)
	aliceID := createUserNamed(t, h, "alice@example.com", true)
	createUserNamed(t, h, "bob@example.com", true)
	createUserNamed(t, h, "carol@example.com", false)

	rec, lr := listUsersFiltered(t, h, `userName eq "alice@example.com"`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if lr.TotalResults != 1 || len(lr.Resources) != 1 {
		t.Fatalf("filtered total = %d, resources = %d, want 1/1", lr.TotalResults, len(lr.Resources))
	}
	if lr.Resources[0].ID != aliceID || lr.Resources[0].UserName != "alice@example.com" {
		t.Errorf("filtered resource = %+v, want id %q userName alice", lr.Resources[0], aliceID)
	}
}

// TestListUsersFilterCaseInsensitive confirms the eq operator folds case
// for the userName string both in the literal and the keyword.
func TestListUsersFilterCaseInsensitive(t *testing.T) {
	h, _, _ := newTestHandler(t)
	createUserNamed(t, h, "Alice@Example.com", true)

	_, lr := listUsersFiltered(t, h, `userName EQ "alice@example.com"`)
	if lr.TotalResults != 1 {
		t.Fatalf("case-insensitive filter total = %d, want 1", lr.TotalResults)
	}
}

// TestListUsersFilterActive covers the deprovision-reconcile filter Azure
// AD / Okta use: list only disabled accounts.
func TestListUsersFilterActive(t *testing.T) {
	h, _, _ := newTestHandler(t)
	createUserNamed(t, h, "enabled@example.com", true)
	disabledID := createUserNamed(t, h, "disabled@example.com", false)

	_, lr := listUsersFiltered(t, h, `active eq false`)
	if lr.TotalResults != 1 || len(lr.Resources) != 1 {
		t.Fatalf("active=false filter total = %d, resources = %d, want 1/1", lr.TotalResults, len(lr.Resources))
	}
	if lr.Resources[0].ID != disabledID {
		t.Errorf("active=false returned id %q, want %q", lr.Resources[0].ID, disabledID)
	}
}

// TestListUsersFilterLogical exercises an and/or filter through the
// handler so the parser + evaluator + integration path are covered
// end-to-end.
func TestListUsersFilterLogical(t *testing.T) {
	h, _, _ := newTestHandler(t)
	createUserNamed(t, h, "alice@corp.example", true)
	createUserNamed(t, h, "bob@corp.example", false)
	createUserNamed(t, h, "carol@other.example", true)

	// active accounts whose userName ends in "@corp.example": only alice.
	_, lr := listUsersFiltered(t, h, `userName ew "@corp.example" and active eq true`)
	if lr.TotalResults != 1 || lr.Resources[0].UserName != "alice@corp.example" {
		t.Fatalf("and-filter total = %d, first = %+v", lr.TotalResults, lr.Resources)
	}

	// either corp user (or across the two userNames).
	_, lr = listUsersFiltered(t, h, `userName eq "alice@corp.example" or userName eq "bob@corp.example"`)
	if lr.TotalResults != 2 {
		t.Fatalf("or-filter total = %d, want 2", lr.TotalResults)
	}
}

// TestListUsersFilterNoMatch confirms a filter matching nothing returns an
// empty page with totalResults 0 (not an error).
func TestListUsersFilterNoMatch(t *testing.T) {
	h, _, _ := newTestHandler(t)
	createUserNamed(t, h, "alice@example.com", true)

	_, lr := listUsersFiltered(t, h, `userName eq "nobody@example.com"`)
	if lr.TotalResults != 0 || len(lr.Resources) != 0 {
		t.Fatalf("no-match filter total = %d, resources = %d, want 0/0", lr.TotalResults, len(lr.Resources))
	}
}

// TestListUsersFilterInvalid confirms a malformed filter yields HTTP 400
// with the SCIM invalidFilter error shape (RFC 7644 §3.4.2.2 / §3.12).
func TestListUsersFilterInvalid(t *testing.T) {
	h, _, _ := newTestHandler(t)
	createUserNamed(t, h, "alice@example.com", true)

	rec := do(t, h, http.MethodGet, pathUsers+"?"+queryFilter+"="+url.QueryEscape(`userName eq`), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid filter status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	e := decodeError(t, rec)
	if len(e.Schemas) != 1 || e.Schemas[0] != SchemaError {
		t.Errorf("error schemas = %v, want [%s]", e.Schemas, SchemaError)
	}
	if e.Status != "400" {
		t.Errorf("error status = %q, want 400", e.Status)
	}
	if e.ScimType != scimTypeInvalidFilter {
		t.Errorf("error scimType = %q, want %q", e.ScimType, scimTypeInvalidFilter)
	}
}

// TestListUsersFilterValuePathRejected confirms a value-path filter (the
// unsupported "attr[...]" form) is rejected as invalidFilter rather than
// silently returning the unfiltered set.
func TestListUsersFilterValuePathRejected(t *testing.T) {
	h, _, _ := newTestHandler(t)
	createUserNamed(t, h, "alice@example.com", true)

	rec := do(t, h, http.MethodGet, pathUsers+"?"+queryFilter+"="+url.QueryEscape(`emails[type eq "work"]`), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("value-path filter status = %d, want 400", rec.Code)
	}
	if decodeError(t, rec).ScimType != scimTypeInvalidFilter {
		t.Error("value-path filter must be invalidFilter")
	}
}

// TestListUsersFilterPaginationAfterFilter confirms pagination applies to
// the FILTERED set: totalResults is the filtered count, and startIndex/
// count page within it (RFC 7644 §3.4.2.2 + §3.4.2.4).
func TestListUsersFilterPaginationAfterFilter(t *testing.T) {
	h, _, _ := newTestHandler(t)
	// 3 active + 1 disabled; filter to the 3 active, page size 2.
	createUserNamed(t, h, "a@example.com", true)
	createUserNamed(t, h, "b@example.com", true)
	createUserNamed(t, h, "c@example.com", true)
	createUserNamed(t, h, "d@example.com", false)

	rec := do(t, h, http.MethodGet,
		pathUsers+"?"+queryFilter+"="+url.QueryEscape(`active eq true`)+"&count=2&startIndex=1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var lr ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lr.TotalResults != 3 {
		t.Errorf("totalResults = %d, want 3 (filtered count)", lr.TotalResults)
	}
	if lr.ItemsPerPage != 2 || len(lr.Resources) != 2 {
		t.Errorf("page = %d items (%d resources), want 2/2", lr.ItemsPerPage, len(lr.Resources))
	}
}

// TestListUsersNoFilterUnchanged confirms an absent ?filter= returns every
// user (the filter is purely opt-in).
func TestListUsersNoFilterUnchanged(t *testing.T) {
	h, _, _ := newTestHandler(t)
	createUserNamed(t, h, "alice@example.com", true)
	createUserNamed(t, h, "bob@example.com", true)

	rec := do(t, h, http.MethodGet, pathUsers, "")
	var lr ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lr.TotalResults != 2 {
		t.Errorf("no-filter total = %d, want 2", lr.TotalResults)
	}
}

// --- Group filter integration ---

// createGroupNamed POSTs a group and returns its id.
func createGroupNamed(t *testing.T, h *Handler, displayName string) string {
	t.Helper()
	body := `{"schemas":["` + SchemaGroup + `"],"displayName":"` + displayName + `"}`
	rec := do(t, h, http.MethodPost, pathGroups, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group %q status = %d; body=%s", displayName, rec.Code, rec.Body.String())
	}
	return decodeGroupResource(t, rec).ID
}

// TestListGroupsFilterRoundTrip confirms displayName eq filtering through
// the Groups handler.
func TestListGroupsFilterRoundTrip(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	engID := createGroupNamed(t, h, "Engineering")
	createGroupNamed(t, h, "Sales")

	rec := do(t, h, http.MethodGet,
		pathGroups+"?"+queryFilter+"="+url.QueryEscape(`displayName eq "engineering"`), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var lr GroupListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lr.TotalResults != 1 || len(lr.Resources) != 1 {
		t.Fatalf("group filter total = %d, resources = %d, want 1/1", lr.TotalResults, len(lr.Resources))
	}
	if lr.Resources[0].ID != engID {
		t.Errorf("filtered group id = %q, want %q", lr.Resources[0].ID, engID)
	}
}

// TestListGroupsFilterByMember confirms a members eq filter selects groups
// containing a given user id (the membership reconcile a connector runs).
func TestListGroupsFilterByMember(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	engID := createGroupNamed(t, h, "Engineering")
	createGroupNamed(t, h, "Sales")
	// Add user-1 to Engineering via PATCH (add member).
	patch := `{"schemas":["` + SchemaPatchOp + `"],"Operations":[{"op":"add","path":"members","value":[{"value":"user-1"}]}]}`
	if rec := do(t, h, http.MethodPatch, pathGroups+"/"+engID, patch); rec.Code != http.StatusOK {
		t.Fatalf("patch add member status = %d; body=%s", rec.Code, rec.Body.String())
	}

	rec := do(t, h, http.MethodGet,
		pathGroups+"?"+queryFilter+"="+url.QueryEscape(`members eq "user-1"`), "")
	var lr GroupListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lr.TotalResults != 1 || lr.Resources[0].ID != engID {
		t.Fatalf("members filter total = %d, first = %+v, want 1 / %q", lr.TotalResults, lr.Resources, engID)
	}
}

// TestListGroupsFilterInvalid confirms a malformed group filter is
// invalidFilter / 400.
func TestListGroupsFilterInvalid(t *testing.T) {
	h, _, _ := newGroupHandler(t)
	createGroupNamed(t, h, "Engineering")

	rec := do(t, h, http.MethodGet,
		pathGroups+"?"+queryFilter+"="+url.QueryEscape(`displayName co`), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid group filter status = %d, want 400", rec.Code)
	}
	if decodeError(t, rec).ScimType != scimTypeInvalidFilter {
		t.Error("invalid group filter must be invalidFilter")
	}
}
