package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mustUnmarshal decodes a JSON body into v, failing the test on error.
func mustUnmarshal(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, body)
	}
}

// doH issues a request with custom headers against the handler. The base do()
// helper can't set conditional headers, so the ETag tests use this.
func doH(t *testing.T, h *Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, testBase+path, nil)
	} else {
		r = httptest.NewRequest(method, testBase+path, strings.NewReader(body))
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestETag_RoundTrip: create + get + list all stamp meta.version, the GET
// echoes it in the ETag header, and the header equals the body value
// (RFC 7644 §3.14).
func TestETag_RoundTrip(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"etag@example.com"}`)

	rec := do(t, h, http.MethodGet, pathUsers+"/"+id, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.Meta == nil || res.Meta.Version == "" {
		t.Fatalf("meta.version not set: %+v", res.Meta)
	}
	if !strings.HasPrefix(res.Meta.Version, `W/"`) {
		t.Errorf("meta.version = %q, want a weak ETag (W/\"...\")", res.Meta.Version)
	}
	if hdr := rec.Header().Get("ETag"); hdr != res.Meta.Version {
		t.Errorf("ETag header = %q, want body version %q", hdr, res.Meta.Version)
	}
}

// TestETag_DeterministicForSameContent: two users with identical attributes
// hash to the same version (content-derived ETag), and the version changes
// when content changes.
func TestETag_DeterministicForSameContent(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"v1@example.com","displayName":"V"}`)

	v1 := decodeResource(t, do(t, h, http.MethodGet, pathUsers+"/"+id, "")).Meta.Version

	// A no-op GET returns the same version.
	v1again := decodeResource(t, do(t, h, http.MethodGet, pathUsers+"/"+id, "")).Meta.Version
	if v1 != v1again {
		t.Errorf("version not stable across reads: %q != %q", v1, v1again)
	}

	// Changing content (displayName) changes the version.
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"displayName","value":"W"}]}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, patch)
	v2 := decodeResource(t, rec).Meta.Version
	if v2 == v1 {
		t.Errorf("version did not change after content change: still %q", v2)
	}
}

// TestETag_IfMatchMismatch412: a write whose If-Match is stale is rejected
// 412 and writes nothing; a write with the current version succeeds.
func TestETag_IfMatchMismatch412(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"ifmatch@example.com"}`)
	current := decodeResource(t, do(t, h, http.MethodGet, pathUsers+"/"+id, "")).Meta.Version

	// Stale If-Match -> 412 Precondition Failed.
	body := `{"userName":"ifmatch@example.com","displayName":"Changed"}`
	rec := doH(t, h, http.MethodPut, pathUsers+"/"+id, body, map[string]string{"If-Match": `W/"stale0000"`})
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match status = %d, want 412; body=%s", rec.Code, rec.Body.String())
	}
	// The user was NOT modified.
	after := decodeResource(t, do(t, h, http.MethodGet, pathUsers+"/"+id, ""))
	if after.DisplayName != "" {
		t.Errorf("displayName = %q after rejected PUT, want unchanged (empty)", after.DisplayName)
	}

	// Matching If-Match -> the write proceeds.
	rec = doH(t, h, http.MethodPut, pathUsers+"/"+id, body, map[string]string{"If-Match": current})
	if rec.Code != http.StatusOK {
		t.Fatalf("matching If-Match status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).DisplayName != "Changed" {
		t.Error("matching If-Match PUT did not apply the change")
	}
}

// TestETag_IfMatchPatchAndDelete: If-Match guards PATCH and DELETE too.
func TestETag_IfMatchPatchAndDelete(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"guard@example.com"}`)
	cur := decodeResource(t, do(t, h, http.MethodGet, pathUsers+"/"+id, "")).Meta.Version

	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"active","value":false}]}`
	if rec := doH(t, h, http.MethodPatch, pathUsers+"/"+id, patch, map[string]string{"If-Match": `W/"nope"`}); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match PATCH = %d, want 412", rec.Code)
	}
	if rec := doH(t, h, http.MethodDelete, pathUsers+"/"+id, "", map[string]string{"If-Match": `W/"nope"`}); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match DELETE = %d, want 412", rec.Code)
	}
	// Current version lets DELETE through.
	if rec := doH(t, h, http.MethodDelete, pathUsers+"/"+id, "", map[string]string{"If-Match": cur}); rec.Code != http.StatusNoContent {
		t.Fatalf("matching If-Match DELETE = %d, want 204", rec.Code)
	}
}

// TestETag_IfNoneMatch304: a GET whose If-None-Match equals the current
// version returns 304 with no body and the ETag header (RFC 7644 §3.14).
func TestETag_IfNoneMatch304(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"inm@example.com"}`)
	cur := decodeResource(t, do(t, h, http.MethodGet, pathUsers+"/"+id, "")).Meta.Version

	rec := doH(t, h, http.MethodGet, pathUsers+"/"+id, "", map[string]string{"If-None-Match": cur})
	if rec.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match (match) status = %d, want 304; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("304 carried a body: %s", rec.Body.String())
	}
	if rec.Header().Get("ETag") != cur {
		t.Errorf("304 ETag = %q, want %q", rec.Header().Get("ETag"), cur)
	}

	// A non-matching If-None-Match serves the body normally.
	rec = doH(t, h, http.MethodGet, pathUsers+"/"+id, "", map[string]string{"If-None-Match": `W/"different"`})
	if rec.Code != http.StatusOK {
		t.Fatalf("If-None-Match (no match) status = %d, want 200", rec.Code)
	}
}

// TestETag_WildcardIfMatch: If-Match:* matches any existing resource
// (RFC 7232 §3.1).
func TestETag_WildcardIfMatch(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	id := seedUser(t, h, `{"userName":"wild@example.com"}`)
	body := `{"userName":"wild@example.com","displayName":"D"}`
	rec := doH(t, h, http.MethodPut, pathUsers+"/"+id, body, map[string]string{"If-Match": "*"})
	if rec.Code != http.StatusOK {
		t.Fatalf("If-Match:* status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestETag_Group: groups also stamp meta.version and honor If-Match.
func TestETag_Group(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	id := seedGroup(t, h, `{"displayName":"G"}`)
	g := decodeGroupResource(t, do(t, h, http.MethodGet, pathGroups+"/"+id, ""))
	if g.Meta == nil || g.Meta.Version == "" {
		t.Fatalf("group meta.version not set: %+v", g.Meta)
	}
	// Stale If-Match -> 412.
	if rec := doH(t, h, http.MethodPut, pathGroups+"/"+id, `{"displayName":"G2"}`, map[string]string{"If-Match": `W/"old"`}); rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale group If-Match = %d, want 412", rec.Code)
	}
	// Current version -> proceeds.
	if rec := doH(t, h, http.MethodPut, pathGroups+"/"+id, `{"displayName":"G2"}`, map[string]string{"If-Match": g.Meta.Version}); rec.Code != http.StatusOK {
		t.Fatalf("matching group If-Match = %d, want 200", rec.Code)
	}
}

// TestSort_UserName exercises ascending + descending sort by userName
// (RFC 7644 §3.4.2.3): the page is a window into the FULLY sorted set.
func TestSort_UserName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	// Seed out of order so a no-sort list would not be alphabetical.
	for _, name := range []string{"charlie", "alice", "bob"} {
		seedUser(t, h, `{"userName":"`+name+`"}`)
	}

	asc := listUserNames(t, h, "?sortBy=userName&sortOrder=ascending")
	if got := strings.Join(asc, ","); got != "alice,bob,charlie" {
		t.Errorf("ascending sort = %q, want alice,bob,charlie", got)
	}

	desc := listUserNames(t, h, "?sortBy=userName&sortOrder=descending")
	if got := strings.Join(desc, ","); got != "charlie,bob,alice" {
		t.Errorf("descending sort = %q, want charlie,bob,alice", got)
	}

	// Default sortOrder is ascending (RFC 7644 §3.4.2.3).
	def := listUserNames(t, h, "?sortBy=userName")
	if got := strings.Join(def, ","); got != "alice,bob,charlie" {
		t.Errorf("default sortOrder = %q, want ascending alice,bob,charlie", got)
	}
}

// TestSort_AppliesAcrossPages: sort runs before pagination, so a page is a
// window into the globally sorted set, not a sort of one page.
func TestSort_AppliesAcrossPages(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	for _, name := range []string{"d", "b", "a", "c"} {
		seedUser(t, h, `{"userName":"`+name+`"}`)
	}
	// Ascending, first page of 2 -> the two smallest.
	page := listUserNames(t, h, "?sortBy=userName&sortOrder=ascending&startIndex=1&count=2")
	if got := strings.Join(page, ","); got != "a,b" {
		t.Errorf("sorted page 1 = %q, want a,b", got)
	}
}

// TestSort_Group exercises group sort by displayName.
func TestSort_Group(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	for _, name := range []string{"Zeta", "Alpha", "Mu"} {
		seedGroup(t, h, `{"displayName":"`+name+`"}`)
	}
	rec := do(t, h, http.MethodGet, pathGroups+"?sortBy=displayName&sortOrder=descending", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list groups status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var lr GroupListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	var names []string
	for _, g := range lr.Resources {
		names = append(names, g.DisplayName)
	}
	if got := strings.Join(names, ","); got != "Zeta,Mu,Alpha" {
		t.Errorf("descending group sort = %q, want Zeta,Mu,Alpha", got)
	}
}

// listUserNames lists users with the given query suffix and returns the
// userName of each resource in page order.
func listUserNames(t *testing.T, h *Handler, query string) []string {
	t.Helper()
	rec := do(t, h, http.MethodGet, pathUsers+query, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list users status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var lr ListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	out := make([]string, 0, len(lr.Resources))
	for _, r := range lr.Resources {
		out = append(out, r.UserName)
	}
	return out
}
