package scim

import (
	"net/http"
	"strings"
	"testing"
)

// These tests cover the sort internals the conditional_sort_test.go suite does
// not reach: numeric ordering (keyLess numeric branch), absent-attribute
// placement (sortKey "" branch), an unrecognized sortBy (stable no-op), and a
// descending sort over a multi-valued attribute.

// TestSortNumericKeyLess: when both keys parse as numbers, keyLess orders them
// numerically so "2" precedes "10" (not lexical). We sort by externalId set to
// numeric strings.
func TestSortNumericKeyLess(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	// externalId carries the numeric sort key; seed out of numeric order.
	for _, ext := range []string{"10", "2", "1", "20"} {
		seedUser(t, h, `{"userName":"u`+ext+`@example.com","externalId":"`+ext+`"}`)
	}
	rec := do(t, h, http.MethodGet, pathUsers+"?sortBy=externalId&sortOrder=ascending", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var lr ListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	var got []string
	for _, r := range lr.Resources {
		got = append(got, r.ExternalID)
	}
	if strings.Join(got, ",") != "1,2,10,20" {
		t.Errorf("numeric sort = %v, want [1 2 10 20]", got)
	}
}

// TestSortAbsentAttributeCollatesFirst: resources missing the sort attribute
// resolve to "" and collate before populated ones in ascending order
// (sortKey's absent branch).
func TestSortAbsentAttributeCollatesFirst(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	seedUser(t, h, `{"userName":"has@example.com","displayName":"Zed"}`)
	seedUser(t, h, `{"userName":"none@example.com"}`) // no displayName
	rec := do(t, h, http.MethodGet, pathUsers+"?sortBy=displayName&sortOrder=ascending", "")
	var lr ListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	if len(lr.Resources) != 2 {
		t.Fatalf("resources = %d, want 2", len(lr.Resources))
	}
	// The user with no displayName ("") sorts first.
	if lr.Resources[0].UserName != "none@example.com" {
		t.Errorf("first = %q, want none@example.com (absent attr collates first)", lr.Resources[0].UserName)
	}
}

// TestSortUnknownAttributeIsNoOp: an unrecognized sortBy resolves to absent for
// every resource (sortKey ""), so sortUsers is a STABLE no-op preserving the
// input order. Exercised directly on a fixed slice because the store's List
// order is unspecified (a handler round-trip can't pin the input order).
func TestSortUnknownAttributeIsNoOp(t *testing.T) {
	t.Parallel()
	in := []Resource{
		{Schemas: []string{SchemaUser}, ID: "1", UserName: "c"},
		{Schemas: []string{SchemaUser}, ID: "2", UserName: "a"},
		{Schemas: []string{SchemaUser}, ID: "3", UserName: "b"},
	}
	sortUsers(in, sortSpec{by: "nonexistentattr"})
	var got []string
	for _, r := range in {
		got = append(got, r.UserName)
	}
	// Stable no-op: input order c,a,b preserved.
	if strings.Join(got, ",") != "c,a,b" {
		t.Errorf("unknown-attr sort reordered the slice: %v, want [c a b]", got)
	}
}

// TestSortDescendingNumeric: descending order flips numeric keyLess.
func TestSortDescendingNumeric(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	for _, ext := range []string{"3", "1", "2"} {
		seedUser(t, h, `{"userName":"d`+ext+`@example.com","externalId":"`+ext+`"}`)
	}
	rec := do(t, h, http.MethodGet, pathUsers+"?sortBy=externalId&sortOrder=descending", "")
	var lr ListResponse
	mustUnmarshal(t, rec.Body.Bytes(), &lr)
	var got []string
	for _, r := range lr.Resources {
		got = append(got, r.ExternalID)
	}
	if strings.Join(got, ",") != "3,2,1" {
		t.Errorf("descending numeric sort = %v, want [3 2 1]", got)
	}
}

// TestParseSortSpec_NoSortBy: an absent sortBy yields the empty spec (the
// caller skips sorting). Exercised directly so the by=="" early return is hit
// without relying on a handler round-trip.
func TestParseSortSpec_NoSortBy(t *testing.T) {
	t.Parallel()
	r := httptest_NewRequest(t, http.MethodGet, "/Users")
	if spec := parseSortSpec(r); spec.by != "" {
		t.Errorf("parseSortSpec with no sortBy = %+v, want empty", spec)
	}
	r = httptest_NewRequest(t, http.MethodGet, "/Users?sortBy=userName&sortOrder=DESCENDING")
	spec := parseSortSpec(r)
	if spec.by != "username" || !spec.desc {
		t.Errorf("parseSortSpec = %+v, want {username true} (case-folded)", spec)
	}
}

// httptest_NewRequest builds a bare request for the direct parseSortSpec test.
func httptest_NewRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, "http://example.test"+target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return r
}
