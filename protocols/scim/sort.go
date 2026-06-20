package scim

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// SCIM list sorting (RFC 7644 §3.4.2.3). A list/query GET may carry
// ?sortBy=<attr>&sortOrder=ascending|descending; the server returns the
// resources ordered by that attribute. Sorting runs over the projected
// resource view (after filtering, before pagination) reusing the same
// attrLookup the filter evaluator walks, so the sort key semantics match
// what a filter on the same attribute would see. WHY sort before paginate:
// §3.4.2.3 requires the page to be a window into the FULLY sorted set, not a
// sort of one page.

// querySortBy / querySortOrder are the sort query-parameter names
// (RFC 7644 §3.4.2.3). Centralized so no literal leaks.
const (
	querySortBy    = "sortBy"
	querySortOrder = "sortOrder"
)

// sortOrderDescending is the only sortOrder value that reverses the default
// ascending order (RFC 7644 §3.4.2.3). Compared case-insensitively; any
// other value (including the explicit "ascending") sorts ascending.
const sortOrderDescending = "descending"

// sortSpec is a parsed sort request. by is the lower-cased attribute path
// (matching attrLookup keys); when by == "" no sort was requested and the
// slice order is left untouched.
type sortSpec struct {
	by   string
	desc bool
}

// parseSortSpec reads sortBy + sortOrder from the request. An absent sortBy
// yields by=="" (the caller skips sorting). sortBy is lower-cased to match
// the attrLookup key space (SCIM attribute names are case-insensitive,
// RFC 7643 §2.1). An unrecognized attribute is NOT an error here: it
// resolves to "absent" for every resource, so the sort is a stable no-op —
// the same lenient stance the filter evaluator takes for unknown attributes.
func parseSortSpec(r *http.Request) sortSpec {
	by := strings.TrimSpace(r.URL.Query().Get(querySortBy))
	if by == "" {
		return sortSpec{}
	}
	order := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(querySortOrder)))
	return sortSpec{by: strings.ToLower(by), desc: order == sortOrderDescending}
}

// sortUsers stable-sorts a User resource slice in place per spec. A blank
// sortBy leaves the slice untouched.
func sortUsers(in []Resource, spec sortSpec) {
	if spec.by == "" {
		return
	}
	sort.SliceStable(in, func(i, j int) bool {
		a := sortKey(userAttrs(in[i]), spec.by)
		b := sortKey(userAttrs(in[j]), spec.by)
		return lessSortKey(a, b, spec.desc)
	})
}

// sortGroups stable-sorts a Group resource slice in place per spec.
func sortGroups(in []GroupResource, spec sortSpec) {
	if spec.by == "" {
		return
	}
	sort.SliceStable(in, func(i, j int) bool {
		a := sortKey(groupAttrs(in[i]), spec.by)
		b := sortKey(groupAttrs(in[j]), spec.by)
		return lessSortKey(a, b, spec.desc)
	})
}

// sortKey resolves the sort attribute for one resource to a single comparable
// string. For a multi-valued attribute the FIRST value is used as the key
// (RFC 7644 §3.4.2.3: "the primary or first value"); the projections build
// emails primary-first and members sorted, so the first element is stable.
// An absent attribute yields "" so such resources collate before populated
// ones in ascending order — a deterministic, documented placement rather
// than an error.
func sortKey(lookup attrLookup, path string) string {
	vals, present := lookup(path)
	if !present || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// lessSortKey compares two sort keys, numerically when BOTH parse as numbers
// (so "2" sorts before "10") and lexically (case-folded) otherwise. desc
// flips the result. The case fold matches the non-caseExact comparison the
// filter evaluator uses for these string attributes (RFC 7644 §3.4.2.2).
func lessSortKey(a, b string, desc bool) bool {
	less := keyLess(a, b)
	if desc {
		return keyLess(b, a)
	}
	return less
}

// keyLess is the ascending ordering predicate: numeric when both sides are
// numbers, else case-insensitive lexical.
func keyLess(a, b string) bool {
	if af, aerr := strconv.ParseFloat(a, 64); aerr == nil {
		if bf, berr := strconv.ParseFloat(b, 64); berr == nil {
			return af < bf
		}
	}
	return strings.ToLower(a) < strings.ToLower(b)
}
