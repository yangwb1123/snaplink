package consent

import (
	"slices"
	"strings"
)

// ScopesMatch reports whether a and b contain exactly the same scopes
// regardless of order. Used to bind challenge validation to the exact scope set
// the challenge was issued for.
func ScopesMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := slices.Clone(a)
	bs := slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

// HasPromptValue reports whether the space-separated OIDC prompt parameter
// contains the named value (e.g. "consent"). Case-sensitive per spec.
func HasPromptValue(prompt, val string) bool {
	for _, p := range strings.Fields(prompt) {
		if p == val {
			return true
		}
	}
	return false
}

// ScopesSubsumed reports whether every scope in requested is present in
// granted. An empty requested set is trivially subsumed (nothing to check).
func ScopesSubsumed(granted, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		set[s] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}
