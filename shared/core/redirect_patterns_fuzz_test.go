package core

import "testing"

// FuzzValidateAndMatchRedirectPattern throws arbitrary pattern/URI pairs at
// the grammar. Patterns and candidate URIs are attacker-controllable at
// provisioning and login time respectively, so a panic on crafted input is a
// remote DoS and a match=true result for a pattern
// ValidateRedirectURIPattern rejects is a gate bypass.
//
// Invariants:
//  1. ValidateRedirectURIPattern(pattern) and MatchRedirectURIPattern never
//     panic.
//  2. A pattern that fails validation must never match anything — the
//     provisioning gates make that state unreachable in production, but a
//     stale store row must not widen the redirect allowlist (Defense in depth
//     in the design doc's Decision 3).
func FuzzValidateAndMatchRedirectPattern(f *testing.F) {
	// Seed corpus: the FAPI shape + the adversarial table.
	seeds := []string{
		"https://app.example/test/*/callback",
		"https://localhost:8443/test/*/callback",
		"https://app.example/test/R7bzpU0mqX8Rghe/callback",
		"https://evil.com/test/x/callback",
		"https://app.example/test/a%2Fb/callback",
		"https://app.example/*",
		"http://app.example/test/*/callback",
		"",
		"https://app.example/test//x/callback",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, pattern, uri string) {
		err := ValidateRedirectURIPattern(pattern)
		got := MatchRedirectURIPattern(pattern, uri)
		if err != nil && got {
			t.Errorf("invalid pattern %q matched URI %q", pattern, uri)
		}
	})
}
