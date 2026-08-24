package core

import (
	"strings"
	"testing"
)

func TestValidateRedirectURIPatternAccepts(t *testing.T) {
	t.Parallel()
	valid := []string{
		"https://localhost:8443/test/*/callback", // the FAPI2 SP FINAL shape
		"https://app.example/oauth/*/cb",
		"https://app.example/a/b/*/c/d",
		"https://app.example:8443/test/*/cb", // non-default port preserved
		"https://app.example:443/test/*/cb",  // explicit default port
		"https://[::1]:8443/test/*/cb",       // IPv6 literal
	}
	for _, p := range valid {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			if err := ValidateRedirectURIPattern(p); err != nil {
				t.Errorf("ValidateRedirectURIPattern(%q) = %v, want nil", p, err)
			}
		})
	}
}

func TestValidateRedirectURIPatternRejects(t *testing.T) {
	t.Parallel()
	invalid := []string{
		"",                                   // empty
		"https://app.example/cb",             // no wildcard at all
		"https://app.example/*",              // bare trailing wildcard
		"https://app.example/*/cb",           // wildcard with no literal prefix segment
		"https://app.example/cb/*",           // trailing wildcard
		"https://app.example/test/*/cb/*/x",  // two wildcards
		"https://app.example/test/cb*",       // partial wildcard
		"https://app.example/test/*x/cb",     // partial wildcard
		"https://app.example/test/a*b/cb",    // partial wildcard
		"https://app.example/test/*/cb?x=1",  // query
		"https://app.example/test/*/cb?",     // empty query delimiter
		"https://app.example/test/*/cb#f",    // fragment
		"https://app.example/test/*/cb#",     // empty fragment delimiter
		"https://*.example.com/test/*/cb",    // host wildcard
		"http://app.example/test/*/cb",       // http scheme
		"https://user@app.example/test/*/cb", // userinfo
		"https://app.example/test//cb",       // empty segment
		"https://app.example/test/*/cb/",     // trailing slash -> empty segment
		"https://app.example/test/%2F/cb",    // percent-encoding in pattern
		"https://app.example/test/%78/cb",    // percent-encoding in pattern
		"https://app.example:abc/test/*/cb",  // non-numeric port
		"https://app.example:/test/*/cb",     // empty port
		"https://app.example/test/ /cb",      // space in segment
		"https://app.example/test/*/cb\\x",   // backslash
		"not a url",                          // unparseable
		"https://app.example",                // no path at all
		"https://app.example/",               // empty path
		"https://app.example/../*",           // dot-segment collapse leaves no literals
	}
	for _, p := range invalid {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			if err := ValidateRedirectURIPattern(p); err == nil {
				t.Errorf("ValidateRedirectURIPattern(%q) = nil, want error", p)
			}
		})
	}
}

func TestMatchRedirectURIPatternMatrix(t *testing.T) {
	t.Parallel()
	pattern := "https://app.example/test/*/callback"
	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "wildcard hit", uri: "https://app.example/test/R7bzpU0mqX8Rghe/callback", want: true},
		{name: "host mismatch", uri: "https://evil.com/test/x/callback", want: false},
		{name: "cross-segment", uri: "https://app.example/test/a/b/callback", want: false},
		{name: "extra tail", uri: "https://app.example/test/x/evil/callback", want: false},
		{name: "encoded slash attack", uri: "https://app.example/test/a%2Fb/callback", want: false},
		{name: "query rejected", uri: "https://app.example/test/a?x=1/callback", want: false},
		{name: "empty query rejected", uri: "https://app.example/test/x/callback?", want: false},
		{name: "fragment rejected", uri: "https://app.example/test/A/callback#frag", want: false},
		{name: "empty fragment rejected", uri: "https://app.example/test/x/callback#", want: false},
		{name: "port mismatch", uri: "https://app.example:8443/test/x/callback", want: false},
		{name: "http rejected", uri: "http://app.example/test/x/callback", want: false},
		{name: "scheme case normalized", uri: "HTTPS://app.example/test/x/callback", want: true},
		{name: "host case normalized", uri: "https://APP.EXAMPLE/test/x/callback", want: true},
		{name: "default port normalized", uri: "https://app.example:443/test/x/callback", want: true},
		{name: "encoded segment decodes", uri: "https://app.example/test/%78/callback", want: true},
		{name: "dot segment collapsed", uri: "https://app.example/a/../test/x/callback", want: true},
		{name: "inner dot segment collapse", uri: "https://app.example/test/a/../x/callback", want: true},
		{name: "encoded dot escape shrinks path", uri: "https://app.example/test/%2E%2E/../x/callback", want: false},
		{name: "double slash rejected", uri: "https://app.example/test//x/callback", want: false},
		{name: "extra segment before callback", uri: "https://app.example/test/only/extra/callback", want: false},
		{name: "empty uri", uri: "", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := MatchRedirectURIPattern(pattern, tc.uri); got != tc.want {
				t.Errorf("MatchRedirectURIPattern(%q, %q) = %v, want %v", pattern, tc.uri, got, tc.want)
			}
		})
	}
}

func TestMatchRedirectURIPatternFAPIShape(t *testing.T) {
	t.Parallel()
	// The archived FAPI2 SP FINAL module callback (results/07832dda-fapi).
	pattern := "https://localhost:8443/test/*/callback"
	if !MatchRedirectURIPattern(pattern, "https://localhost:8443/test/R7bzpU0mqX8Rghe/callback") {
		t.Fatal("archived per-test callback must match the static-client pattern")
	}
}

func TestMatchRedirectURIPatternInvalidPatternNeverMatches(t *testing.T) {
	t.Parallel()
	// Defense in depth: a store row carrying an invalid pattern (pre-migration
	// replica / downstream fork) must never widen the gate.
	for _, p := range []string{"", "not a url", "https://app.example/*"} {
		if MatchRedirectURIPattern(p, "https://app.example/anything/here") {
			t.Errorf("MatchRedirectURIPattern(%q, ...) = true, want false for an invalid pattern", p)
		}
	}
}

func TestMatchRedirectURIPatternPortVariants(t *testing.T) {
	t.Parallel()
	pattern := "https://app.example:8443/test/*/cb"
	for _, uri := range []string{
		"https://app.example:8443/test/x/cb",
		"https://app.example:443/test/x/cb", // explicit 443 vs 8443 -> no
	} {
		want := strings.HasSuffix(uri, ":8443/test/x/cb")
		if got := MatchRedirectURIPattern(pattern, uri); got != want {
			t.Errorf("MatchRedirectURIPattern(%q, %q) = %v, want %v", pattern, uri, got, want)
		}
	}
}
