package oidc

import (
	"net/url"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// FuzzComposePostLogoutTarget throws arbitrary post_logout_redirect_uri
// + state strings at composePostLogoutTarget with various client allowlist
// configurations and asserts it NEVER panics. The function is called with
// fully attacker-controlled query parameters (the RP redirects the user
// agent to the end_session endpoint with arbitrary query strings), so a
// panic on crafted input is a remote DoS.
//
// The fuzzer exercises three security-relevant invariants:
//   - The return value is always either empty OR a valid absolute URL
//   - A non-empty return always means the target was in the allowlist
//   - The state parameter is properly URL-encoded in the query
func FuzzComposePostLogoutTarget(f *testing.F) {
	// Seed corpus: realistic post-logout URIs with various client configs.
	type seed struct {
		postLogoutURI   string
		state           string
		allowlist       []string
	}
	seeds := []seed{
		{postLogoutURI: "https://client.example/logged-out", state: "abc123", allowlist: []string{"https://client.example/logged-out"}},
		{postLogoutURI: "https://client.example/logged-out?foo=bar", state: "", allowlist: []string{"https://client.example/logged-out?foo=bar"}},
		{postLogoutURI: "https://evil.com/phish", state: "", allowlist: []string{"https://client.example/logged-out"}},
		{postLogoutURI: "", state: "xyz", allowlist: []string{"https://client.example/logged-out"}},
		{postLogoutURI: "https://client.example/logged-out", state: "state with spaces", allowlist: []string{"https://client.example/logged-out"}},
		{postLogoutURI: "http://localhost:3000/cb", state: "", allowlist: []string{"http://localhost:3000/cb"}},
		{postLogoutURI: "https://client.example/../../etc/passwd", state: "", allowlist: []string{"https://client.example/logged-out"}},
		{postLogoutURI: "javascript:alert(1)", state: "", allowlist: []string{"https://client.example/logged-out"}},
		{postLogoutURI: "https://client.example/trailing?x=1&y=2", state: "abc", allowlist: []string{"https://client.example/trailing?x=1&y=2"}},
	}
	for _, s := range seeds {
		f.Add(s.postLogoutURI, s.state, strings.Join(s.allowlist, "\x00"))
	}

	f.Fuzz(func(t *testing.T, postLogoutURI, state, allowlistJoined string) {
		allowlist := splitAllowlist(allowlistJoined)
		client := &core.Client{
			PostLogoutRedirectURIs: allowlist,
		}

		// MUST NOT panic for any input.
		result := composePostLogoutTarget(postLogoutURI, state, client)

		if result == "" {
			// Empty result is valid — the URI was rejected by allowlist or missing.
			return
		}

		// Non-empty MUST be a valid absolute URL.
		parsed, err := url.Parse(result)
		if err != nil {
			t.Fatalf("composePostLogoutTarget returned unparseable URL %q: %v", result, err)
		}
		if !parsed.IsAbs() {
			t.Fatalf("composePostLogoutTarget returned relative URL %q; must be absolute", result)
		}

		// The scheme must be http or https (no javascript: or data:).
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			t.Fatalf("composePostLogoutTarget returned non-http(s) URL %q", result)
		}

		// The base URI (without state) must be in the allowlist.
		baseURI := postLogoutURI
		if state != "" {
			// Strip the state parameter to get the base.
			q := parsed.Query()
			q.Del("state")
			cleaned := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path, RawQuery: q.Encode()}
			baseURI = cleaned.String()
		}
		if !client.IsPostLogoutRedirectURIValid(baseURI) && !client.IsPostLogoutRedirectURIValid(postLogoutURI) {
			t.Fatalf("composePostLogoutTarget returned %q but the base %q is not in the allowlist %v", result, baseURI, allowlist)
		}

		// When state was provided, it MUST appear in the result.
		if state != "" {
			gotState := parsed.Query().Get("state")
			if gotState == "" {
				t.Fatalf("composePostLogoutTarget dropped state %q from result %q", state, result)
			}
		}
	})
}

// splitAllowlist splits the allowlist on \x00 (the fuzzer's serialization
// delimiter). Empty elements are discarded.
func splitAllowlist(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
