package ssotest

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestClient_IsRedirectURIValid(t *testing.T) {
	c := &sso.Client{
		ID: "web", RedirectURIs: []string{"https://app.example.com/cb", "myapp://callback"},
	}
	cases := []struct {
		uri  string
		want bool
	}{
		{"https://app.example.com/cb", true},
		{"myapp://callback", true},
		{"https://attacker.com/cb", false},
		{"", false},
		{"HTTPS://APP.EXAMPLE.COM/CB", false}, // exact string match — no normalization
	}
	for _, tc := range cases {
		if got := c.IsRedirectURIValid(tc.uri); got != tc.want {
			t.Errorf("IsRedirectURIValid(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}

func TestClient_IsRedirectURIValid_EmptyAllowlist(t *testing.T) {
	// Empty allowlist rejects everything (security-critical default).
	c := &sso.Client{ID: "x"}
	if c.IsRedirectURIValid("https://anything") {
		t.Error("empty allowlist should reject all URIs")
	}
}

func TestClient_IsAuthenticatorAllowed_EmptyMeansAny(t *testing.T) {
	c := &sso.Client{ID: "x"}
	for _, name := range []string{"password", "phone", "anything-goes"} {
		if !c.IsAuthenticatorAllowed(name) {
			t.Errorf("empty AllowedAuthenticators should allow %q", name)
		}
	}
}

func TestClient_IsAuthenticatorAllowed_Restricted(t *testing.T) {
	c := &sso.Client{ID: "x", AllowedAuthenticators: []string{"password", "phone"}}
	if !c.IsAuthenticatorAllowed("password") {
		t.Error("password should be allowed")
	}
	if c.IsAuthenticatorAllowed("certificate") {
		t.Error("certificate not in allowlist; should be rejected")
	}
}

func TestSession_IsExpired(t *testing.T) {
	now := time.Now()
	expired := &sso.Session{ExpiresAt: now.Add(-time.Minute)}
	fresh := &sso.Session{ExpiresAt: now.Add(time.Hour)}
	if !expired.IsExpired() {
		t.Error("session past ExpiresAt should be expired")
	}
	if fresh.IsExpired() {
		t.Error("session well before ExpiresAt should not be expired")
	}
}
