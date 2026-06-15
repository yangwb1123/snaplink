package core

import (
	"testing"
	"time"
)

func TestIsRedirectURIValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		client   *Client
		uri      string
		expected bool
	}{
		{
			name:     "exact match",
			client:   &Client{RedirectURIs: []string{"https://example.com/callback"}},
			uri:      "https://example.com/callback",
			expected: true,
		},
		{
			name:     "no match",
			client:   &Client{RedirectURIs: []string{"https://example.com/callback"}},
			uri:      "https://evil.com/callback",
			expected: false,
		},
		{
			name:     "empty client redirect uris",
			client:   &Client{},
			uri:      "https://example.com/callback",
			expected: false,
		},
		{
			name: "subpath no match",
			client: &Client{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			uri:      "https://example.com/callback/sub",
			expected: false,
		},
		{
			name: "multiple uris match second",
			client: &Client{
				RedirectURIs: []string{"https://app1.example/cb", "https://app2.example/cb"},
			},
			uri:      "https://app2.example/cb",
			expected: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.client.IsRedirectURIValid(tc.uri)
			if got != tc.expected {
				t.Errorf("IsRedirectURIValid(%q) = %v, want %v", tc.uri, got, tc.expected)
			}
		})
	}
}

func TestIsPostLogoutRedirectURIValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		client   *Client
		uri      string
		expected bool
	}{
		{
			name: "exact match",
			client: &Client{
				PostLogoutRedirectURIs: []string{"https://example.com/logged-out"},
			},
			uri:      "https://example.com/logged-out",
			expected: true,
		},
		{
			name: "post logout separate list",
			client: &Client{
				RedirectURIs:          []string{"https://example.com/callback"},
				PostLogoutRedirectURIs: []string{"https://example.com/logged-out"},
			},
			uri:      "https://example.com/logged-out",
			expected: true,
		},
		{
			name: "not in post logout list",
			client: &Client{
				RedirectURIs:          []string{"https://example.com/callback"},
				PostLogoutRedirectURIs: []string{"https://example.com/logged-out"},
			},
			uri:      "https://example.com/callback",
			expected: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.client.IsPostLogoutRedirectURIValid(tc.uri)
			if got != tc.expected {
				t.Errorf("IsPostLogoutRedirectURIValid(%q) = %v, want %v", tc.uri, got, tc.expected)
			}
		})
	}
}

func TestAreResourcesAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		client    *Client
		requested []string
		expected  bool
	}{
		{
			name:      "empty allowlist allows all",
			client:    &Client{},
			requested: []string{"https://api.example.com"},
			expected:  true,
		},
		{
			name:      "empty requested always allowed",
			client:    &Client{AllowedResources: []string{"https://api.example.com"}},
			requested: nil,
			expected:  true,
		},
		{
			name:      "allowed resource",
			client:    &Client{AllowedResources: []string{"https://api.example.com", "https://api2.example.com"}},
			requested: []string{"https://api.example.com"},
			expected:  true,
		},
		{
			name:      "disallowed resource",
			client:    &Client{AllowedResources: []string{"https://api.example.com"}},
			requested: []string{"https://evil.com"},
			expected:  false,
		},
		{
			name: "multiple requested all allowed",
			client: &Client{
				AllowedResources: []string{"https://api1.example.com", "https://api2.example.com"},
			},
			requested: []string{"https://api1.example.com", "https://api2.example.com"},
			expected:  true,
		},
		{
			name: "multiple requested one disallowed",
			client: &Client{
				AllowedResources: []string{"https://api1.example.com"},
			},
			requested: []string{"https://api1.example.com", "https://api2.example.com"},
			expected:  false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.client.AreResourcesAllowed(tc.requested)
			if got != tc.expected {
				t.Errorf("AreResourcesAllowed(%v) = %v, want %v", tc.requested, got, tc.expected)
			}
		})
	}
}

func TestIsAuthenticatorAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		client   *Client
		authName string
		expected bool
	}{
		{
			name:     "empty allowlist allows any",
			client:   &Client{},
			authName: "password",
			expected: true,
		},
		{
			name:     "allowed authenticator",
			client:   &Client{AllowedAuthenticators: []string{"password", "totp"}},
			authName: "password",
			expected: true,
		},
		{
			name:     "disallowed authenticator",
			client:   &Client{AllowedAuthenticators: []string{"password"}},
			authName: "totp",
			expected: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.client.IsAuthenticatorAllowed(tc.authName)
			if got != tc.expected {
				t.Errorf("IsAuthenticatorAllowed(%q) = %v, want %v", tc.authName, got, tc.expected)
			}
		})
	}
}

func TestClientSetFingerprint(t *testing.T) {
	t.Parallel()

	c1 := &Client{ID: "client1", AllowedScopes: []string{"openid", "profile"}}
	c2 := &Client{ID: "client2", AllowedScopes: []string{"openid"}}

	fp := ClientSetFingerprint([]*Client{c1, c2})
	if fp == "" {
		t.Fatal("ClientSetFingerprint returned empty string")
	}

	// Order-independent: reverse order should produce same hash
	fp2 := ClientSetFingerprint([]*Client{c2, c1})
	if fp != fp2 {
		t.Errorf("ClientSetFingerprint order-dependent: %q != %q", fp, fp2)
	}

	// Empty set
	fp3 := ClientSetFingerprint(nil)
	if fp3 == "" {
		t.Fatal("ClientSetFingerprint(nil) should return non-empty hash")
	}
	fp4 := ClientSetFingerprint([]*Client{})
	if fp3 != fp4 {
		t.Errorf("ClientSetFingerprint(nil) != ClientSetFingerprint([]): %q != %q", fp3, fp4)
	}

	// Ignored nils
	fp5 := ClientSetFingerprint([]*Client{c1, nil, c2})
	if fp != fp5 {
		t.Errorf("ClientSetFingerprint with nil should be same: %q != %q", fp, fp5)
	}
}

func TestSessionIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name     string
		session  *Session
		expected bool
	}{
		{
			name:     "not expired",
			session:  &Session{ExpiresAt: now.Add(time.Hour)},
			expected: false,
		},
		{
			name:     "expired",
			session:  &Session{ExpiresAt: now.Add(-time.Hour)},
			expected: true,
		},
		{
			name:     "zero time",
			session:  &Session{},
			expected: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.session.IsExpired()
			if got != tc.expected {
				t.Errorf("IsExpired() = %v, want %v (expiresAt=%v, now=%v)", got, tc.expected, tc.session.ExpiresAt, now)
			}
		})
	}
}

func TestClientSetFingerprintSkipsNil(t *testing.T) {
	t.Parallel()

	fp := ClientSetFingerprint([]*Client{nil, nil})
	if fp == "" {
		t.Fatal("ClientSetFingerprint(all nil) should return non-empty hash")
	}
}
