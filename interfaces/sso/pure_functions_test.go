package sso

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// TestBoundLoginProvider is the cardinality-DoS regression guard: an arbitrary
// (attacker-supplied) provider on the pre-validation /auth/login failure path
// must collapse to "unknown" so it cannot explode the provider metric label,
// while a registered authenticator name passes through.
func TestBoundLoginProvider(t *testing.T) {
	t.Parallel()
	s := &Server{wiringState: wiringState{authenticators: map[string]Authenticator{"password": nil, "webauthn": nil}}}
	if got := s.boundLoginProvider("password"); got != "password" {
		t.Errorf("registered provider must pass through: got %q", got)
	}
	for _, bogus := range []string{"evil-random-xyz", "", "PASSWORD", "../etc"} {
		if got := s.boundLoginProvider(bogus); got != "unknown" {
			t.Errorf("unregistered provider %q must collapse to unknown: got %q", bogus, got)
		}
	}
}

// TestBuildTokenExchangeRequest_ThreadsSenderConstraint verifies the /token
// dispatch carries the captured DPoP JKT / mTLS x5t#S256 into the RFC 8693
// token-exchange request so the issued token can be cnf-bound like every other
// grant (the binding was previously dropped for token-exchange only).
func TestBuildTokenExchangeRequest_ThreadsSenderConstraint(t *testing.T) {
	t.Parallel()
	got := buildTokenExchangeRequest(oauth.TokenRequest{
		SubjectToken:     "st",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		Scope:            "openid",
	}, "jkt-xyz", "x5t-uvw")
	if got.DPoPJKT != "jkt-xyz" || got.MTLSX5T != "x5t-uvw" {
		t.Fatalf("sender constraint not threaded into exchange request: jkt=%q x5t=%q", got.DPoPJKT, got.MTLSX5T)
	}
	if got.SubjectToken != "st" || got.Scope != "openid" {
		t.Fatalf("base fields not mapped: %+v", got)
	}
}

// TestLoginUsedPAR locks in the RFC 9126-vs-RFC 9101 distinction: only the
// urn:ietf:params:oauth:request_uri: PAR scheme counts as "used PAR". A JAR
// (https/http) request_uri must NOT satisfy the RequirePAR gate or FAPI's
// PAR-required rule, or a replayable JAR-by-reference silently downgrades PAR's
// single-use guarantee.
func TestLoginUsedPAR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		requestURI string
		want       bool
	}{
		{"real PAR urn reference", oauth.PARURIPrefix + "abc123", true},
		{"JAR-by-reference https URL is not PAR", "https://rp.example.com/req.jwt", false},
		{"JAR-by-reference http URL is not PAR", "http://rp.example.com/req.jwt", false},
		{"empty request_uri is not PAR", "", false},
	}
	for _, tc := range tests {
		if got := loginUsedPAR(&login.Request{RequestURI: tc.requestURI}); got != tc.want {
			t.Errorf("%s: loginUsedPAR(%q) = %v, want %v", tc.name, tc.requestURI, got, tc.want)
		}
	}
}

func TestIsSecureRedirectURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri  string
		want bool
	}{
		{"https://example.com/cb", true},
		{"http://example.com/cb", false},   // not HTTPS
		{"http://localhost:8080/cb", true}, // localhost is allowed
		{"https://", true},                 // https scheme is allowed
		{"", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.uri, func(t *testing.T) {
			t.Parallel()
			got := isSecureRedirectURI(tc.uri)
			if got != tc.want {
				t.Errorf("isSecureRedirectURI(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestIsValidPKCEMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		want   bool
	}{
		{"S256", true},
		{"plain", true},
		{"", true}, // empty means default method
		{"invalid", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			got := isValidPKCEMethod(tc.method)
			if got != tc.want {
				t.Errorf("isValidPKCEMethod(%q) = %v, want %v", tc.method, got, tc.want)
			}
		})
	}
}

func TestIsScopeSubset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request []string
		allowed []string
		want    bool
	}{
		{"nil allowed blocks all", []string{"openid"}, nil, false},
		{"subset", []string{"openid"}, []string{"openid", "profile"}, true},
		{"exact match", []string{"openid"}, []string{"openid"}, true},
		{"not subset", []string{"openid", "admin"}, []string{"openid"}, false},
		{"empty request", nil, []string{"openid"}, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isScopeSubset(tc.request, tc.allowed)
			if got != tc.want {
				t.Errorf("isScopeSubset(%v, %v) = %v, want %v", tc.request, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestJWTExpUnsafe(t *testing.T) {
	t.Parallel()

	// Valid JWT with future expiry
	token := "eyJhbGciOiJub25lIn0.eyJleHAiOjE4OTM0NTYwMDB9."
	got := jwtExpUnsafe(token)
	if got == 0 {
		t.Error("jwtExpUnsafe() returned 0 for valid token")
	}
	// 1893456000 = 2030-01-01
	if got != 1893456000 {
		t.Errorf("jwtExpUnsafe() = %d, want 1893456000", got)
	}

	// Invalid JWT
	got = jwtExpUnsafe("invalid")
	if got != 0 {
		t.Error("jwtExpUnsafe() should return 0 for invalid token")
	}

	// Empty string
	got = jwtExpUnsafe("")
	if got != 0 {
		t.Error("jwtExpUnsafe() should return 0 for empty token")
	}
}

func TestSortedKeys(t *testing.T) {
	t.Parallel()

	m := map[string]struct{}{
		"b": {},
		"a": {},
		"c": {},
	}
	keys := sortedKeys(m)
	if len(keys) != 3 {
		t.Fatalf("sortedKeys() len = %d, want 3", len(keys))
	}
	if keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Errorf("sortedKeys() = %v, want [a b c]", keys)
	}
}

func TestGenerateDeviceCodeBytes(t *testing.T) {
	t.Parallel()

	code, err := generateDeviceCodeBytes()
	if err != nil {
		t.Fatalf("generateDeviceCodeBytes() error: %v", err)
	}
	if code == "" {
		t.Fatal("generateDeviceCodeBytes() returned empty")
	}
	// Two calls should produce different codes
	code2, _ := generateDeviceCodeBytes()
	if code == code2 {
		t.Error("generateDeviceCodeBytes() returned same value twice")
	}
}

func TestGenerateUserCodeBytes(t *testing.T) {
	t.Parallel()

	code, err := generateUserCodeBytes()
	if err != nil {
		t.Fatalf("generateUserCodeBytes() error: %v", err)
	}
	if code == "" {
		t.Fatal("generateUserCodeBytes() returned empty")
	}
	// Should be 8 chars + dash = 9 (XXXX-XXXX format)
	if len(code) != 9 {
		t.Errorf("generateUserCodeBytes() len = %d, want 9", len(code))
	}
	if code[4] != '-' {
		t.Errorf("generateUserCodeBytes() = %q, want XXXX-XXXX format", code)
	}
}

func TestGenerateAuthCodeBytes(t *testing.T) {
	t.Parallel()

	code, err := generateAuthCodeBytes()
	if err != nil {
		t.Fatalf("generateAuthCodeBytes() error: %v", err)
	}
	if code == "" {
		t.Fatal("generateAuthCodeBytes() returned empty")
	}
}

func TestBuildDiscoveryDocEntry(t *testing.T) {
	t.Parallel()

	body := []byte(`{"issuer":"https://example.com"}`)
	entry := buildDiscoveryDocEntry(body, time.Minute)
	if entry == nil {
		t.Fatal("buildDiscoveryDocEntry() returned nil")
	}
	if string(entry.Body) != string(body) {
		t.Errorf("body = %q, want %q", entry.Body, body)
	}
	if entry.ETag == "" {
		t.Error("buildDiscoveryDocEntry() ETag is empty")
	}
}
