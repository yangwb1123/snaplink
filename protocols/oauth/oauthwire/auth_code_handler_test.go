package oauthwire

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRequest(method, target string, body any) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

func TestIsSecureRedirectURI(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		{"https://example.com/cb", true},
		{"http://example.com/cb", false},
		{"http://localhost:3000/cb", true},
		{"http://127.0.0.1:8080/cb", true},
		{"custom://callback", false},
		{"", false},
		{"http://[::1]:3000/cb", true},
	}
	for _, tc := range tests {
		got := IsSecureRedirectURI(tc.uri)
		if got != tc.want {
			t.Errorf("IsSecureRedirectURI(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}

func TestIsValidPKCEMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"S256", true},
		{"s256", false},
		{"plain", true},
		{"PLAIN", false},
		{"invalid", false},
	}
	for _, tc := range tests {
		got := IsValidPKCEMethod(tc.method)
		if got != tc.want {
			t.Errorf("IsValidPKCEMethod(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}

func TestIsPKCEMethodAllowedForClient(t *testing.T) {
	if !IsPKCEMethodAllowedForClient("S256", nil) {
		t.Error("expected S256 allowed for nil")
	}
	if !IsPKCEMethodAllowedForClient("S256", []string{}) {
		t.Error("expected S256 allowed for empty")
	}
	if !IsPKCEMethodAllowedForClient("S256", []string{"S256"}) {
		t.Error("expected S256 in allowlist")
	}
	if IsPKCEMethodAllowedForClient("plain", []string{"S256"}) {
		t.Error("expected plain rejected")
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXkg"
	hash := sha256.Sum256([]byte(verifier))
	s256Challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	if !VerifyPKCE("S256", s256Challenge, verifier) {
		t.Error("expected S256 verification to pass")
	}
	if VerifyPKCE("S256", "wrong", verifier) {
		t.Error("expected S256 verification to fail")
	}
	if !VerifyPKCE("plain", verifier, verifier) {
		t.Error("expected plain verification to pass")
	}
	if VerifyPKCE("plain", "different", verifier) {
		t.Error("expected plain verification to fail")
	}
	if VerifyPKCE("unknown", "x", "x") {
		t.Error("expected unknown method to fail")
	}
}

func TestIsScopeSubset(t *testing.T) {
	if !IsScopeSubset([]string{"openid", "profile"}, []string{"openid", "profile"}) {
		t.Error("identical scopes should be subset")
	}
	if !IsScopeSubset([]string{"openid"}, []string{"openid", "profile"}) {
		t.Error("subset should pass")
	}
	if IsScopeSubset([]string{"admin"}, []string{"openid"}) {
		t.Error("non-subset should fail")
	}
	if !IsScopeSubset(nil, []string{"openid"}) {
		t.Error("nil want should be subset")
	}
	if !IsScopeSubset([]string{}, []string{"openid"}) {
		t.Error("empty want should be subset")
	}
	if IsScopeSubset([]string{"openid"}, nil) {
		t.Error("non-empty want should NOT be subset of nil")
	}
}

func TestGenerateAuthCodeBytes(t *testing.T) {
	code1, err := GenerateAuthCodeBytes()
	if err != nil {
		t.Fatalf("GenerateAuthCodeBytes: %v", err)
	}
	if code1 == "" {
		t.Fatal("expected non-empty code")
	}
	code2, _ := GenerateAuthCodeBytes()
	if code1 == code2 {
		t.Error("expected different codes on successive calls")
	}
}

func TestBearerToken(t *testing.T) {
	r := newRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer my-token")
	if token := BearerToken(r); token != "my-token" {
		t.Errorf("expected 'my-token', got %q", token)
	}

	r2 := newRequest("GET", "/", nil)
	if token := BearerToken(r2); token != "" {
		t.Errorf("expected empty, got %q", token)
	}

	r3 := newRequest("GET", "/", nil)
	r3.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if token := BearerToken(r3); token != "" {
		t.Errorf("expected empty for Basic, got %q", token)
	}

	r4 := newRequest("GET", "/", nil)
	r4.Header.Set("Authorization", "Bearer")
	if token := BearerToken(r4); token != "" {
		t.Errorf("expected empty for malformed, got %q", token)
	}
}
