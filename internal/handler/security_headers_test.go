package handler

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// noopHandler writes a 200 with no headers of its own, so tests can observe
// exactly what SecurityHeaders adds.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestSecurityHeaders_DefaultPolicy(t *testing.T) {
	t.Parallel()
	h := SecurityHeaders(SecurityHeadersPolicy{})(noopHandler)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	cases := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for name, want := range cases {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default directive: %q", csp)
	}
	if !strings.Contains(csp, "script-src 'self' 'nonce-") {
		t.Errorf("CSP script-src missing per-request nonce: %q", csp)
	}
	if pp := rec.Header().Get("Permissions-Policy"); !strings.Contains(pp, "camera=()") {
		t.Errorf("Permissions-Policy = %q, want camera=() present", pp)
	}
}

func TestSecurityHeaders_HSTSOnlyOverTLS(t *testing.T) {
	t.Parallel()
	h := SecurityHeaders(SecurityHeadersPolicy{})(noopHandler)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS set over plain HTTP: %q", hsts)
	}

	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	h.ServeHTTP(rec2, req)
	if hsts := rec2.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("HSTS not set over TLS")
	}
}

func TestSecurityHeaders_DoesNotOverwriteExistingHeaders(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a credential endpoint / form_post page that already set
		// its own values BEFORE WriteHeader.
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	})
	h := SecurityHeaders(SecurityHeadersPolicy{})(inner)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options overwritten: got %q, want SAMEORIGIN preserved", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control disturbed: got %q", got)
	}
}

func TestSecurityHeaders_CustomPolicyOverridesOnlyGivenFields(t *testing.T) {
	t.Parallel()
	policy := SecurityHeadersPolicy{
		CSPDirectives: []string{"default-src 'none'", "script-src 'self'"},
		// PermissionsPolicy left empty ⇒ falls back to the SDK default.
	}
	h := SecurityHeaders(policy)(noopHandler)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("custom CSP directive missing: %q", csp)
	}
	if strings.Contains(csp, "style-src") {
		t.Errorf("unexpected default directive leaked into custom policy: %q", csp)
	}
	if pp := rec.Header().Get("Permissions-Policy"); !strings.Contains(pp, "geolocation=()") {
		t.Errorf("Permissions-Policy did not fall back to default: %q", pp)
	}
}

func TestSecurityHeaders_NonceInContextMatchesCSPHeader(t *testing.T) {
	t.Parallel()
	var seenNonce string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenNonce = core.CSPNonceFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := SecurityHeaders(SecurityHeadersPolicy{})(inner)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seenNonce == "" {
		t.Fatal("no CSP nonce reached the inner handler's request context")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'nonce-"+seenNonce+"'") {
		t.Errorf("CSP header nonce does not match the context nonce: header=%q context nonce=%q", csp, seenNonce)
	}
}

func TestSecurityHeaders_NoncesAreUniquePerRequest(t *testing.T) {
	t.Parallel()
	h := SecurityHeaders(SecurityHeadersPolicy{})(noopHandler)

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		csp := rec.Header().Get("Content-Security-Policy")
		if seen[csp] {
			t.Fatalf("nonce repeated across requests: %q", csp)
		}
		seen[csp] = true
	}
}
