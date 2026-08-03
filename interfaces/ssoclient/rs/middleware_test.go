package rs_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

func TestHTTPMiddleware_NoCredentials401(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	cfg := newTestConfig(t, iss, "")
	h := rs.HTTPMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run without credentials")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/orders", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// RFC 6750 §3.1: no credentials presented -> bare scheme, no error attr.
	challenge := rec.Header().Get("WWW-Authenticate")
	if challenge != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want bare %q", challenge, "Bearer")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestHTTPMiddleware_InvalidToken401(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	cfg := newTestConfig(t, iss, "")
	h := rs.HTTPMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run with an invalid token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want error=\"invalid_token\"", challenge)
	}
	if !strings.HasPrefix(challenge, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q, want Bearer scheme", challenge)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestHTTPMiddleware_ServingRegionMismatch403 pins the decision-3 wire
// shape: a region mismatch is a GOVERNANCE denial (403 region_not_allowed,
// no WWW-Authenticate challenge — mirrors the AS's authzErrorBody
// discipline), while token-validity failures stay 401 (existing tests). The
// no-store headers remain set on the 403 like every credential-bearing
// exchange.
func TestHTTPMiddleware_ServingRegionMismatch403(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub":            "user-1",
		"serving_region": "us-east-1",
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.AllowedServingRegions = []string{"eu-west-1"}
	h := rs.HTTPMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run for a region-mismatched token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ch := rec.Header().Get("WWW-Authenticate"); ch != "" {
		t.Errorf("WWW-Authenticate = %q, want none (governance denial, not token-validity failure)", ch)
	}
	if body := rec.Body.String(); body != `{"error":"region_not_allowed"}` {
		t.Errorf("body = %q, want region_not_allowed JSON", body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on the 403 too", cc)
	}
}

// TestHTTPMiddleware_ServingRegionMismatchDPoP proves the sentinel survives
// the ValidateTokenWithDPoP wrap: a region-mismatched token presented over
// the DPoP scheme still maps to 403, because validateByMode (and its region
// gate) runs FIRST inside ValidateTokenWithDPoP.
func TestHTTPMiddleware_ServingRegionMismatchDPoP(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub":            "user-1",
		"serving_region": "us-east-1",
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.AllowedServingRegions = []string{"eu-west-1"}
	h := rs.HTTPMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run")
	}))

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("Authorization", "DPoP "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// The DPoP proof is missing, but the region gate sits AFTER full token
	// validation (validateByMode runs first inside ValidateTokenWithDPoP) —
	// the token is valid, so this is the governance 403, not a DPoP 401.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (region sentinel survives the DPoP wrap)", rec.Code)
	}
	if ch := rec.Header().Get("WWW-Authenticate"); ch != "" {
		t.Errorf("WWW-Authenticate = %q, want none", ch)
	}
}

func TestHTTPMiddleware_ValidTokenServesRequest(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	tok, err := iss.MintAccessToken(map[string]any{"sub": "user-1", "scope": "orders:read"})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")

	var gotSubject string
	h := rs.HTTPMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := rs.ClaimsFromContext(r.Context())
		if !ok {
			t.Fatal("ClaimsFromContext: not found")
		}
		gotSubject = claims.Subject
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotSubject != "user-1" {
		t.Errorf("subject seen by handler = %q, want user-1", gotSubject)
	}
}

func TestHTTPMiddleware_CnfBoundTokenRequiresDPoPProof(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	key := newDPoPKey(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"cnf": map[string]any{"jkt": key.thumbprint()},
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	h := rs.HTTPMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run: cnf-bound token presented as plain Bearer")
	}))

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestHTTPMiddleware_DPoPHappyPath(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	key := newDPoPKey(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"cnf": map[string]any{"jkt": key.thumbprint()},
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.DPoPVerifier = rs.NewDPoPVerifier()
	h := rs.HTTPMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/orders", nil)
	req.Header.Set("Authorization", "DPoP "+tok)
	req.Header.Set("DPoP", key.proof(t, http.MethodGet, "https://api.example.com/orders", tok, time.Now().Unix(), "mw-jti-1"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}
