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
