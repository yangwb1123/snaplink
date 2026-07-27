package sso_test

// login_early_gate_headers_test.go locks AGENTS.md §3's credential-endpoint
// contract for /auth/login's EARLIEST gates (content-type + Origin), which
// run before the request body is even bound: every /auth/login response —
// success AND error, with NO exception for a pre-bind gate — MUST carry
// Cache-Control: no-store + Pragma: no-cache (Credential Endpoints table) and
// stamp `iss` per RFC 9207 §2 (every /auth/login response uses
// s.resolveIssuer via authzErrorBody, not the plain errorBody).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/cors"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func newLoginGateTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "test-client", Secret: "test-secret", RedirectURIs: []string{"https://app.example.com/callback"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true,
	})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCORS(cors.Policy{AllowedOrigins: []string{"https://app.example.com"}}),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// TestLogin_OriginBlocked_CarriesNoStoreAndIssuer locks that the 403 written by
// the Origin-mismatch gate (rejectDisallowedLoginOrigin) — reached BEFORE the
// request body is bound — still carries the credential-endpoint no-store
// headers and the RFC 9207 `iss` field, exactly like every other /auth/login
// error.
func TestLogin_OriginBlocked_CarriesNoStoreAndIssuer(t *testing.T) {
	t.Parallel()
	httpSrv := newLoginGateTestServer(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		httpSrv.URL+"/auth/login", strings.NewReader(`{"client_id":"test-client"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from the origin gate, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control: got %q, want %q (AGENTS.md §3 credential-endpoint no-store, including errors)", got, "no-store")
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma: got %q, want %q", got, "no-cache")
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("expected non-empty `iss` per RFC 9207 §2 on the origin-blocked response, body=%v", body)
	}
}

// TestLogin_UnsupportedMediaType_CarriesNoStoreAndIssuer locks the same
// contract for the Content-Type gate (rejectNonJSONLogin)'s 415 — the
// earliest possible /auth/login gate, reached before Origin validation and
// before the body is bound.
func TestLogin_UnsupportedMediaType_CarriesNoStoreAndIssuer(t *testing.T) {
	t.Parallel()
	httpSrv := newLoginGateTestServer(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		httpSrv.URL+"/auth/login", strings.NewReader(`client_id=test-client`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 from the content-type gate, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control: got %q, want %q (AGENTS.md §3 credential-endpoint no-store, including errors)", got, "no-store")
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma: got %q, want %q", got, "no-cache")
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("expected non-empty `iss` per RFC 9207 §2 on the unsupported-media-type response, body=%v", body)
	}
}
