package sso_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// ---------- Server.ValidateToken ----------

func TestServer_ValidateToken_WithMultipleIssuers(t *testing.T) {
	// Register two issuers; a token from issuer A must validate even
	// when issuer B is checked first. The implementation tries each.
	sessIssuer := defaultimpl.NewSessionTokenIssuer()
	jwtIssuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("validate-test"),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	srv := sso.NewServer(
		sso.WithTokenIssuer("session", sessIssuer),
		sso.WithTokenIssuer("jwt", jwtIssuer),
		sso.WithDefaultTokenStrategy("session"),
	)

	tok, err := sessIssuer.Issue(context.Background(), &sso.Subject{ID: "u-1"}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := srv.ValidateToken(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject != "u-1" {
		t.Errorf("Subject = %q", claims.Subject)
	}
}

func TestServer_ValidateToken_UnknownTokenSurfacesError(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("session", defaultimpl.NewSessionTokenIssuer()),
		sso.WithDefaultTokenStrategy("session"),
	)
	if _, err := srv.ValidateToken(context.Background(), "garbage"); err == nil {
		t.Error("expected error on unknown token")
	}
}

func TestServer_ValidateToken_NoIssuersRegistered(t *testing.T) {
	srv := sso.NewServer() // no issuers
	_, err := srv.ValidateToken(context.Background(), "any")
	if err == nil {
		t.Error("expected error when no issuers registered")
	}
}

// ---------- Server.RegisterAuthenticator ----------

func TestServer_RegisterAuthenticator_AddsAfterConstruction(t *testing.T) {
	srv := sso.NewServer() // no authenticators at build time
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(
			func(_ context.Context, u, p string) (*sso.AuthResult, error) {
				if u == "alice" && p == "pw" {
					return &sso.AuthResult{UserID: "u-1"}, nil
				}
				return nil, errors.New("bad")
			},
		),
	)
	srv.RegisterAuthenticator(pw)

	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// /auth/login with no provider should list the now-registered authenticator.
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json",
		bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	providers, _ := body["providers"].([]any)
	found := false
	for _, p := range providers {
		if s, _ := p.(string); s == "password" {
			found = true
		}
	}
	if !found {
		t.Errorf("password not in providers list: %s", raw)
	}
}

// ---------- handleGetClient ----------

func TestGetClient_HappyPath(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "demo", Secret: "hush", Name: "Demo",
		RedirectURIs: []string{"https://demo.example.com/cb"},
		Active:       true,
	})
	srv := sso.NewServer(sso.WithClientStore(clients))
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL + "/api/v1/clients/demo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}

	var got sso.Client
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "demo" || got.Name != "Demo" {
		t.Errorf("client = %+v", got)
	}
	// Secret must NOT appear in the JSON (the field is json:"-").
	if got.Secret != "" {
		t.Errorf("Secret leaked in response: %q", got.Secret)
	}
}

func TestGetClient_NotFound(t *testing.T) {
	srv := sso.NewServer(sso.WithClientStore(defaultimpl.NewMemoryClientStore()))
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL + "/api/v1/clients/missing")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGetClient_NoClientStore(t *testing.T) {
	srv := sso.NewServer() // no client store
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL + "/api/v1/clients/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// ---------- providersForClient ----------

func TestLogin_ProvidersListing_NoClient(t *testing.T) {
	// POST /auth/login with no provider AND no client_id should list
	// every registered authenticator.
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(
			func(_ context.Context, _, _ string) (*sso.AuthResult, error) { return nil, errors.New("nope") },
		),
	)
	srv := sso.NewServer(sso.WithAuthenticator(pw))
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json",
		bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	providers, _ := body["providers"].([]any)
	if len(providers) == 0 {
		t.Errorf("no providers listed: %v", body)
	}
}

func TestLogin_ProvidersListing_ScopedByClient(t *testing.T) {
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(
			func(_ context.Context, _, _ string) (*sso.AuthResult, error) { return nil, errors.New("nope") },
		),
	)
	store := authenticators.NewMemoryCodeStore()
	phone := authenticators.NewPhoneAuthenticator(store, &stubSMS{})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "pwd-only", Active: true,
		AllowedAuthenticators: []string{"password"}, // restrict to password
	})

	srv := sso.NewServer(
		sso.WithAuthenticator(pw),
		sso.WithAuthenticator(phone),
		sso.WithClientStore(clients),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Query the client-scoped listing.
	body, _ := json.Marshal(map[string]any{"client_id": "pwd-only"})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	providers, _ := out["providers"].([]any)

	if len(providers) != 1 {
		t.Fatalf("providers = %v, want only [password] for restricted client", providers)
	}
	if s, _ := providers[0].(string); s != "password" {
		t.Errorf("provider = %q, want password", s)
	}
}

func TestLogin_ProvidersListing_UnknownClientFallsBackToAll(t *testing.T) {
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(
			func(_ context.Context, _, _ string) (*sso.AuthResult, error) { return nil, errors.New("nope") },
		),
	)
	srv := sso.NewServer(
		sso.WithAuthenticator(pw),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	body, _ := json.Marshal(map[string]any{"client_id": "no-such-client"})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	providers, _ := out["providers"].([]any)
	if len(providers) == 0 {
		t.Errorf("unknown client should fall back to all providers: %v", out)
	}
}
