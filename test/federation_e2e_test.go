package ssotest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

func TestFederationEntityStatementE2E(t *testing.T) {
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()

	_ = users.CreateOrUpdate(ctx, &core.User{ID: "fed-user"})
	clients.AddSeed(&core.Client{
		ID: "fed-client", Secret: "secret", Active: true,
		TokenStrategy: "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer()
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*core.AuthResult, error) {
			return &core.AuthResult{UserID: "fed-user", Provider: "password"}, nil
		},
	))

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithSessionManager(sessions),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)

	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()

	t.Run("SSFConfiguration", func(t *testing.T) {
		resp, err := http.Get(hsrv.URL + "/.well-known/ssf-configuration")
		if err != nil {
			t.Fatalf("GET SSF config: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var doc map[string]any
		json.NewDecoder(resp.Body).Decode(&doc)

		if doc["issuer"] != "https://sso.test" {
			t.Errorf("expected issuer 'https://sso.test', got '%v'", doc["issuer"])
		}
		if doc["delivery_methods_supported"] == nil {
			t.Error("expected delivery_methods_supported")
		}
		t.Logf("SSF config: issuer=%v, delivery=%v", doc["issuer"], doc["delivery_methods_supported"])
	})

	t.Run("Discovery", func(t *testing.T) {
		resp, err := http.Get(hsrv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var doc map[string]any
		json.NewDecoder(resp.Body).Decode(&doc)

		if doc["issuer"] != "https://sso.test" {
			t.Errorf("expected issuer 'https://sso.test', got '%v'", doc["issuer"])
		}
		if doc["jwks_uri"] == nil {
			t.Error("expected jwks_uri in discovery")
		}
		t.Logf("Discovery: issuer=%v, jwks=%v, authz=%v",
			doc["issuer"], doc["jwks_uri"], doc["authorization_endpoint"])
	})

	t.Run("JWKS", func(t *testing.T) {
		resp, err := http.Get(hsrv.URL + "/.well-known/jwks.json")
		if err != nil {
			t.Fatalf("GET JWKS: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var doc map[string]any
		json.NewDecoder(resp.Body).Decode(&doc)

		if doc["keys"] == nil {
			t.Fatal("expected keys in JWKS response")
		}
		keys := doc["keys"].([]any)
		if len(keys) == 0 {
			t.Fatal("expected at least one key")
		}
		t.Logf("JWKS: %d keys", len(keys))
	})
}
