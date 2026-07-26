package ssotest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// TestFederationHistoricalKeysEndpoint verifies that the historical keys
// endpoint at /.well-known/openid-federation-historical-keys returns a valid
// JWKS when a HistoricalKeyStore is wired, and an empty keys array when not.
func TestFederationHistoricalKeysEndpoint(t *testing.T) {
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()

	_ = users.CreateOrUpdate(ctx, &core.User{ID: "test"})
	clients.AddSeed(&core.Client{
		ID: "test-client", Secret: "secret", Active: true,
		TokenStrategy: "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer()
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*core.AuthResult, error) {
			return &core.AuthResult{UserID: "test", Provider: "password"}, nil
		},
	))

	t.Run("WithoutStoreReturns404", func(t *testing.T) {
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

		resp, err := http.Get(hsrv.URL + "/.well-known/openid-federation-historical-keys")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()

		// Route is not mounted when no store is wired -- expect 404
		if resp.StatusCode != 404 {
			t.Fatalf("expected 404 (no store), got %d", resp.StatusCode)
		}
	})

	t.Run("WithStoreReturnsHistoricalKeys", func(t *testing.T) {
		keyStore := federation.NewMemoryHistoricalKeyStore()

		_ = keyStore.RecordKey(ctx, &federation.HistoricalKey{
			KID:         "old-key-1",
			ActiveFrom:  now.Add(-96 * time.Hour),
			ActiveUntil: now.Add(-48 * time.Hour),
			JWK:         map[string]any{"kty": "EC", "crv": "P-256", "x": "base64x", "y": "base64y"},
		})
		_ = keyStore.RecordKey(ctx, &federation.HistoricalKey{
			KID:        "recent-key-2",
			ActiveFrom: now.Add(-24 * time.Hour),
			JWK:        map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "base64x"},
		})

		srv := sso.NewServer(
			sso.WithIssuer("https://sso.test"),
			sso.WithUserProvider(users),
			sso.WithClientStore(clients),
			sso.WithAuthenticator(pw),
			sso.WithSessionManager(sessions),
			sso.WithTokenIssuer("jwt", issuer),
			sso.WithIDTokenIssuer(issuer),
			sso.WithDefaultTokenStrategy("jwt"),
			sso.WithFederationHistoricalKeyStore(keyStore),
		)

		hsrv := httptest.NewServer(srv.Handler())
		defer hsrv.Close()

		resp, err := http.Get(hsrv.URL + "/.well-known/openid-federation-historical-keys")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		keys, _ := result["keys"].([]any)
		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}

		firstKey := keys[0].(map[string]any)
		if firstKey["kty"] == nil {
			t.Error("expected JWK fields in key entry")
		}

		t.Logf("historical keys endpoint returned %d keys", len(keys))
	})
}

var now = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
