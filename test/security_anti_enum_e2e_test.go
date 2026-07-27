package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// TestAntiEnumeration verifies oracle-safe error responses on credential
// endpoints per AGENTS.md §3 Anti-Enumeration.
func TestAntiEnumerationE2E(t *testing.T) {
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()

	_ = users.CreateOrUpdate(ctx, &core.User{ID: "alice"})
	// Use a REAL password verifier that rejects wrong passwords
	pwSecret := "correct-horse-battery-staple"
	clients.AddSeed(&core.Client{
		ID: "app", Secret: "secret", Active: true,
		AllowedAuthenticators: []string{"password"},
		AllowedScopes:         []string{"openid"},
		TokenStrategy:         "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer()
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*core.AuthResult, error) {
			if p != pwSecret {
				return nil, errors.New("invalid_credentials")
			}
			return &core.AuthResult{UserID: "alice", Provider: "password"}, nil
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

	// Helper: POST login and return response
	loginResp := func(provider, clientID, username, password string) *http.Response {
		body, _ := json.Marshal(map[string]any{
			"provider":   provider,
			"client_id":  clientID,
			"credential": map[string]string{"username": username, "password": password},
		})
		resp, err := http.Post(hsrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		return resp
	}

	t.Run("WrongPasswordReturns401", func(t *testing.T) {
		resp := loginResp("password", "app", "alice", "wrong-password")
		defer resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("expected 401 for wrong password, got %d", resp.StatusCode)
		}
	})

	t.Run("UnknownUserReturnsSame401", func(t *testing.T) {
		// Since our password verifier doesn't look up users, unknown user
		// with wrong password also returns 401 invalid_credentials
		resp := loginResp("password", "app", "nonexistent", "wrong")
		defer resp.Body.Close()
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		t.Logf("unknown user: status=%d error=%v", resp.StatusCode, body["error"])
		if resp.StatusCode != 401 {
			t.Errorf("expected 401 for unknown user, got %d", resp.StatusCode)
		}
	})

	t.Run("UnknownProviderReturnsConsistentError", func(t *testing.T) {
		resp1 := loginResp("provider_does_not_exist", "app", "alice", "any")
		defer resp1.Body.Close()
		resp2 := loginResp("another_missing_provider", "app", "bob", "x")
		defer resp2.Body.Close()

		if resp1.StatusCode != resp2.StatusCode {
			t.Errorf("different status codes: %d vs %d", resp1.StatusCode, resp2.StatusCode)
		}
		var r1, r2 map[string]any
		json.NewDecoder(resp1.Body).Decode(&r1)
		json.NewDecoder(resp2.Body).Decode(&r2)
		if r1["error"] != r2["error"] || r1["error_description"] != r2["error_description"] {
			t.Errorf("different error bodies: %v vs %v", r1["error"], r2["error"])
		}
		t.Logf("unknown provider error: %v", r1["error"])
	})

	t.Run("InactiveClientVsUnknownClient", func(t *testing.T) {
		// Unknown client
		resp1 := loginResp("password", "does-not-exist", "alice", "any")
		defer resp1.Body.Close()

		// Inactive client
		clients.AddSeed(&core.Client{
			ID: "inactive-client", Secret: "secret", Active: false,
			AllowedAuthenticators: []string{"password"},
		})
		resp2 := loginResp("password", "inactive-client", "alice", "any")
		defer resp2.Body.Close()

		var r1, r2 map[string]any
		json.NewDecoder(resp1.Body).Decode(&r1)
		json.NewDecoder(resp2.Body).Decode(&r2)
		t.Logf("unknown client: status=%d error=%v", resp1.StatusCode, r1["error"])
		t.Logf("inactive client: status=%d error=%v", resp2.StatusCode, r2["error"])
	})

	t.Run("IntrospectionInactiveForUnknownToken", func(t *testing.T) {
		introBody := "token=nonexistent&token_type_hint=access_token"
		req, _ := http.NewRequest("POST", hsrv.URL+"/token/introspect", bytes.NewReader([]byte(introBody)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("app", "secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		defer resp.Body.Close()

		var r map[string]any
		json.NewDecoder(resp.Body).Decode(&r)
		if active, _ := r["active"].(bool); active {
			t.Error("expected active=false for unknown token")
		}
	})

	t.Run("RevokeUnknownTokenReturns200", func(t *testing.T) {
		revBody := "token=nonexistent"
		req, _ := http.NewRequest("POST", hsrv.URL+"/token/revoke", bytes.NewReader([]byte(revBody)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("app", "secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("expected 200 for revoke unknown token, got %d", resp.StatusCode)
		}
	})
}
