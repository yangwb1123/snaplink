package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// newDeprovisionLoginServer wires a password authenticator whose verifier ALWAYS
// succeeds (correct credential), so the only thing that can stop login is the
// stored user's SCIM active flag.
func newDeprovisionLoginServer(t *testing.T, users *defaultimpl.MemoryUserProvider) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "c", Active: true, AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: u, Provider: "password"}, nil
		}))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func postDeprovLogin(t *testing.T, srv *httptest.Server, username string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": "c",
		"credential": map[string]string{"username": username, "password": "correct"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestLogin_SCIMDeactivatedUserRejected guards the SCIM-deprovisioning
// enforcement: a user PATCHed active=false (Attributes["scim:active"]=="false")
// MUST NOT obtain tokens even with a correct credential — an IdP connector that
// deactivates the user expects access revoked. A user with the flag absent or
// "true" logs in normally.
func TestLogin_SCIMDeactivatedUserRejected(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &core.User{
		ID: "deactivated", Attributes: map[string]string{core.UserAttrActive: "false"},
	})
	_ = users.CreateOrUpdate(context.Background(), &core.User{
		ID: "active-explicit", Attributes: map[string]string{core.UserAttrActive: "true"},
	})
	_ = users.CreateOrUpdate(context.Background(), &core.User{ID: "active-absent"})
	srv := newDeprovisionLoginServer(t, users)

	// Deactivated -> rejected, no token, account_locked.
	code, body := postDeprovLogin(t, srv, "deactivated")
	if code != http.StatusForbidden {
		t.Fatalf("deactivated login status=%d body=%v, want 403", code, body)
	}
	if body["error"] != "account_locked" {
		t.Errorf("error=%v, want account_locked", body["error"])
	}
	if body["access_token"] != nil {
		t.Errorf("deactivated user obtained a token: %v", body)
	}

	// Active (explicit and absent) -> login succeeds.
	for _, uid := range []string{"active-explicit", "active-absent"} {
		code, body := postDeprovLogin(t, srv, uid)
		if code != http.StatusOK {
			t.Errorf("active user %q login status=%d body=%v, want 200", uid, code, body)
		}
		if body["access_token"] == nil {
			t.Errorf("active user %q got no token: %v", uid, body)
		}
	}
}
