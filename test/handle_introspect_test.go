package ssotest

import "github.com/snaplink/sso/protocols/oauth"

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

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

const (
	introUser   = "u-intro"
	introClient = "intro-client"
	introSecret = "intro-secret"
)

func newIntrospectionServer(t *testing.T) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: introUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: introClient, Secret: introSecret,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: introUser}, nil
		},
	))
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(refresh, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, refresh
}

// loginForTokens posts /auth/login and returns (access, refresh).
func loginForTokens(t *testing.T, srv *httptest.Server) (access, refresh string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  introClient,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"read", "write"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ = out["access_token"].(string)
	refresh, _ = out["refresh_token"].(string)
	return access, refresh
}

func postIntrospect(t *testing.T, srv *httptest.Server, token, hint, id, secret string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"token":           token,
		"token_type_hint": hint,
		"client_id":       id,
		"client_secret":   secret,
	})
	resp, err := http.Post(srv.URL+"/token/introspect", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// ---------- introspection ----------

func TestIntrospect_ValidAccessToken(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	access, _ := loginForTokens(t, srv)

	status, body := postIntrospect(t, srv, access, "", introClient, introSecret)
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, body)
	}
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active = false, want true (valid access token)")
	}
	if body["sub"] != introUser {
		t.Errorf("sub = %v want %q", body["sub"], introUser)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}
	if body["token_type_hint"] != "access_token" {
		t.Errorf("token_type_hint = %v", body["token_type_hint"])
	}
}

func TestIntrospect_ValidRefreshTokenViaInspector(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	_, refresh := loginForTokens(t, srv)

	status, body := postIntrospect(t, srv, refresh, "refresh_token", introClient, introSecret)
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, body)
	}
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active = false, want true (valid refresh token)")
	}
	if body["client_id"] != introClient {
		t.Errorf("client_id = %v want %q", body["client_id"], introClient)
	}
	if body["token_type_hint"] != "refresh_token" {
		t.Errorf("token_type_hint = %v", body["token_type_hint"])
	}
}

func TestIntrospect_UnknownTokenReturnsInactive(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	status, body := postIntrospect(t, srv, "garbage-token", "", introClient, introSecret)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if active, _ := body["active"].(bool); active {
		t.Errorf("active = true, want false for unknown token")
	}
	// §2.2: inactive responses MUST NOT include any other metadata.
	for k := range body {
		if k != "active" {
			t.Errorf("inactive response leaked metadata key %q", k)
		}
	}
}

func TestIntrospect_WrongHintStillFindsTokenViaFallback(t *testing.T) {
	// Caller mislabels an access token as refresh_token. The server
	// MUST still find it after the fallback to access introspection.
	srv, _ := newIntrospectionServer(t)
	access, _ := loginForTokens(t, srv)

	status, body := postIntrospect(t, srv, access, "refresh_token", introClient, introSecret)
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, body)
	}
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active = false despite valid access token + wrong hint")
	}
}

func TestIntrospect_RejectsMissingCreds(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	access, _ := loginForTokens(t, srv)
	status, body := postIntrospect(t, srv, access, "", "", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestIntrospect_RejectsWrongSecret(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	access, _ := loginForTokens(t, srv)
	status, _ := postIntrospect(t, srv, access, "", introClient, "wrong-secret")
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong secret", status)
	}
}

func TestIntrospect_AcceptsBasicAuth(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	access, _ := loginForTokens(t, srv)

	body, _ := json.Marshal(map[string]any{"token": access})
	r, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/introspect", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetBasicAuth(introClient, introSecret)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if active, _ := out["active"].(bool); !active {
		t.Errorf("active = false via Basic auth")
	}
}

func TestIntrospect_EmptyTokenRejected(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	status, _ := postIntrospect(t, srv, "", "", introClient, introSecret)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 invalid_request", status)
	}
}

// ---------- revocation ----------

func postRevoke(t *testing.T, srv *httptest.Server, token, hint, id, secret string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"token":           token,
		"token_type_hint": hint,
		"client_id":       id,
		"client_secret":   secret,
	})
	resp, err := http.Post(srv.URL+"/token/revoke", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestRevoke_AccessTokenSucceeds(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	access, _ := loginForTokens(t, srv)
	if status := postRevoke(t, srv, access, "access_token", introClient, introSecret); status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
}

func TestRevoke_RefreshTokenSucceedsAndKillsToken(t *testing.T) {
	srv, store := newIntrospectionServer(t)
	_, refresh := loginForTokens(t, srv)

	if status := postRevoke(t, srv, refresh, "refresh_token", introClient, introSecret); status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}

	// Consume must now fail — the token is gone.
	if _, err := store.Consume(context.Background(), refresh); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Consume after revoke err = %v want oauth.ErrRefreshTokenNotFound", err)
	}
}

func TestRevoke_UnknownTokenIsIdempotent(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	// Per §2.2: server MUST respond as if revoked even for unknown
	// tokens. No 404, no error.
	if status := postRevoke(t, srv, "ghost", "", introClient, introSecret); status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
}

func TestRevoke_RejectsMissingCreds(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	access, _ := loginForTokens(t, srv)
	if status := postRevoke(t, srv, access, "", "", ""); status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}

func TestRevoke_EmptyTokenRejected(t *testing.T) {
	srv, _ := newIntrospectionServer(t)
	if status := postRevoke(t, srv, "", "", introClient, introSecret); status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
}
