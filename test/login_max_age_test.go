package ssotest

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

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sso "github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	maxAgeUserID   = "u-maxage"
	maxAgeClientID = "maxage-client"
	maxAgeSecret   = "maxage-secret"
	maxAgePassword = "pw"
)

// newMaxAgeHarness builds a minimal server to exercise max_age enforcement
// in the interactive login flow.
func newMaxAgeHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: maxAgeUserID})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    maxAgeClientID,
		Secret:                maxAgeSecret,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != maxAgePassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: maxAgeUserID, Provider: "password"}, nil
		},
	))

	sessions := defaultimpl.NewMemorySessionManager()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// maxAgeLogin posts to /auth/login with the given max_age (nil = omit).
func maxAgeLogin(t *testing.T, srv *httptest.Server, maxAge *int64) (int, map[string]any) {
	t.Helper()
	body := map[string]any{
		"provider":   "password",
		"client_id":  maxAgeClientID,
		"credential": map[string]string{"username": maxAgeUserID, "password": maxAgePassword},
	}
	if maxAge != nil {
		body["max_age"] = *maxAge
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestMaxAge_NilParam — no max_age parameter → login succeeds (no constraint).
func TestMaxAge_NilParam(t *testing.T) {
	srv := newMaxAgeHarness(t)
	status, body := maxAgeLogin(t, srv, nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (nil max_age should always succeed)", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Errorf("expected access_token: %v", body)
	}
}

// TestMaxAge_ZeroWithFreshCredentials — max_age=0 requires fresh auth;
// the user just provided credentials, so AuthTime=now satisfies max_age=0.
func TestMaxAge_ZeroWithFreshCredentials(t *testing.T) {
	srv := newMaxAgeHarness(t)
	maxAge := int64(0)
	status, body := maxAgeLogin(t, srv, &maxAge)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (fresh credentials must satisfy max_age=0)", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Errorf("expected access_token: %v", body)
	}
}

// TestMaxAge_LargeWindowWithFreshCredentials — max_age=3600 with fresh
// credentials; the user just authenticated, so AuthTime=now is well within
// the 1-hour window.
func TestMaxAge_LargeWindowWithFreshCredentials(t *testing.T) {
	srv := newMaxAgeHarness(t)
	maxAge := int64(3600)
	status, body := maxAgeLogin(t, srv, &maxAge)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (fresh credentials must satisfy max_age=3600)", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Errorf("expected access_token: %v", body)
	}
}
