package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	terUserID   = "u-ter"
	terClientID = "ter-client"
	terSecret   = "ter-secret"
	terPassword = "pw"
)

func newTokenExchangeRefreshHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: terUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: terClientID, Secret: terSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != terPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: terUserID, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func loginForExchange(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  terClientID,
		"credential": map[string]string{"username": terUserID, "password": terPassword},
		"scope":      []string{"read", "write"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %s", rb)
	}
	return access
}

func TestTokenExchange_ReturnsRefreshTokenWhenRequested(t *testing.T) {
	srv := newTokenExchangeRefreshHarness(t)
	subject := loginForExchange(t, srv)

	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {terClientID},
		"client_secret":        {terSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["access_token"] == nil {
		t.Errorf("access_token missing: %v", out)
	}
	if out["refresh_token"] == nil {
		t.Errorf("refresh_token MUST be returned when requested_token_type=refresh_token: %v", out)
	}
	if out["issued_token_type"] != "urn:ietf:params:oauth:token-type:refresh_token" {
		t.Errorf("issued_token_type = %v want refresh_token URN", out["issued_token_type"])
	}
}

func TestTokenExchange_RejectsRefreshWithoutStore(t *testing.T) {
	// No refresh store wired → request for refresh_token MUST be
	// rejected upfront (not silently degraded to access-only).
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: terUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: terClientID, Secret: terSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: terUserID, Provider: "password"}, nil
		},
	))
	server := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		// no WithRefreshTokenStore
	)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)

	subject := loginForExchange(t, srv)
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {terClientID},
		"client_secret":        {terSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		rb, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, rb)
	}
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["error"] != sso.ErrRefreshTokenNotConfigured {
		t.Errorf("error=%v want %q", out["error"], sso.ErrRefreshTokenNotConfigured)
	}
}

func TestTokenExchange_RotatedRefreshHonored(t *testing.T) {
	// The refresh token returned by token-exchange should be
	// rotatable via the standard refresh_token grant.
	srv := newTokenExchangeRefreshHarness(t)
	subject := loginForExchange(t, srv)

	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {terClientID},
		"client_secret":        {terSecret},
		"subject_token":        {subject},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	rt, _ := out["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh_token from exchange: %s", rb)
	}

	// Rotate it.
	rotForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {terClientID},
		"client_secret": {terSecret},
	}
	rotResp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(rotForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rotResp.Body.Close() }()
	rotRB, _ := io.ReadAll(rotResp.Body)
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotResp.StatusCode, rotRB)
	}
}
