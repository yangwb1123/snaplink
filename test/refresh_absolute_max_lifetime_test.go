package ssotest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	ramlUser   = "u-raml"
	ramlClient = "raml-client"
	ramlSecret = "raml-secret"
)

// newRefreshAbsoluteMaxLifetimeHarness builds a server with the refresh
// store wired and (when maxLifetime > 0) the absolute-max-lifetime cap
// enabled — mirroring newRefreshFamilyHarness but parameterized so both the
// enabled and disabled (byte-identical) cases share one harness.
func newRefreshAbsoluteMaxLifetimeHarness(t *testing.T, maxLifetime time.Duration) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: ramlUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: ramlClient, Secret: ramlSecret, Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: ramlUser, Provider: "password"}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	}
	if maxLifetime > 0 {
		opts = append(opts, sso.WithRefreshAbsoluteMaxLifetime(maxLifetime))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func ramlLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body := `{"provider":"password","client_id":"` + ramlClient +
		`","credential":{"username":"x","password":"y"}}`
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := jsonDecodeRespBody(resp)
	r, _ := out["refresh_token"].(string)
	if r == "" {
		t.Fatalf("no refresh_token: %v", out)
	}
	return r
}

func ramlRotate(t *testing.T, srv *httptest.Server, refresh string) (status int, body map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {ramlClient},
		"client_secret": {ramlSecret},
		"refresh_token": {refresh},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, jsonDecodeRespBody(resp)
}

// TestRefreshAbsoluteMaxLifetime_Disabled_ByteIdenticalRotation proves the
// default-off contract: with no cap wired, a family may rotate however long
// after original issuance without ever hitting the new check.
func TestRefreshAbsoluteMaxLifetime_Disabled_ByteIdenticalRotation(t *testing.T) {
	srv := newRefreshAbsoluteMaxLifetimeHarness(t, 0)
	refresh := ramlLogin(t, srv)
	time.Sleep(20 * time.Millisecond)
	status, body := ramlRotate(t, srv, refresh)
	if status != http.StatusOK {
		t.Fatalf("rotate status=%d body=%v (want 200 — cap disabled)", status, body)
	}
}

// TestRefreshAbsoluteMaxLifetime_ExceededDeniesRotation proves the hard
// ceiling fires (fail-closed invalid_grant) once the family has outlived
// AbsoluteMaxLifetime, independent of the per-token TTL (which is 1h here —
// far from expiring — so ONLY the absolute-max-lifetime cap can explain the
// denial).
func TestRefreshAbsoluteMaxLifetime_ExceededDeniesRotation(t *testing.T) {
	srv := newRefreshAbsoluteMaxLifetimeHarness(t, 5*time.Millisecond)
	refresh := ramlLogin(t, srv)
	time.Sleep(25 * time.Millisecond)

	status, body := ramlRotate(t, srv, refresh)
	if status != http.StatusBadRequest {
		t.Fatalf("rotate status=%d body=%v (want 400 invalid_grant)", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}
}

// TestRefreshAbsoluteMaxLifetime_WithinWindowRotates proves the cap does NOT
// fire prematurely — a rotation well within the configured window succeeds.
func TestRefreshAbsoluteMaxLifetime_WithinWindowRotates(t *testing.T) {
	srv := newRefreshAbsoluteMaxLifetimeHarness(t, time.Hour)
	refresh := ramlLogin(t, srv)
	status, body := ramlRotate(t, srv, refresh)
	if status != http.StatusOK {
		t.Fatalf("rotate status=%d body=%v (want 200 — well within the 1h cap)", status, body)
	}
}
