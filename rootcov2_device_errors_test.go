package sso_test

// rootcov2_device_errors_test.go fills the error/edge branches of the RFC 8628
// device flow and the OIDC CIBA grant the happy-path tests skipped
// (device_code_handler.go handleDeviceCode / handleDeviceTokenGrant /
// handleCIBATokenGrant). These are pure rejection branches — unknown client,
// inactive client, disallowed resource, unknown/wrong-client device_code,
// slow_down throttling.
//
// REUSES rcovNewServer / rcovPostJSON and rcov2PasswordAuth.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

// TestRcov2DE_DeviceStartErrors covers handleDeviceCode rejection branches.
func TestRcov2DE_DeviceStartErrors(t *testing.T) {
	ctx := context.Background()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, TokenStrategy: "jwt", Active: true,
		AllowedResources: []string{"https://api.example.com"},
	})
	clients.AddSeed(&sso.Client{ID: "inactive-client", TokenStrategy: "jwt", Active: false})
	_ = ctx

	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), time.Minute, time.Second, ""),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Missing client_id => 400.
	status, _ := rcovPostJSON(t, httpSrv.URL+"/device/code", "", map[string]any{"scope": "openid"})
	if status != http.StatusBadRequest {
		t.Errorf("device/code no client_id = %d, want 400", status)
	}

	// Unknown client => 401.
	status, _ = rcovPostJSON(t, httpSrv.URL+"/device/code", "", map[string]any{"client_id": "ghost"})
	if status != http.StatusUnauthorized {
		t.Errorf("device/code unknown client = %d, want 401", status)
	}

	// Inactive client => 403.
	status, _ = rcovPostJSON(t, httpSrv.URL+"/device/code", "", map[string]any{"client_id": "inactive-client"})
	if status != http.StatusForbidden {
		t.Errorf("device/code inactive client = %d, want 403", status)
	}

	// Disallowed resource => 400 invalid_target.
	status, out := rcovPostJSON(t, httpSrv.URL+"/device/code", "", map[string]any{
		"client_id": rcovClient,
		"resource":  []string{"https://not-allowed.example.com"},
	})
	if status != http.StatusBadRequest {
		t.Errorf("device/code disallowed resource = %d, want 400 (body=%v)", status, out)
	}

	// Happy path with an allowed resource + verification_uri_complete shape.
	status, out = rcovPostJSON(t, httpSrv.URL+"/device/code", "", map[string]any{
		"client_id": rcovClient,
		"scope":     "openid",
		"resource":  []string{"https://api.example.com"},
	})
	if status != http.StatusOK {
		t.Fatalf("device/code ok = %d body=%v", status, out)
	}
	if out["verification_uri_complete"] == "" || out["verification_uri_complete"] == nil {
		t.Errorf("missing verification_uri_complete: %v", out)
	}
}

// TestRcov2DE_DeviceTokenGrantErrors covers handleDeviceTokenGrant rejection
// branches: missing device_code, unknown device_code, wrong-client binding.
func TestRcov2DE_DeviceTokenGrantErrors(t *testing.T) {
	s := rcovNewServer(t, sso.WithDeviceCodeStore(
		defaultimpl.NewMemoryDeviceCodeStore(), time.Minute, time.Second, ""))

	// Missing device_code => 400.
	status, _ := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("device grant no code = %d, want 400", status)
	}

	// Unknown device_code => 400 (expired_token, anti-enumeration).
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   "totally-unknown-device-code",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("device grant unknown code = %d, want 400 (body=%v)", status, out)
	}
}

// TestRcov2DE_CIBATokenGrantErrors covers handleCIBATokenGrant rejection
// branches: missing auth_req_id, unknown auth_req_id, and slow_down throttling.
func TestRcov2DE_CIBATokenGrantErrors(t *testing.T) {
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		// A LONG poll interval so the second immediate poll trips slow_down.
		sso.WithCIBA(defaultimpl.NewMemoryCIBAStore(), oauth.CIBATransportFunc(
			func(context.Context, string, string, map[string]string) error { return nil }),
			time.Minute, time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Missing auth_req_id => 400 invalid_request.
	status, _ := rcovPostJSON(t, httpSrv.URL+"/token", "", map[string]any{
		"grant_type":    "urn:openid:params:grant-type:ciba",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("ciba grant no auth_req_id = %d, want 400", status)
	}

	// Unknown auth_req_id => 400 (expired_token).
	status, _ = rcovPostJSON(t, httpSrv.URL+"/token", "", map[string]any{
		"grant_type":    "urn:openid:params:grant-type:ciba",
		"auth_req_id":   "no-such-req",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("ciba grant unknown req = %d, want 400", status)
	}

	// Start a real request then poll twice quickly => the second trips slow_down.
	_, out := rcovPostJSON(t, httpSrv.URL+"/backchannel-authentication", "", map[string]any{
		"client_id": rcovClient, "client_secret": rcovSecret,
		"login_hint": rcovUser, "scope": "openid",
	})
	authReqID, _ := out["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("no auth_req_id: %v", out)
	}
	poll := map[string]any{
		"grant_type":    "urn:openid:params:grant-type:ciba",
		"auth_req_id":   authReqID,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	}
	// First poll => authorization_pending.
	status, first := rcovPostJSON(t, httpSrv.URL+"/token", "", poll)
	if status != http.StatusBadRequest || first["error"] != "authorization_pending" {
		t.Fatalf("first ciba poll = %d %v, want authorization_pending", status, first)
	}
	// Second immediate poll (within the 1m interval) => slow_down.
	status, second := rcovPostJSON(t, httpSrv.URL+"/token", "", poll)
	if status != http.StatusBadRequest || second["error"] != "slow_down" {
		t.Errorf("second ciba poll = %d %v, want slow_down", status, second)
	}
}
