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

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// TestRcov2DE_DeviceStartErrors covers handleDeviceCode rejection branches.
func TestRcov2DE_DeviceStartErrors(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

	// Unknown device_code => 400 invalid_grant (oracle-safe collapse).
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   "totally-unknown-device-code",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("device grant unknown code = %d, want 400 (body=%v)", status, out)
	}
	if out["error"] != sso.ErrInvalidGrant {
		t.Errorf("device grant unknown code = %v, want invalid_grant", out)
	}
}

// TestRcov2DE_ForgeClientOwnerParity exercises the deployment contract used by
// Forge: a browser token and an RFC 8628 CLI token from separate public clients
// must resolve to the same verified Hub owner tuple.
func TestRcov2DE_ForgeClientOwnerParity(t *testing.T) {
	t.Parallel()
	const tenantID = "acme"
	const forgeResource = "forge-api"
	forgeScopes := []string{"forge:conversations:read", "forge:conversations:write"}
	consoleScopes := []string{"openid", "profile", "forge:conversations:read", "forge:conversations:write"}
	s := rcovNewServer(t, sso.WithDeviceCodeStore(
		defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, time.Nanosecond, rcov2DeviceVerifyURI))
	for _, clientID := range []string{"forge-console", "forge-cli"} {
		grantTypes := []string{"authorization_code", "refresh_token"}
		allowedScopes := consoleScopes
		if clientID == "forge-cli" {
			grantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}
			allowedScopes = forgeScopes
		}
		s.clients.AddSeed(&sso.Client{
			ID: clientID, Name: clientID, TenantID: tenantID, SubjectType: "public",
			AllowedScopes: allowedScopes, AllowedResources: []string{forgeResource},
			AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
			TokenEndpointAuthMethod: "none", RequirePKCE: true, SkipConsent: true,
			GrantTypes: grantTypes,
		})
	}

	status, consoleLogin := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": "forge-console",
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      consoleScopes,
		"resource":   []string{forgeResource},
	})
	if status != http.StatusOK {
		t.Fatalf("Forge Console login = %d body=%v", status, consoleLogin)
	}
	consoleToken, _ := consoleLogin["access_token"].(string)
	if consoleToken == "" {
		t.Fatalf("Forge Console login returned no access token: %v", consoleLogin)
	}

	status, deviceStart := rcovPostJSON(t, s.http.URL+"/device/code", "", map[string]any{
		"client_id": "forge-cli", "scope": "forge:conversations:read forge:conversations:write",
		"resource": []string{forgeResource},
	})
	if status != http.StatusOK {
		t.Fatalf("Forge CLI device start = %d body=%v", status, deviceStart)
	}
	deviceCode, _ := deviceStart["device_code"].(string)
	userCode, _ := deviceStart["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("Forge CLI device start omitted codes: %v", deviceStart)
	}
	status, _ = rcovPostJSON(t, s.http.URL+"/device/verify", consoleToken, map[string]any{
		"user_code": userCode, "approve": true,
	})
	if status != http.StatusOK {
		t.Fatalf("Forge Console approval = %d", status)
	}
	status, cliPoll := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode, "client_id": "forge-cli",
	})
	if status != http.StatusOK {
		t.Fatalf("Forge CLI device poll = %d body=%v", status, cliPoll)
	}
	cliToken, _ := cliPoll["access_token"].(string)
	if cliToken == "" {
		t.Fatalf("Forge CLI poll returned no access token: %v", cliPoll)
	}

	consoleClaims := trrDecodePayload(t, consoleToken)
	cliClaims := trrDecodePayload(t, cliToken)
	for _, claim := range []string{"iss", "sub", "tenant_id"} {
		if consoleClaims[claim] == nil || consoleClaims[claim] != cliClaims[claim] {
			t.Errorf("owner claim %s differs: Console=%v CLI=%v", claim, consoleClaims[claim], cliClaims[claim])
		}
	}
	if consoleClaims["tenant_id"] != tenantID {
		t.Errorf("tenant_id = %v, want %s", consoleClaims["tenant_id"], tenantID)
	}
	if consoleClaims["client_id"] != "forge-console" || cliClaims["client_id"] != "forge-cli" {
		t.Errorf("client IDs = Console:%v CLI:%v, want forge-console and forge-cli", consoleClaims["client_id"], cliClaims["client_id"])
	}
	for clientID, claims := range map[string]map[string]any{
		"forge-console": consoleClaims,
		"forge-cli":     cliClaims,
	} {
		audienceOK := claims["aud"] == forgeResource
		if audiences, ok := claims["aud"].([]any); ok && len(audiences) == 1 {
			audienceOK = audiences[0] == forgeResource
		}
		if !audienceOK {
			t.Errorf("%s audience = %v, want %s", clientID, claims["aud"], forgeResource)
		}
	}
	for _, grantType := range []string{"authorization_code", "refresh_token"} {
		status, disallowed := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
			"grant_type": grantType, "client_id": "forge-cli", "code": "unused",
		})
		if status != http.StatusBadRequest || disallowed["error"] != "unauthorized_client" {
			t.Errorf("Forge CLI disallowed %s grant = %d %v", grantType, status, disallowed)
		}
	}
}

// TestRcov2DE_CIBATokenGrantErrors covers handleCIBATokenGrant rejection
// branches: missing auth_req_id, unknown auth_req_id, and slow_down throttling.
func TestRcov2DE_CIBATokenGrantErrors(t *testing.T) {
	t.Parallel()
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
