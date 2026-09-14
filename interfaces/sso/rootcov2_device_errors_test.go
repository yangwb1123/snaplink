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
	"reflect"
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
// must resolve to the same verified Hub owner tuple. The CLI refresh grant is
// explicitly allowed and must preserve the original token binding through
// rotation, while its authorization-code grant remains denied.
func TestRcov2DE_ForgeClientOwnerParity(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithDeviceCodeStore(
		defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, time.Nanosecond, rcov2DeviceVerifyURI))
	rcovSeedForgeClients(s)
	consoleToken := rcovForgeConsoleLogin(t, s)
	cliToken, cliRefresh := rcovForgeCLIDeviceLogin(t, s, consoleToken)
	rotatedToken, rotatedRefresh := rcovForgeCLIRefresh(t, s, cliRefresh)
	if rotatedRefresh == cliRefresh {
		t.Fatal("Forge CLI refresh grant did not rotate its refresh token")
	}
	rcovAssertForgeTokenBindings(t, consoleToken, cliToken, rotatedToken)
	rcovAssertForgeCLIAuthorizationCodeDenied(t, s)
}

func rcovSeedForgeClients(s *rcovServer) {
	forgeScopes := []string{"forge:conversations:read", "forge:conversations:write"}
	consoleScopes := append([]string{"openid", "profile"}, forgeScopes...)
	for _, client := range []struct {
		id         string
		scopes     []string
		grantTypes []string
	}{
		{id: "forge-console", scopes: consoleScopes, grantTypes: []string{sso.GrantAuthorizationCode, sso.GrantRefreshToken}},
		{id: "forge-cli", scopes: forgeScopes, grantTypes: []string{sso.GrantDeviceCode, sso.GrantRefreshToken}},
	} {
		s.clients.AddSeed(&sso.Client{
			ID: client.id, Name: client.id, TenantID: "acme", SubjectType: "public",
			AllowedScopes: client.scopes, AllowedResources: []string{"forge-api"},
			AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
			TokenEndpointAuthMethod: "none", RequirePKCE: true, SkipConsent: true,
			GrantTypes: client.grantTypes,
		})
	}
}

func rcovForgeConsoleLogin(t *testing.T, s *rcovServer) string {
	t.Helper()
	status, login := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": "forge-console",
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile", "forge:conversations:read", "forge:conversations:write"},
		"resource":   []string{"forge-api"},
	})
	if status != http.StatusOK {
		t.Fatalf("Forge Console login = %d body=%v", status, login)
	}
	token, _ := login["access_token"].(string)
	if token == "" {
		t.Fatalf("Forge Console login returned no access token: %v", login)
	}
	return token
}

func rcovForgeCLIDeviceLogin(t *testing.T, s *rcovServer, consoleToken string) (string, string) {
	t.Helper()
	status, start := rcovPostJSON(t, s.http.URL+"/device/code", "", map[string]any{
		"client_id": "forge-cli", "scope": "forge:conversations:read forge:conversations:write",
		"resource": []string{"forge-api"},
	})
	if status != http.StatusOK {
		t.Fatalf("Forge CLI device start = %d body=%v", status, start)
	}
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("Forge CLI device start omitted codes: %v", start)
	}
	status, _ = rcovPostJSON(t, s.http.URL+"/device/verify", consoleToken, map[string]any{
		"user_code": userCode, "approve": true,
	})
	if status != http.StatusOK {
		t.Fatalf("Forge Console approval = %d", status)
	}
	status, poll := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type": sso.GrantDeviceCode, "device_code": deviceCode, "client_id": "forge-cli",
	})
	if status != http.StatusOK {
		t.Fatalf("Forge CLI device poll = %d body=%v", status, poll)
	}
	accessToken, _ := poll["access_token"].(string)
	refreshToken, _ := poll["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("Forge CLI device poll omitted a token: %v", poll)
	}
	return accessToken, refreshToken
}

func rcovForgeCLIRefresh(t *testing.T, s *rcovServer, refreshToken string) (string, string) {
	t.Helper()
	status, rotated := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type": sso.GrantRefreshToken, "refresh_token": refreshToken, "client_id": "forge-cli",
	})
	if status != http.StatusOK {
		t.Fatalf("Forge CLI refresh = %d body=%v", status, rotated)
	}
	accessToken, _ := rotated["access_token"].(string)
	refreshToken, _ = rotated["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("Forge CLI refresh omitted rotated tokens: %v", rotated)
	}
	return accessToken, refreshToken
}

func rcovAssertForgeTokenBindings(t *testing.T, consoleToken, cliToken, rotatedToken string) {
	t.Helper()
	consoleClaims := trrDecodePayload(t, consoleToken)
	cliClaims := trrDecodePayload(t, cliToken)
	rotatedClaims := trrDecodePayload(t, rotatedToken)
	for _, claim := range []string{"iss", "sub", "tenant_id"} {
		if consoleClaims[claim] == nil || consoleClaims[claim] != cliClaims[claim] || cliClaims[claim] != rotatedClaims[claim] {
			t.Errorf("owner claim %s differs: Console=%v CLI=%v rotated CLI=%v", claim, consoleClaims[claim], cliClaims[claim], rotatedClaims[claim])
		}
	}
	if consoleClaims["tenant_id"] != "acme" {
		t.Errorf("tenant_id = %v, want acme", consoleClaims["tenant_id"])
	}
	for _, tokenClaims := range []map[string]any{consoleClaims, cliClaims, rotatedClaims} {
		if !rcovIsForgeAudience(tokenClaims["aud"]) {
			t.Errorf("audience = %v, want forge-api", tokenClaims["aud"])
		}
	}
	if consoleClaims["client_id"] != "forge-console" || cliClaims["client_id"] != "forge-cli" || rotatedClaims["client_id"] != "forge-cli" {
		t.Errorf("client IDs = Console:%v CLI:%v rotated CLI:%v", consoleClaims["client_id"], cliClaims["client_id"], rotatedClaims["client_id"])
	}
	if cliClaims["scope"] != "forge:conversations:read forge:conversations:write" {
		t.Errorf("CLI scope = %v, want the two Forge conversation scopes", cliClaims["scope"])
	}
	for _, claim := range []string{"iss", "sub", "tenant_id", "client_id", "aud", "scope"} {
		if !reflect.DeepEqual(cliClaims[claim], rotatedClaims[claim]) {
			t.Errorf("refresh changed CLI %s: before=%v after=%v", claim, cliClaims[claim], rotatedClaims[claim])
		}
	}
}

func rcovIsForgeAudience(audience any) bool {
	switch value := audience.(type) {
	case string:
		return value == "forge-api"
	case []any:
		return len(value) == 1 && value[0] == "forge-api"
	default:
		return false
	}
}

func rcovAssertForgeCLIAuthorizationCodeDenied(t *testing.T, s *rcovServer) {
	t.Helper()
	status, denied := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type": sso.GrantAuthorizationCode, "client_id": "forge-cli", "code": "unused",
	})
	if status != http.StatusBadRequest || denied["error"] != "unauthorized_client" {
		t.Errorf("Forge CLI authorization_code grant = %d %v, want 400 unauthorized_client", status, denied)
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
