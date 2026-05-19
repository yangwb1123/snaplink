package sso_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	riClientID      = "ri-client"
	riSecret        = "ri-secret"
	riUserID        = "u-ri"
	riAllowedRes    = "https://api.example/v1"
	riAllowedRes2   = "https://billing.example/v1"
	riForbiddenRes  = "https://evil.example/x"
	riRefreshTokTTL = time.Hour
)

func newResourceHarness(t *testing.T, allowed []string) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: riUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: riClientID, Secret: riSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedResources:      allowed,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: riUserID, Provider: "password"}, nil
		},
	))
	store := defaultimpl.NewMemoryRefreshTokenStore()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, riRefreshTokTTL),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store
}

// jwtPayloadClaim extracts the named claim from a JWT's payload as
// raw JSON. Used to inspect the aud claim without a full validator.
func jwtPayloadField(t *testing.T, token, field string) any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %s", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims[field]
}

func TestResourceIndicators_LoginStampsAudClaim(t *testing.T) {
	srv, _ := newResourceHarness(t, []string{riAllowedRes, riAllowedRes2})
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  riClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"resource":   []string{riAllowedRes},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatal("no access_token")
	}
	aud := jwtPayloadField(t, access, "aud")
	// Single-resource: emit as a JSON string per OIDC convention.
	if got, want := aud, riAllowedRes; got != want {
		t.Errorf("aud = %v want %q", got, want)
	}
}

func TestResourceIndicators_LoginRejectsUnregisteredResource(t *testing.T) {
	srv, _ := newResourceHarness(t, []string{riAllowedRes})
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  riClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"resource":   []string{riForbiddenRes},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["error"] != "invalid_target" {
		t.Errorf("error = %v want invalid_target", out["error"])
	}
}

func TestResourceIndicators_EmptyClientAllowlistAcceptsAny(t *testing.T) {
	// Legacy compat: when the client doesn't declare AllowedResources,
	// any resource is accepted (the field is opt-in).
	srv, _ := newResourceHarness(t, nil)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  riClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"resource":   []string{"https://anything.example/x"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d want 200 (legacy compat)", resp.StatusCode)
	}
}

func TestResourceIndicators_ClientCredentialsStampsAud(t *testing.T) {
	srv, _ := newResourceHarness(t, []string{riAllowedRes, riAllowedRes2})
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {riClientID},
		"client_secret": {riSecret},
		"resource":      {riAllowedRes, riAllowedRes2},
	}
	resp, err := http.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ := out["access_token"].(string)
	aud := jwtPayloadField(t, access, "aud")
	// Multi-resource: emit as JSON array.
	asArr, ok := aud.([]any)
	if !ok {
		t.Fatalf("aud not array: %v", aud)
	}
	if len(asArr) != 2 || asArr[0] != riAllowedRes || asArr[1] != riAllowedRes2 {
		t.Errorf("aud = %v want [%q %q]", asArr, riAllowedRes, riAllowedRes2)
	}
}

func TestResourceIndicators_TokenEndpointRejectsUnregistered(t *testing.T) {
	srv, _ := newResourceHarness(t, []string{riAllowedRes})
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {riClientID},
		"client_secret": {riSecret},
		"resource":      {riForbiddenRes},
	}
	resp, err := http.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	if out["error"] != "invalid_target" {
		t.Errorf("error = %v want invalid_target", out["error"])
	}
}

func TestResourceIndicators_RefreshPropagatesResources(t *testing.T) {
	srv, _ := newResourceHarness(t, []string{riAllowedRes})

	// Login with resource → mint refresh_token tagged with that resource.
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  riClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"resource":   []string{riAllowedRes},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var login map[string]any
	_ = json.Unmarshal(raw, &login)
	refresh, _ := login["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token: %s", raw)
	}

	// Rotate WITHOUT supplying the resource param — the captured one
	// from the original auth should flow through into the new access
	// token's aud claim.
	rotBody := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {riClientID},
		"client_secret": {riSecret},
		"refresh_token": {refresh},
	}
	rresp, err := http.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(rotBody.Encode()))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer rresp.Body.Close()
	rraw, _ := io.ReadAll(rresp.Body)
	var rot map[string]any
	_ = json.Unmarshal(rraw, &rot)
	access2, _ := rot["access_token"].(string)
	if access2 == "" {
		t.Fatalf("no rotated access_token: %s", rraw)
	}
	if got := jwtPayloadField(t, access2, "aud"); got != riAllowedRes {
		t.Errorf("rotated aud = %v want %q (resource not propagated)", got, riAllowedRes)
	}
}

func TestResourceIndicators_AreResourcesAllowedHelper(t *testing.T) {
	c := &sso.Client{AllowedResources: []string{"a", "b", "c"}}
	if !c.AreResourcesAllowed(nil) {
		t.Error("nil request should be allowed")
	}
	if !c.AreResourcesAllowed([]string{"a", "c"}) {
		t.Error("subset should be allowed")
	}
	if c.AreResourcesAllowed([]string{"a", "d"}) {
		t.Error("unregistered 'd' should be rejected")
	}
	// Empty allowlist = no enforcement.
	open := &sso.Client{}
	if !open.AreResourcesAllowed([]string{"anything"}) {
		t.Error("open client should allow any resource")
	}
}
