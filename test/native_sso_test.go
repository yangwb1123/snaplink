package ssotest

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
	nssoAppA = "nsso-app-a"
	nssoAppB = "nsso-app-b"
	nssoUser = "u-nsso"
)

func newNativeSSOHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: nssoUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: nssoAppA, Secret: "sa", Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	clients.AddSeed(&sso.Client{
		ID: nssoAppB, Secret: "sb", Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: nssoUser, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceSecretStore(defaultimpl.NewMemoryDeviceSecretStore(), time.Minute),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// nssoLogin logs in app-a with the device_sso scope and returns the id_token +
// device_secret from the response.
func nssoLogin(t *testing.T, srv *httptest.Server) (idToken, deviceSecret string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  nssoAppA,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid", "device_sso"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	idToken, _ = out["id_token"].(string)
	deviceSecret, _ = out["device_secret"].(string)
	if idToken == "" || deviceSecret == "" {
		t.Fatalf("login missing id_token/device_secret: %s", raw)
	}
	return idToken, deviceSecret
}

func nssoExchange(t *testing.T, srv *httptest.Server, subjectIDToken, actorSecret string) (int, map[string]any) {
	t.Helper()
	return postExchange(t, srv, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {nssoAppB},
		"client_secret":      {"sb"},
		"subject_token":      {subjectIDToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
		"actor_token":        {actorSecret},
		"actor_token_type":   {"urn:openid:params:token-type:device-secret"},
		"scope":              {"openid device_sso"},
	})
}

// idTokenClaim decodes a claim from an id_token payload (test-only, unverified).
func idTokenClaim(t *testing.T, tok, claim string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		t.Fatalf("not a JWT: %q", tok)
	}
	seg, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(seg, &m)
	s, _ := m[claim].(string)
	return s
}

// TestNativeSSO_IssuesDeviceSecretAndDsHash: login with device_sso yields a
// device_secret + an id_token carrying ds_hash.
func TestNativeSSO_IssuesDeviceSecretAndDsHash(t *testing.T) {
	srv := newNativeSSOHarness(t)
	idToken, secret := nssoLogin(t, srv)
	if idTokenClaim(t, idToken, "ds_hash") == "" {
		t.Errorf("id_token missing ds_hash claim")
	}
	if secret == "" {
		t.Errorf("missing device_secret")
	}
}

// TestNativeSSO_ExchangeHappyPath: app-b exchanges app-a's id_token +
// device_secret for its own tokens + a fresh device_secret.
func TestNativeSSO_ExchangeHappyPath(t *testing.T) {
	srv := newNativeSSOHarness(t)
	idToken, secret := nssoLogin(t, srv)

	status, body := nssoExchange(t, srv, idToken, secret)
	if status != http.StatusOK {
		t.Fatalf("exchange status=%d body=%v", status, body)
	}
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Errorf("missing access_token: %v", body)
	}
	if body["id_token"] == nil || body["id_token"] == "" {
		t.Errorf("missing id_token: %v", body)
	}
	newSecret, _ := body["device_secret"].(string)
	if newSecret == "" {
		t.Errorf("exchange did not return a fresh device_secret")
	}
	if newSecret == secret {
		t.Errorf("device_secret was not rotated")
	}
}

// TestNativeSSO_SecretIsSingleUse: the device_secret is consumed on exchange;
// replay fails with invalid_grant.
func TestNativeSSO_SecretIsSingleUse(t *testing.T) {
	srv := newNativeSSOHarness(t)
	idToken, secret := nssoLogin(t, srv)
	if status, _ := nssoExchange(t, srv, idToken, secret); status != http.StatusOK {
		t.Fatalf("first exchange status=%d", status)
	}
	status, body := nssoExchange(t, srv, idToken, secret)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("replay status=%d err=%v, want 400 invalid_grant", status, body["error"])
	}
}

// TestNativeSSO_WrongSecretRejected: a device_secret that doesn't match the
// id_token's ds_hash is rejected (oracle-safe invalid_grant).
func TestNativeSSO_WrongSecretRejected(t *testing.T) {
	srv := newNativeSSOHarness(t)
	idToken, _ := nssoLogin(t, srv)
	status, body := nssoExchange(t, srv, idToken, "not-the-real-secret")
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("wrong secret status=%d err=%v, want 400 invalid_grant", status, body["error"])
	}
}

// TestNativeSSO_CrossTokenSecretRejected: a valid secret from one login can't
// be paired with a different login's id_token (ds_hash binds them).
func TestNativeSSO_CrossTokenSecretRejected(t *testing.T) {
	srv := newNativeSSOHarness(t)
	idTokenA, _ := nssoLogin(t, srv)
	_, secretB := nssoLogin(t, srv)
	// id_token from session A + device_secret from session B → ds_hash mismatch.
	status, body := nssoExchange(t, srv, idTokenA, secretB)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("cross-token status=%d err=%v, want 400 invalid_grant", status, body["error"])
	}
}

// TestNativeSSO_NotConfigured: with a VALID id_token but NO device-secret store
// wired, the device-secret exchange returns 501 device_secret_not_configured
// (the subject_token validates first, then the store-nil gate fires).
func TestNativeSSO_NotConfigured(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: nssoUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: nssoAppA, Secret: "sa", Active: true, AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt"})
	clients.AddSeed(&sso.Client{ID: nssoAppB, Secret: "sb", Active: true, AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt"})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: nssoUser, Provider: "password"}, nil
		}))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	// NOTE: no WithDeviceSecretStore.
	srv := sso.NewServer(
		sso.WithUserProvider(users), sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients), sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer), sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	// Log in to get a real (validly-signed) id_token — no device_secret minted.
	body, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": nssoAppA,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid"},
	})
	resp, _ := http.Post(hs.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("login missing id_token: %s", raw)
	}

	status, ebody := postExchange(t, hs, url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {nssoAppB},
		"client_secret":      {"sb"},
		"subject_token":      {idToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
		"actor_token":        {"some-secret"},
		"actor_token_type":   {"urn:openid:params:token-type:device-secret"},
	})
	if status != http.StatusNotImplemented || ebody["error"] != "device_secret_not_configured" {
		t.Errorf("status=%d err=%v, want 501 device_secret_not_configured", status, ebody["error"])
	}
}
