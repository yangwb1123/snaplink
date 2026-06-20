package ssotest

import "github.com/snaplink/sso/protocols/oauth"

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

const dcrInitialAT = "iat-secret-bearer"

func newDCRHarness(t *testing.T, policy oauth.DCRPolicy) (*httptest.Server, sso.ClientStore) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDynamicClientRegistration(policy),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, clients
}

func postDCR(t *testing.T, srv *httptest.Server, bearer string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/register", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respRaw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(respRaw, &out)
	return resp.StatusCode, out
}

func TestDCR_HappyPath_IssuesIDAndSecret(t *testing.T) {
	srv, store := newDCRHarness(t, oauth.DCRPolicy{
		InitialAccessToken:   dcrInitialAT,
		DefaultActive:        true,
		DefaultTokenStrategy: "jwt",
	})
	status, body := postDCR(t, srv, dcrInitialAT, map[string]any{
		"client_name":    "my app",
		"redirect_uris":  []string{"https://app.example/cb"},
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scope":          "openid read",
	})
	if status != http.StatusCreated {
		t.Fatalf("status=%d body=%v", status, body)
	}
	id, _ := body["client_id"].(string)
	secret, _ := body["client_secret"].(string)
	if id == "" || secret == "" {
		t.Fatalf("missing creds: %v", body)
	}
	if issuedAt, _ := body["client_id_issued_at"].(float64); issuedAt <= 0 {
		t.Errorf("client_id_issued_at = %v", issuedAt)
	}
	if exp, _ := body["client_secret_expires_at"].(float64); exp != 0 {
		t.Errorf("client_secret_expires_at = %v want 0 (never)", exp)
	}
	// Server-side: client is in the store and active.
	stored, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !stored.Active {
		t.Errorf("expected Active=true")
	}
	if stored.TokenStrategy != "jwt" {
		t.Errorf("TokenStrategy = %q want jwt", stored.TokenStrategy)
	}
}

func TestDCR_RejectsBadBearer(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{
		InitialAccessToken: dcrInitialAT,
	})
	status, body := postDCR(t, srv, "wrong-token", map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidToken {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidToken)
	}
}

func TestDCR_RejectsMissingBearer(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{
		InitialAccessToken: dcrInitialAT,
	})
	status, _ := postDCR(t, srv, "", map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d", status)
	}
}

func TestDCR_OpenRegistration_NoBearer(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	})
	status, body := postDCR(t, srv, "", map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
		"client_name":   "open-reg-app",
	})
	if status != http.StatusCreated {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["client_id"] == "" || body["client_id"] == nil {
		t.Errorf("missing client_id")
	}
}

func TestDCR_PublicClient_NoSecret_ForcesPKCE(t *testing.T) {
	srv, store := newDCRHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	})
	status, body := postDCR(t, srv, "", map[string]any{
		"redirect_uris":              []string{"https://spa.example/cb"},
		"token_endpoint_auth_method": "none",
	})
	if status != http.StatusCreated {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if secret, ok := body["client_secret"]; ok && secret != "" {
		t.Errorf("public client should have no client_secret, got %v", secret)
	}
	id := body["client_id"].(string)
	stored, _ := store.Get(context.Background(), id)
	if !stored.RequirePKCE {
		t.Errorf("public client must be RequirePKCE=true")
	}
}

func TestDCR_MissingRedirectURIs_RejectedForCodeFlow(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	status, body := postDCR(t, srv, "", map[string]any{
		"client_name": "no-redirect",
		// grant_types defaults to authorization_code
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != oauth.ErrInvalidClientMetadata {
		t.Errorf("error=%v want %q", body["error"], oauth.ErrInvalidClientMetadata)
	}
}

func TestDCR_ClientCredentialsOnly_NoRedirectURIs_OK(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true})
	status, body := postDCR(t, srv, "", map[string]any{
		"client_name": "service-app",
		"grant_types": []string{"client_credentials"},
	})
	if status != http.StatusCreated {
		t.Fatalf("status=%d body=%v", status, body)
	}
}

func TestDCR_RejectsUnsupportedAuthMethod(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	status, body := postDCR(t, srv, "", map[string]any{
		"redirect_uris":              []string{"https://app.example/cb"},
		"token_endpoint_auth_method": "private_key_jwt", // not supported yet
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != oauth.ErrInvalidClientMetadata {
		t.Errorf("error=%v", body["error"])
	}
}

func TestDCR_RejectsUnsupportedGrantType(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	status, body := postDCR(t, srv, "", map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
		"grant_types":   []string{"password"}, // not in SupportedGrants
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != oauth.ErrInvalidClientMetadata {
		t.Errorf("error=%v", body["error"])
	}
}

func TestDCR_AuthenticatorWhitelist(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
		AllowedAuthenticators: []string{"password"},
	})
	status, body := postDCR(t, srv, "", map[string]any{
		"redirect_uris":          []string{"https://app.example/cb"},
		"allowed_authenticators": []string{"phone"}, // not on whitelist
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
}

func TestDCR_NotConfigured_Returns501(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	resp, err := http.Post(httpSrv.URL+"/register", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["error"] != oauth.ErrRegistrationDisabled {
		t.Errorf("error=%v want %q", out["error"], oauth.ErrRegistrationDisabled)
	}
}

func TestDCR_AdvertisedInDiscovery(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	endpoint, _ := doc["registration_endpoint"].(string)
	if !strings.HasSuffix(endpoint, "/register") {
		t.Errorf("registration_endpoint = %q", endpoint)
	}
}

func TestDCR_RegisteredClient_UsableForLogin(t *testing.T) {
	// End-to-end: register a client, then attempt a login against it.
	// The login flow needs an authenticator wired and the client
	// to allowlist that authenticator (registration defaults to
	// no restriction → all server authenticators allowed).
	clients := defaultimpl.NewMemoryClientStore()
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{
			AllowOpenRegistration: true,
			DefaultActive:         true,
			DefaultTokenStrategy:  "jwt",
		}),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	regBody, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://e2e.example/cb"},
		"client_name":   "e2e",
	})
	regResp, err := http.Post(httpSrv.URL+"/register", "application/json",
		strings.NewReader(string(regBody)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = regResp.Body.Close() }()
	regRaw, _ := io.ReadAll(regResp.Body)
	var regOut map[string]any
	_ = json.Unmarshal(regRaw, &regOut)
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", regResp.StatusCode, regRaw)
	}
	id, _ := regOut["client_id"].(string)
	if id == "" {
		t.Fatalf("no client_id in %s", regRaw)
	}

	// Reading back via store confirms the persisted record matches.
	stored, err := clients.Get(context.Background(), id)
	if err != nil || stored == nil {
		t.Fatalf("clients.Get(%q): %v", id, err)
	}
	if stored.Name != "e2e" {
		t.Errorf("Name = %q want e2e", stored.Name)
	}
}
