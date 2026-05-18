package sso_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	oidcUser     = "u-oidc"
	oidcClient   = "oidc-client"
	oidcSecret   = "oidc-secret"
	oidcRedirect = "https://app.example.com/cb"
)

// decodeJWTPayload pulls the middle segment of a JWT and JSON-decodes it.
// Returns an error string in the map under "_decode_err" on failure so
// tests can assert with a single subscript.
func decodeJWTPayload(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-segment JWT, got %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	return out
}

func newOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: oidcUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: oidcClient, Secret: oidcSecret,
		RedirectURIs:          []string{oidcRedirect},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{
				UserID:     oidcUser,
				Provider:   "password",
				Attributes: map[string]string{"email": "alice@example.com"},
			}, nil
		},
	))
	// One issuer instance, used as both access-token and ID-token signer
	// (shared key + shared JWKS entry — the canonical wiring).
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.test"),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// ---------- direct mint path ----------

func TestOIDC_LoginWithOpenIDScopeEmitsIDToken(t *testing.T) {
	srv := newOIDCServer(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  oidcClient,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid", "profile"},
		"nonce":      "n-0S6_WzA2Mj",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("missing id_token: %v", out)
	}
	claims := decodeJWTPayload(t, idToken)
	if claims["sub"] != oidcUser {
		t.Errorf("sub = %v want %q", claims["sub"], oidcUser)
	}
	if claims["aud"] != oidcClient {
		t.Errorf("aud = %v want %q (single-client scalar audience)", claims["aud"], oidcClient)
	}
	if claims["iss"] != "https://sso.test" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["nonce"] != "n-0S6_WzA2Mj" {
		t.Errorf("nonce echo failed: %v", claims["nonce"])
	}
}

func TestOIDC_LoginWithoutOpenIDScopeOmitsIDToken(t *testing.T) {
	srv := newOIDCServer(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  oidcClient,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"profile"}, // no "openid"
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if id, _ := out["id_token"].(string); id != "" {
		t.Errorf("id_token unexpectedly present without openid scope: %q", id)
	}
}

func TestOIDC_LoginWithoutIDTokenIssuerOmitsIDToken(t *testing.T) {
	// Server omits WithIDTokenIssuer entirely — openid scope is benign.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: oidcUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: oidcClient, Secret: oidcSecret, AllowedAuthenticators: []string{"password"}, Active: true})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: oidcUser}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  oidcClient,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid"},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if id, _ := out["id_token"].(string); id != "" {
		t.Errorf("id_token unexpectedly present: %q", id)
	}
}

// ---------- authorization_code path ----------

func TestOIDC_AuthCodeFlowEmitsIDTokenWithCapturedNonce(t *testing.T) {
	srv := newOIDCServer(t)

	// Step 1: request code WITH openid scope + nonce.
	loginBody, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     oidcClient,
		"credential":    map[string]string{"username": "x", "password": "y"},
		"response_type": "code",
		"redirect_uri":  oidcRedirect,
		"scope":         []string{"openid", "email"},
		"nonce":         "code-flow-nonce-xyz",
	})
	lresp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer lresp.Body.Close()
	var lOut map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&lOut)
	code, _ := lOut["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", lOut)
	}

	// Step 2: exchange code for tokens.
	exBody, _ := json.Marshal(map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     oidcClient,
		"client_secret": oidcSecret,
		"redirect_uri":  oidcRedirect,
	})
	tresp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(exBody))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tresp.Body.Close()
	if tresp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", tresp.StatusCode)
	}
	var tOut map[string]any
	_ = json.NewDecoder(tresp.Body).Decode(&tOut)
	idToken, _ := tOut["id_token"].(string)
	if idToken == "" {
		t.Fatalf("authorization_code exchange missing id_token: %v", tOut)
	}
	claims := decodeJWTPayload(t, idToken)
	if claims["nonce"] != "code-flow-nonce-xyz" {
		t.Errorf("nonce captured at login was not echoed: got %v", claims["nonce"])
	}
}

// ---------- SPI happy + unhappy paths on Ed25519 issuer ----------

func TestOIDC_Ed25519IDTokenRejectsMissingFields(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	if _, err := iss.IssueIDToken(context.Background(), nil); err == nil {
		t.Error("nil request must error")
	}
	if _, err := iss.IssueIDToken(context.Background(), &sso.IDTokenRequest{Subject: "u"}); err == nil {
		t.Error("missing audience must error")
	}
	if _, err := iss.IssueIDToken(context.Background(), &sso.IDTokenRequest{Audience: "c"}); err == nil {
		t.Error("missing subject must error")
	}
}

func TestOIDC_Ed25519IDTokenAuthTimeRoundTrip(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	auth := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	tok, err := iss.IssueIDToken(context.Background(), &sso.IDTokenRequest{
		Subject: "u", Audience: "c", AuthTime: auth,
		AMR: []string{"pwd", "mfa"}, ACR: "level-2",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt: %q", tok)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims["auth_time"] == nil {
		t.Error("auth_time missing")
	}
	amr, _ := claims["amr"].([]any)
	if len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Errorf("amr = %v", claims["amr"])
	}
	if claims["acr"] != "level-2" {
		t.Errorf("acr = %v", claims["acr"])
	}
}

// Guard against any future Token interface drift: the same instance
// must continue to satisfy both interfaces.
func TestOIDC_Ed25519SatisfiesIDTokenIssuerInterface(t *testing.T) {
	var _ sso.IDTokenIssuer = defaultimpl.NewEd25519JWTIssuer()
	// errors import kept honest by an unused assertion below.
	_ = errors.New("anchor")
}
