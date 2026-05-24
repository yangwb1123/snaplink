package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// OAuth 2.1 strict mode: response_type=token rejected; PKCE
// required regardless of per-client policy; http:// redirect_uri
// rejected (except localhost). When strict mode is off, every
// pre-strict-mode test must keep passing.

const (
	strictClient      = "strict-client"
	strictSecret      = "secret"
	strictRedirect    = "https://app.example.com/cb"
	strictUser        = "u-strict"
	strictPassword    = "pw"
	strictAuthnMethod = "password"
)

func newStrictServer(t *testing.T, strict bool, redirect string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: strictUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    strictClient,
		Secret:                strictSecret,
		Name:                  "Strict Test",
		RedirectURIs:          []string{redirect},
		AllowedAuthenticators: []string{strictAuthnMethod},
		TokenStrategy:         "jwt",
		Active:                true,
		// Deliberately RequirePKCE=false so we can prove strict
		// mode overrides the per-client opt-out.
		RequirePKCE: false,
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == strictUser && p == strictPassword {
				return &sso.AuthResult{UserID: strictUser}, nil
			}
			return nil, errors.New("bad")
		},
	))

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	}
	if strict {
		opts = append(opts, sso.WithOAuth21StrictMode(true))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func loginStrict(t *testing.T, srv *httptest.Server, overrides map[string]any) (int, map[string]any) {
	t.Helper()
	body := map[string]any{
		"provider":   strictAuthnMethod,
		"client_id":  strictClient,
		"credential": map[string]string{"username": strictUser, "password": strictPassword},
	}
	maps.Copy(body, overrides)
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	body2, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body2, &out)
	return resp.StatusCode, out
}

func TestOAuth21Strict_RejectsResponseTypeToken(t *testing.T) {
	srv := newStrictServer(t, true, strictRedirect)
	status, body := loginStrict(t, srv, map[string]any{
		"response_type":         "token",
		"redirect_uri":          strictRedirect,
		"code_challenge":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789012",
		"code_challenge_method": "plain",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "unsupported_response_type" {
		t.Errorf("error = %v want unsupported_response_type", body["error"])
	}
}

func TestOAuth21Strict_RejectsEmptyResponseType(t *testing.T) {
	// Empty response_type defaulted to direct-mint (implicit-style)
	// pre-2.1; strict mode rejects to force explicit response_type=code.
	srv := newStrictServer(t, true, strictRedirect)
	status, body := loginStrict(t, srv, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "unsupported_response_type" {
		t.Errorf("error = %v want unsupported_response_type", body["error"])
	}
}

func TestOAuth21Strict_AllowsResponseTypeCodeWithPKCE(t *testing.T) {
	srv := newStrictServer(t, true, strictRedirect)
	status, body := loginStrict(t, srv, map[string]any{
		"response_type":         "code",
		"redirect_uri":          strictRedirect,
		"code_challenge":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789012",
		"code_challenge_method": "plain",
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v want 200", status, body)
	}
	if code, _ := body["code"].(string); code == "" {
		t.Errorf("code missing in response: %v", body)
	}
}

func TestOAuth21Strict_RequiresPKCEDespitePerClientOptOut(t *testing.T) {
	srv := newStrictServer(t, true, strictRedirect)
	status, body := loginStrict(t, srv, map[string]any{
		"response_type": "code",
		"redirect_uri":  strictRedirect,
		// No code_challenge — client.RequirePKCE=false but strict
		// mode forces PKCE per OAuth 2.1 §4.1.1.
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "pkce_required" {
		t.Errorf("error = %v want pkce_required", body["error"])
	}
}

func TestOAuth21Strict_RejectsNonHTTPSRedirectURI(t *testing.T) {
	srv := newStrictServer(t, true, "http://app.example.com/cb")
	status, body := loginStrict(t, srv, map[string]any{
		"response_type":         "code",
		"redirect_uri":          "http://app.example.com/cb",
		"code_challenge":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789012",
		"code_challenge_method": "plain",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %v want invalid_redirect_uri", body["error"])
	}
}

func TestOAuth21Strict_AllowsHTTPLocalhostForDev(t *testing.T) {
	srv := newStrictServer(t, true, "http://localhost:3000/cb")
	status, body := loginStrict(t, srv, map[string]any{
		"response_type":         "code",
		"redirect_uri":          "http://localhost:3000/cb",
		"code_challenge":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789012",
		"code_challenge_method": "plain",
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v want 200 (localhost permitted)", status, body)
	}
}

func TestOAuth21Strict_DiscoveryOmitsImplicitResponseType(t *testing.T) {
	// Discovery advertisement must match runtime enforcement, otherwise
	// an RP scanning openid-configuration sees response_type=token
	// "supported", sends it, and trips unsupported_response_type at
	// the AS — a real integration footgun.
	srv := newStrictServer(t, true, strictRedirect)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	rts, _ := doc["response_types_supported"].([]any)
	for _, v := range rts {
		if s, _ := v.(string); s == "token" {
			t.Fatalf("strict mode advertises response_type=token in discovery: %v", rts)
		}
	}
	hasCode := false
	for _, v := range rts {
		if s, _ := v.(string); s == "code" {
			hasCode = true
		}
	}
	if !hasCode {
		t.Errorf("strict mode discovery missing response_type=code: %v", rts)
	}
}

func TestOAuth21Strict_DiscoveryAdvertisesImplicitWhenOff(t *testing.T) {
	// Off mode keeps the legacy advertisement so OAuth 2.0 RPs
	// scanning discovery don't lose visibility into supported types.
	srv := newStrictServer(t, false, strictRedirect)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	rts, _ := doc["response_types_supported"].([]any)
	hasToken := false
	for _, v := range rts {
		if s, _ := v.(string); s == "token" {
			hasToken = true
		}
	}
	if !hasToken {
		t.Fatalf("non-strict discovery missing legacy response_type=token: %v", rts)
	}
}

func TestOAuth21Strict_OffPreservesLegacyBehavior(t *testing.T) {
	// With strict mode OFF: response_type=token + non-https redirect +
	// client.RequirePKCE=false should all still work to prove zero
	// breaking change for OAuth 2.0 callers.
	srv := newStrictServer(t, false, "http://app.example.com/cb")
	status, body := loginStrict(t, srv, map[string]any{
		// Empty response_type (direct mint), no PKCE, http redirect
		// is in the client's allowlist so it passes.
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v want 200 (strict mode off should not break OAuth 2.0)", status, body)
	}
	if body["access_token"] == "" || body["access_token"] == nil {
		t.Errorf("expected access_token in non-strict-mode response: %v", body)
	}
}
