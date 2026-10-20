package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oidc/browsersso"
	"github.com/yangwb1123/snaplink/shared/core"
)

const stockAuthTimeVerifier = "browser-auth-time-verifier-01234567890123456789"

// A real canonical store whose create response crosses a second boundary.
// This makes independently sampled session/code/mint timestamps fail reliably.
type stockDelayedSessionManager struct{ core.SessionManager }

func (m *stockDelayedSessionManager) CreateWithMeta(ctx context.Context, userID string, meta core.SessionMeta) (*core.Session, error) {
	session, err := m.SessionManager.(core.SessionMetaCreator).CreateWithMeta(ctx, userID, meta)
	if err == nil {
		time.Sleep(time.Until(time.Unix(session.AuthTime.Unix()+2, 0)))
	}
	return session, err
}

func stockAuthTimeApp(t *testing.T) (*app, http.Handler) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.Issuer = "https://sso.example.test"
	cfg.Server.TokenTTL = 15 * time.Minute
	cfg.Server.SessionTTL = time.Hour
	cfg.Keys.Signing.Alg = "eddsa"
	cfg.OAuth.AuthCode.Enabled = true
	cfg.OAuth.RefreshToken.Enabled = true
	cfg.OIDC.BrowserSSO.Enabled = true
	cfg.Identity.Backend = "sqlite"
	cfg.Identity.SQLite.DSN = "file:" + filepath.Join(t.TempDir(), "identity.db")
	cfg.Authenticators.Password = &config.PasswordConfig{Enabled: true, Users: []config.PasswordUserConfig{{
		Username: "alice", SubjectID: "alice", BcryptHashFile: writeBcryptHashFile(t, "fixture-password"),
	}}}
	cfg.Clients = []config.ClientConfig{{ID: "rp", Active: true, SkipConsent: true, TokenStrategy: "jwt",
		TokenEndpointAuthMethod: "none", RequirePKCE: true, AllowedScopes: []string{"openid"},
		AllowedAuthenticators: []string{"password"}, RedirectURIs: []string{"https://rp.example/callback"}}}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shutdownApp(t, a) })
	sso.WithSessionManager(&stockDelayedSessionManager{a.sessionMgr})(a.server)
	handler, err := buildHTTPHandler(cfg, a, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	return a, handler
}

func assertStockAuthTime(t *testing.T, a *app, raw any, want time.Time) {
	t.Helper()
	token, ok := raw.(string)
	if !ok || token == "" {
		t.Fatal("stock token missing")
	}
	claims, err := a.idTokenIssuer.(core.TokenIssuer).Validate(t.Context(), token)
	if err != nil {
		t.Fatalf("stock token signature verification failed: %v", err)
	}
	// Generic signature validation also serves ID-token-hint callers. The
	// resource endpoint, not that generic validator, enforces bearer purpose.
	request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	a.server.Handler().ServeHTTP(response, request)
	if (claims.TokenUse == core.TokenUseAccessToken && response.Code != http.StatusOK) ||
		(claims.TokenUse == core.TokenUseIDToken && response.Code != http.StatusUnauthorized) {
		t.Fatal("stock resource-endpoint token purpose boundary changed")
	}
	if claims.AuthTime.IsZero() || claims.AuthTime.Unix() != want.Unix() {
		t.Fatal("stock token changed the original authentication time")
	}
}

func TestBuildApp_BrowserSSOAuthenticationTimeSurvivesDelayedExchangeAndRefresh(t *testing.T) {
	a, handler := stockAuthTimeApp(t)
	digest := sha256.Sum256([]byte(stockAuthTimeVerifier))
	login := stockBrowserSSORequest(t, handler, map[string]any{
		"client_id": "rp", "response_type": "code", "redirect_uri": "https://rp.example/callback",
		"scope": []string{"openid"}, "provider": "password",
		"credential":     map[string]string{"username": "alice", "password": "fixture-password"},
		"code_challenge": base64.RawURLEncoding.EncodeToString(digest[:]), "code_challenge_method": "S256",
	}, nil)
	cookies := login.Result().Cookies()
	if login.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatal("stock code login failed")
	}
	anchor, err := a.idTokenIssuer.(browsersso.Verifier).ValidateBrowserSession(t.Context(), cookies[0].Value)
	if err != nil || anchor == nil || anchor.AuthTime.IsZero() {
		t.Fatal("stock browser authentication time missing")
	}
	var authorization map[string]any
	if json.Unmarshal(login.Body.Bytes(), &authorization) != nil {
		t.Fatal("invalid authorization response")
	}
	// Exchange is later still: neither code issuance nor exchange may
	// manufacture a newer authentication event than the OP anchor.
	time.Sleep(time.Until(time.Unix(anchor.AuthTime.Unix()+3, 0)))
	grant := stockTokenGrant(t, handler, map[string]any{
		"grant_type": "authorization_code", "client_id": "rp", "code": authorization["code"],
		"redirect_uri": "https://rp.example/callback", "code_verifier": stockAuthTimeVerifier,
	})
	assertStockAuthTime(t, a, grant["access_token"], anchor.AuthTime)
	assertStockAuthTime(t, a, grant["id_token"], anchor.AuthTime)
	refresh := stockTokenGrant(t, handler, map[string]any{
		"grant_type": "refresh_token", "client_id": "rp", "refresh_token": grant["refresh_token"],
	})
	// The published refresh grant returns access/refresh tokens, not an ID token.
	assertStockAuthTime(t, a, refresh["access_token"], anchor.AuthTime)
}

func stockTokenGrant(t *testing.T, handler http.Handler, body map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var grant map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &grant) != nil {
		t.Fatal("stock token grant failed")
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatal("credential response lacks cache isolation")
	}
	return grant
}

func TestBuildApp_BrowserSSOKeepsAuthenticatorAuthenticationTime(t *testing.T) {
	a, handler := stockAuthTimeApp(t)
	original := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	verifier := authenticators.PasswordVerifierFunc(func(_ context.Context, user, password string) (*sso.AuthResult, error) {
		if user != "alice" || password != "fixture-password" {
			return nil, errors.New(core.ErrInvalidCredentials)
		}
		return &sso.AuthResult{UserID: "alice", AuthTime: original}, nil
	})
	sso.WithAuthenticator(authenticators.NewPasswordAuthenticator(verifier))(a.server)
	login := stockBrowserSSORequest(t, handler, map[string]any{
		"client_id": "rp", "response_type": "token", "scope": []string{"openid"}, "provider": "password",
		"credential": map[string]string{"username": "alice", "password": "fixture-password"},
	}, nil)
	cookies := login.Result().Cookies()
	if login.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatal("stock direct login failed")
	}
	anchor, err := a.idTokenIssuer.(browsersso.Verifier).ValidateBrowserSession(t.Context(), cookies[0].Value)
	if err != nil || anchor == nil || anchor.AuthTime.Unix() != original.Unix() {
		t.Fatal("authenticator authentication time was overwritten")
	}
	var grant map[string]any
	if json.Unmarshal(login.Body.Bytes(), &grant) != nil {
		t.Fatal("invalid direct login response")
	}
	assertStockAuthTime(t, a, grant["access_token"], original)
	assertStockAuthTime(t, a, grant["id_token"], original)
}

func TestBuildApp_BrowserSSODirectLoginUsesOneAuthenticationTime(t *testing.T) {
	a, handler := stockAuthTimeApp(t)
	login := stockBrowserSSORequest(t, handler, map[string]any{
		"client_id": "rp", "response_type": "token", "scope": []string{"openid"}, "provider": "password",
		"credential": map[string]string{"username": "alice", "password": "fixture-password"},
	}, nil)
	cookies := login.Result().Cookies()
	if login.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatal("stock direct login failed")
	}
	anchor, err := a.idTokenIssuer.(browsersso.Verifier).ValidateBrowserSession(t.Context(), cookies[0].Value)
	if err != nil || anchor == nil || anchor.TokenUse != core.TokenUseBrowserSession {
		t.Fatal("stock browser authentication time missing")
	}
	var grant map[string]any
	if json.Unmarshal(login.Body.Bytes(), &grant) != nil {
		t.Fatal("invalid direct login response")
	}
	assertStockAuthTime(t, a, grant["access_token"], anchor.AuthTime)
	assertStockAuthTime(t, a, grant["id_token"], anchor.AuthTime)
	refresh := stockTokenGrant(t, handler, map[string]any{
		"grant_type": "refresh_token", "client_id": "rp", "refresh_token": grant["refresh_token"],
	})
	assertStockAuthTime(t, a, refresh["access_token"], anchor.AuthTime)
}
