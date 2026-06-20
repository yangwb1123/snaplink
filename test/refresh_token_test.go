package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
)

const (
	rtUser     = "u-rt-bob"
	rtClient   = "rt-client"
	rtSecret   = "rt-secret"
	rtUsername = "bob"
	rtPassword = "pw"
)

// newRefreshFlowServer wires the minimum surface for end-to-end refresh
// testing: a oauth.RefreshTokenStore + ClientStore + UserProvider + TokenIssuer
// + a password Authenticator + SessionManager (login direct mint needs it).
func newRefreshFlowServer(t *testing.T, ttl time.Duration) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rtUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    rtClient,
		Secret:                rtSecret,
		Name:                  "Refresh Flow",
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rtUsername && p == rtPassword {
				return &sso.AuthResult{
					UserID:     rtUser,
					Attributes: map[string]string{"role": "admin"},
				}, nil
			}
			return nil, errors.New("bad")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	store := defaultimpl.NewMemoryRefreshTokenStore()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, ttl),
		sso.WithAuditRecorder(rec),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store, sink
}

// directLogin posts /auth/login with a password credential, returns the
// access_token + refresh_token from the response.
func directLogin(t *testing.T, srv *httptest.Server, scope []string) (access, refresh string) {
	t.Helper()
	payload := map[string]any{
		"provider":   "password",
		"client_id":  rtClient,
		"credential": map[string]string{"username": rtUsername, "password": rtPassword},
	}
	if scope != nil {
		payload["scope"] = scope
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ = out["access_token"].(string)
	refresh, _ = out["refresh_token"].(string)
	return access, refresh
}

// refreshExchange posts /token with grant_type=refresh_token. Returns
// status + body.
func refreshExchange(t *testing.T, srv *httptest.Server, refresh, scope, clientID, secret string) (int, map[string]any) {
	t.Helper()
	payload := map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     clientID,
		"client_secret": secret,
	}
	if scope != "" {
		payload["scope"] = scope
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// ---------- login-side issuance ----------

func TestRefreshToken_LoginIssuesRefreshTokenWhenStoreWired(t *testing.T) {
	srv, _, _ := newRefreshFlowServer(t, time.Hour)
	access, refresh := directLogin(t, srv, []string{"openid", "profile"})
	if access == "" {
		t.Fatal("access_token missing")
	}
	if refresh == "" {
		t.Fatal("refresh_token missing — store wired but field absent")
	}
	if refresh == access {
		t.Error("refresh_token must differ from access_token")
	}
}

func TestRefreshToken_LoginOmitsRefreshTokenWhenStoreUnwired(t *testing.T) {
	// Without oauth.RefreshTokenStore the field passes through whatever the
	// underlying TokenIssuer returned — for the stateless Ed25519 JWT
	// issuer that's empty.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rtUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rtClient, Secret: rtSecret,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: rtUser}, nil
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
		"client_id":  rtClient,
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if rt, _ := out["refresh_token"].(string); rt != "" {
		t.Errorf("refresh_token = %q, want empty (store unwired)", rt)
	}
}

// ---------- full refresh round trip ----------

func TestRefreshToken_FullRoundTripRotates(t *testing.T) {
	srv, _, sink := newRefreshFlowServer(t, time.Hour)
	_, refresh := directLogin(t, srv, []string{"openid", "profile"})

	status, body := refreshExchange(t, srv, refresh, "", rtClient, rtSecret)
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d body=%v", status, body)
	}
	newAccess, _ := body["access_token"].(string)
	newRefresh, _ := body["refresh_token"].(string)
	if newAccess == "" {
		t.Errorf("new access_token empty: %v", body)
	}
	if newRefresh == "" {
		t.Errorf("new refresh_token empty (rotation not happening): %v", body)
	}
	if newRefresh == refresh {
		t.Errorf("refresh_token NOT rotated — got same value back")
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}

	// Audit: one token_issued from the refresh exchange (login also
	// emits login_success but no extra token_issued, since the login
	// path doesn't call recordTokenIssued).
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventTokenIssued})
	if len(events) != 1 {
		t.Errorf("token_issued events = %d, want 1 (from refresh exchange)", len(events))
	}
}

func TestRefreshToken_SingleUseRotationEnforced(t *testing.T) {
	// Rotation: presenting the OLD refresh after a successful refresh
	// MUST fail as invalid_grant — the canonical replay/reuse signal.
	srv, _, _ := newRefreshFlowServer(t, time.Hour)
	_, refresh := directLogin(t, srv, nil)

	if status, _ := refreshExchange(t, srv, refresh, "", rtClient, rtSecret); status != http.StatusOK {
		t.Fatalf("first refresh status = %d", status)
	}
	status, body := refreshExchange(t, srv, refresh, "", rtClient, rtSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("replay error = %v, want invalid_grant", body["error"])
	}
}

// ---------- exchange-side validation ----------

func TestRefreshToken_ExchangeRequiresRefreshTokenField(t *testing.T) {
	srv, _, _ := newRefreshFlowServer(t, time.Hour)
	status, body := refreshExchange(t, srv, "", "", rtClient, rtSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestRefreshToken_ExchangeUnknownToken(t *testing.T) {
	srv, _, _ := newRefreshFlowServer(t, time.Hour)
	status, body := refreshExchange(t, srv, "made-up-token", "", rtClient, rtSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestRefreshToken_ExchangeMismatchedClient(t *testing.T) {
	// Issue a refresh token under rtClient, then have a SECOND client
	// (with a known secret) try to redeem it. The mismatch must fail
	// with invalid_grant — RFC 6749 §6 binding.
	srv, _, _ := newRefreshFlowServer(t, time.Hour)
	_, refresh := directLogin(t, srv, nil)

	// We don't have a second client registered in the harness, but we
	// can simulate the failure mode by directly checking that another
	// client_id (which doesn't exist) returns 401 invalid_client at the
	// outer guard — and we cover the client_id-mismatch branch via the
	// in-process unit test below using two real clients.
	status, body := refreshExchange(t, srv, refresh, "", "different-client", "different-secret")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%v want 401", status, body)
	}
}

func TestRefreshToken_ExchangeBindingClientIDMismatch(t *testing.T) {
	// Two real clients sharing the same TokenIssuer. Refresh issued for
	// client A must NOT be redeemable by client B even when B authenticates
	// with its own correct secret — this exercises the info.ClientID
	// binding check in the handler.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rtUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "client-a", Secret: "sec-a",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	clients.AddSeed(&sso.Client{
		ID: "client-b", Secret: "sec-b",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: rtUser}, nil
		},
	))
	store := defaultimpl.NewMemoryRefreshTokenStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Login as client-a, capture refresh.
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "client-a",
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var loginOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&loginOut)
	refresh, _ := loginOut["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("login produced no refresh_token")
	}

	// Try to redeem with client-b's (valid) credentials.
	rbody, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     "client-b",
		"client_secret": "sec-b",
	})
	rresp, err := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(rbody))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer func() { _ = rresp.Body.Close() }()
	if rresp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 invalid_grant", rresp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(rresp.Body).Decode(&out)
	if out["error"] != "invalid_grant" {
		t.Errorf("error = %v want invalid_grant", out["error"])
	}
}

func TestRefreshToken_ExchangeWithoutStore_NotImplemented(t *testing.T) {
	// Server has /token wired but no oauth.RefreshTokenStore — refresh_token
	// grant must return 501 + refresh_token_not_configured.
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: rtClient, Secret: rtSecret, Active: true})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	body, _ := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": "anything",
		"client_id":     rtClient,
		"client_secret": rtSecret,
	})
	resp, err := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"] != "refresh_token_not_configured" {
		t.Errorf("error = %v", out["error"])
	}
}

// ---------- scope narrowing ----------

func TestRefreshToken_ScopeNarrowingAccepted(t *testing.T) {
	// Original grant was ["openid", "profile", "email"]; refresh
	// requests just ["openid"] — narrowing is allowed.
	srv, _, _ := newRefreshFlowServer(t, time.Hour)
	_, refresh := directLogin(t, srv, []string{"openid", "profile", "email"})

	status, body := refreshExchange(t, srv, refresh, "openid", rtClient, rtSecret)
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v want 200 (narrowing allowed)", status, body)
	}
}

func TestRefreshToken_ScopeExpansionRejected(t *testing.T) {
	// Original grant was ["openid"]; refresh asks for ["openid", "admin"]
	// — MUST be rejected as invalid_scope per RFC 6749 §6.
	srv, _, _ := newRefreshFlowServer(t, time.Hour)
	_, refresh := directLogin(t, srv, []string{"openid"})

	status, body := refreshExchange(t, srv, refresh, "openid admin", rtClient, rtSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%v want 400 invalid_scope", status, body)
	}
	if body["error"] != "invalid_scope" {
		t.Errorf("error = %v want invalid_scope", body["error"])
	}
}

// ---------- TTL ----------

func TestRefreshToken_ExpiredTokenRejected(t *testing.T) {
	// 1ns TTL → token stale by the time we exchange.
	srv, _, _ := newRefreshFlowServer(t, time.Nanosecond)
	_, refresh := directLogin(t, srv, nil)
	time.Sleep(2 * time.Millisecond)

	status, body := refreshExchange(t, srv, refresh, "", rtClient, rtSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v want invalid_grant", body["error"])
	}
}

// ---------- composition with authorization_code ----------

func TestRefreshToken_AuthCodeExchangeIncludesRefreshTokenWhenStoreWired(t *testing.T) {
	// The authorization_code branch in handleToken should ALSO return
	// a refresh_token when oauth.RefreshTokenStore is wired, so SPAs using
	// the code grant get refresh capability without a separate dance.
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rtUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rtClient, Secret: rtSecret,
		RedirectURIs:          []string{"https://app/cb"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: rtUser}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Step 1: request code via login.
	loginBody, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     rtClient,
		"credential":    map[string]string{"username": "x", "password": "y"},
		"response_type": "code",
		"redirect_uri":  "https://app/cb",
	})
	lresp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = lresp.Body.Close() }()
	var lOut map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&lOut)
	code, _ := lOut["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", lOut)
	}

	// Step 2: exchange code for token — refresh_token MUST be present.
	tokBody, _ := json.Marshal(map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     rtClient,
		"client_secret": rtSecret,
		"redirect_uri":  "https://app/cb",
	})
	tresp, err := http.Post(httpSrv.URL+"/token", "application/json", bytes.NewReader(tokBody))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = tresp.Body.Close() }()
	var tOut map[string]any
	_ = json.NewDecoder(tresp.Body).Decode(&tOut)
	if tresp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d body=%v", tresp.StatusCode, tOut)
	}
	if rt, _ := tOut["refresh_token"].(string); rt == "" {
		t.Errorf("authorization_code exchange missing refresh_token: %v", tOut)
	}
}
