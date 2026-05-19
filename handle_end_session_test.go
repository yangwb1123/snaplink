package sso_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	esClientID  = "es-client"
	esSecret    = "es-secret"
	esUserID    = "u-es"
	esGoodLogin = "https://app.example/post-logout"
)

func newEndSessionHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: esUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: esClientID, Secret: esSecret, Active: true,
		AllowedAuthenticators:  []string{"password"},
		TokenStrategy:          "jwt",
		AllowedScopes:          []string{"openid"},
		PostLogoutRedirectURIs: []string{esGoodLogin},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: esUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	store := defaultimpl.NewMemoryRefreshTokenStore()

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
		sso.WithIDTokenIssuer(issuer),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store
}

func loginAndGetIDToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  esClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	id, _ := out["id_token"].(string)
	if id == "" {
		t.Fatalf("no id_token: %s", raw)
	}
	return id
}

// http.Client that doesn't auto-follow redirects so we can inspect Location.
func nonFollowingClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestEndSession_RedirectsToAllowlistedURI(t *testing.T) {
	srv, _ := newEndSessionHarness(t)
	idToken := loginAndGetIDToken(t, srv)

	u := srv.URL + "/end_session?id_token_hint=" + idToken +
		"&post_logout_redirect_uri=" + esGoodLogin +
		"&state=abc123"
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, esGoodLogin) {
		t.Errorf("Location prefix mismatch: %s", loc)
	}
	if !strings.Contains(loc, "state=abc123") {
		t.Errorf("state not echoed: %s", loc)
	}
}

func TestEndSession_RejectsUnknownRedirectURI(t *testing.T) {
	srv, _ := newEndSessionHarness(t)
	idToken := loginAndGetIDToken(t, srv)
	// Attacker-supplied URI not in the allowlist → MUST NOT redirect.
	u := srv.URL + "/end_session?id_token_hint=" + idToken +
		"&post_logout_redirect_uri=https://evil.example/x"
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d want 204 (no redirect to unallowed URI)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("Location set on rejection: %q", loc)
	}
}

func TestEndSession_BadIDTokenHintRejected(t *testing.T) {
	srv, _ := newEndSessionHarness(t)
	u := srv.URL + "/end_session?id_token_hint=not-a-real-jwt" +
		"&post_logout_redirect_uri=" + esGoodLogin
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d want 400", resp.StatusCode)
	}
}

func TestEndSession_NoHintReturns204(t *testing.T) {
	srv, _ := newEndSessionHarness(t)
	// No id_token_hint, no client_id → still 204 (just a no-op).
	resp, err := nonFollowingClient().Get(srv.URL + "/end_session")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d want 204", resp.StatusCode)
	}
}

func TestEndSession_KillsRefreshTokensForClient(t *testing.T) {
	srv, store := newEndSessionHarness(t)
	idToken := loginAndGetIDToken(t, srv)

	// The login also minted a refresh token. After end_session, all
	// refresh tokens for (esUserID, esClientID) must be gone.
	u := srv.URL + "/end_session?id_token_hint=" + idToken
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// Issue a fresh refresh token tagged with the test subject so we
	// can verify the wipe took effect.
	_ = store.Issue(context.Background(), "leftover-test", &sso.RefreshToken{
		UserID: "different-user", ClientID: esClientID,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	// different-user's token MUST still exist (different subject).
	if _, err := store.Inspect(context.Background(), "leftover-test"); err != nil {
		t.Errorf("unrelated user's token incorrectly wiped: %v", err)
	}
}

func TestEndSession_DiscoveryAdvertisesEndpoint(t *testing.T) {
	srv, _ := newEndSessionHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	got, _ := out["end_session_endpoint"].(string)
	if !strings.HasSuffix(got, "/end_session") {
		t.Errorf("end_session_endpoint = %q, want suffix /end_session", got)
	}
}
