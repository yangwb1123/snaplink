package sso_test

import "github.com/snaplink/sso/oauth"

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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	raUser   = "u-revokeall"
	raClient = "ra-client"
	raSecret = "ra-secret"
)

func newRevokeAllServer(t *testing.T) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: raUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: raClient, Secret: raSecret,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: raUser, Provider: "password"}, nil
		},
	))
	store := defaultimpl.NewMemoryRefreshTokenStore()
	// Use Ed25519 issuer with the client_id as audience so claims.Audience
	// is populated for the revoke-all subject lookup.
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store
}

// loginAndCaptureTokens logs in and returns (access, refresh).
func loginAndCaptureTokens(t *testing.T, srv *httptest.Server) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  raClient,
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ := out["access_token"].(string)
	refresh, _ := out["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens: %s", raw)
	}
	return access, refresh
}

func postRevokeAll(t *testing.T, srv *httptest.Server, bearer string) (int, map[string]any) {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/revoke-all", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestRevokeAll_KillsAllRefreshTokensForSubject(t *testing.T) {
	srv, store := newRevokeAllServer(t)

	// Three logins → three refresh tokens for the same subject.
	access, _ := loginAndCaptureTokens(t, srv)
	_, r2 := loginAndCaptureTokens(t, srv)
	_, r3 := loginAndCaptureTokens(t, srv)

	// Without the audience on the issuer, the bearer won't have aud
	// set — DeleteAllForSubject is called with clientID="", which the
	// memory impl interprets as "all clients for the user". That's
	// fine for this test (the user has tokens only for one client).

	status, body := postRevokeAll(t, srv, access)
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, body)
	}
	// All three refresh tokens MUST be gone.
	for _, r := range []string{r2, r3} {
		if _, err := store.Consume(context.Background(), r); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
			t.Errorf("refresh %q survived revoke-all: err=%v", r, err)
		}
	}
	// Reported count must match.
	count, _ := body["refresh_tokens_revoked"].(float64)
	if count != 3 {
		t.Errorf("refresh_tokens_revoked = %v want 3", count)
	}
}

func TestRevokeAll_PresentedAccessTokenAlsoRevoked(t *testing.T) {
	srv, _ := newRevokeAllServer(t)
	access, _ := loginAndCaptureTokens(t, srv)

	if status, _ := postRevokeAll(t, srv, access); status != http.StatusOK {
		t.Fatalf("revoke-all status = %d", status)
	}

	// The presented access token must no longer work for /userinfo —
	// proves the access token was killed across issuers, not just
	// the refresh tier.
	r, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("/userinfo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/userinfo status = %d, want 401 after revoke-all", resp.StatusCode)
	}
}

func TestRevokeAll_RequiresBearer(t *testing.T) {
	srv, _ := newRevokeAllServer(t)
	status, body := postRevokeAll(t, srv, "")
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d want 401", status)
	}
	if body["error"] != "missing_token" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestRevokeAll_InvalidBearerRejected(t *testing.T) {
	srv, _ := newRevokeAllServer(t)
	status, body := postRevokeAll(t, srv, "garbage-bearer")
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d want 401", status)
	}
	if body["error"] != "invalid_token" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestRevokeAll_WithoutSubjectIndexReturns501(t *testing.T) {
	// Wire a store that DOESN'T implement oauth.RefreshTokenSubjectIndex —
	// revoke-all must 501 with the dedicated error.
	store := stubRefreshStore{}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: raClient, Secret: raSecret, Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt"})
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: raUser})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: raUser}, nil
		},
	))
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

	// Login first to get a valid bearer.
	loginBody, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  raClient,
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	lresp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer lresp.Body.Close()
	var lOut map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&lOut)
	access, _ := lOut["access_token"].(string)

	r, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/token/revoke-all", nil)
	r.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d want 501", resp.StatusCode)
	}
}

// stubRefreshStore implements oauth.RefreshTokenStore but NOT
// oauth.RefreshTokenSubjectIndex — used to verify the 501 fallback.
type stubRefreshStore struct{}

func (stubRefreshStore) Issue(_ context.Context, _ string, _ *oauth.RefreshToken) error {
	return nil
}

func (stubRefreshStore) Consume(_ context.Context, _ string) (*oauth.RefreshToken, error) {
	return nil, oauth.ErrRefreshTokenNotFound
}

// ---------- SPI smoke ----------

func TestRefreshTokenSubjectIndex_MemoryStoreFiltersByClient(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	// User u has tokens for both client-a and client-b.
	_ = store.Issue(context.Background(), "ta-1", &oauth.RefreshToken{
		UserID: "u", ClientID: "a", ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = store.Issue(context.Background(), "ta-2", &oauth.RefreshToken{
		UserID: "u", ClientID: "a", ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = store.Issue(context.Background(), "tb-1", &oauth.RefreshToken{
		UserID: "u", ClientID: "b", ExpiresAt: time.Now().Add(time.Hour),
	})

	// Revoke only client-a's tokens.
	n, err := store.DeleteAllForSubject(context.Background(), "u", "a")
	if err != nil {
		t.Fatalf("DeleteAllForSubject: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d want 2", n)
	}
	// b's token survives.
	if _, err := store.Consume(context.Background(), "tb-1"); err != nil {
		t.Errorf("client-b token incorrectly deleted: %v", err)
	}
}

func TestRefreshTokenSubjectIndex_EmptyClientWipesAcrossAllClients(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	_ = store.Issue(context.Background(), "ta", &oauth.RefreshToken{
		UserID: "u", ClientID: "a", ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = store.Issue(context.Background(), "tb", &oauth.RefreshToken{
		UserID: "u", ClientID: "b", ExpiresAt: time.Now().Add(time.Hour),
	})
	// Empty client → all of u's tokens.
	n, _ := store.DeleteAllForSubject(context.Background(), "u", "")
	if n != 2 {
		t.Errorf("deleted = %d want 2 (admin-style wipe)", n)
	}
}

func TestRefreshTokenSubjectIndex_EmptyUserIsNoOp(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	n, err := store.DeleteAllForSubject(context.Background(), "", "")
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d want 0 (empty user_id is a no-op)", n)
	}
}
