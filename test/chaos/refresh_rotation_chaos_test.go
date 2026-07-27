//go:build chaos

package chaostest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	rrcClient = "chaos-rr-client"
	rrcSecret = "chaos-rr-secret"
	rrcUser   = "u-chaos-rr"
)

// erroringIssueRefreshStore wraps the real MemoryRefreshTokenStore and fails
// every Issue call AFTER the first. The first Issue is the initial grant at
// /auth/login (must succeed so the test has a refresh token to rotate); the
// second Issue is the RE-issuance mid-rotation, at exactly the point
// HandleRefreshGrant has already Consume()'d (deleted) the presented token —
// the fail-closed branch AGENTS.md §3 calls out ("refresh rotation grant
// (500)"). This is the same one-method decorator-over-a-real-store pattern as
// test/refresh_rotation_velocity_test.go's failingRotationLimiter — not a mock
// of an existing implementation, since no bundled store errors on demand.
type erroringIssueRefreshStore struct {
	*defaultimpl.MemoryRefreshTokenStore
	issued int
}

func (e *erroringIssueRefreshStore) Issue(ctx context.Context, token string, info *oauth.RefreshToken) error {
	e.issued++
	if e.issued > 1 {
		return errors.New("simulated refresh store outage on rotation issue")
	}
	return e.MemoryRefreshTokenStore.Issue(ctx, token, info)
}

var _ oauth.RefreshTokenStore = (*erroringIssueRefreshStore)(nil)

func newRRCHarness(t *testing.T, store oauth.RefreshTokenStore) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rrcUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rrcClient, Secret: rrcSecret, Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: rrcUser, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func rrcLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body := `{"provider":"password","client_id":"` + rrcClient + `","credential":{"username":"x","password":"y"}}`
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode login body %q: %v", raw, err)
	}
	r, _ := out["refresh_token"].(string)
	if r == "" {
		t.Fatalf("no refresh_token in login body: %v", out)
	}
	return r
}

func rrcRotate(t *testing.T, srv *httptest.Server, refresh string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {rrcClient},
		"client_secret": {rrcSecret},
		"refresh_token": {refresh},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestChaos_RefreshRotationIssueError_FailsClosed drives a real
// authorization_code-free login -> refresh_token rotation and injects a
// storage failure exactly at the re-issuance step (the OLD token is already
// Consume()'d/deleted by then). AGENTS.md §3 classifies this branch
// FAIL-CLOSED: the client must see a hard 500, never a 200 that promises a
// refresh token that was never durably persisted.
func TestChaos_RefreshRotationIssueError_FailsClosed(t *testing.T) {
	inner := defaultimpl.NewMemoryRefreshTokenStore()
	store := &erroringIssueRefreshStore{MemoryRefreshTokenStore: inner}
	srv := newRRCHarness(t, store)

	refresh := rrcLogin(t, srv)
	status, body := rrcRotate(t, srv, refresh)
	if status != http.StatusInternalServerError {
		t.Fatalf("rotation-issue failure status=%d want %d (body=%v)", status, http.StatusInternalServerError, body)
	}
	if body["error"] != core.ErrInternal {
		t.Errorf("rotation-issue failure error=%v want %q", body["error"], core.ErrInternal)
	}

	// The old leaf cannot be redeemed a second time (the store keeps a
	// tombstone for BCP §4.13 reuse detection, so this surfaces as
	// ErrRefreshTokenReused rather than ErrRefreshTokenNotFound) and the new
	// leaf was never persisted (Issue errored) — the family is a dead end,
	// exactly as documented, never a silent partial success.
	if _, err := inner.Consume(context.Background(), refresh); !errors.Is(err, oauth.ErrRefreshTokenReused) {
		t.Errorf("consumed token should stay dead after the failed rotation: err=%v want %v", err, oauth.ErrRefreshTokenReused)
	}
}
