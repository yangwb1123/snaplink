package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

const (
	txARUser   = "u-txar"
	txARClient = "tx-ar-client"
	txARSecret = "tx-ar-secret"
	txARAPI    = "https://api.example.com"
)

func newTokenExchangeActorReplayHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: txARUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: txARClient, Secret: txARSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedResources:      []string{txARAPI},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: txARUser, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func txARLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  txARClient,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"read"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("no token: %v", out)
	}
	return tok
}

func txARExchange(t *testing.T, srv *httptest.Server, subject, actor string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txARClient},
		"client_secret":      {txARSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {actor},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txARAPI},
	}
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	body := map[string]any{}
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body
}

func TestTokenExchange_ActorTokenJTIReplayRejected(t *testing.T) {
	srv := newTokenExchangeActorReplayHarness(t)
	subject := txARLogin(t, srv)
	actor := txARLogin(t, srv)

	// First exchange consumes the actor_token's jti — succeeds.
	status, body := txARExchange(t, srv, subject, actor)
	if status != http.StatusOK {
		t.Fatalf("first exchange status=%d body=%v", status, body)
	}

	// Second exchange replays the SAME actor_token (same jti within
	// its expiry) — defense-in-depth replay store rejects with
	// invalid_grant, matching the oracle-collapse pattern.
	status, body = txARExchange(t, srv, subject, actor)
	if status != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400; body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidGrant {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidGrant)
	}
}
