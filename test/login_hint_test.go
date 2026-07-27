package ssotest

import "github.com/yangwb1123/snaplink/protocols/oauth"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	loginHintUserID   = "u-loginhint"
	loginHintClientID = "loginhint-client"
	loginHintSecret   = "loginhint-secret"
	loginHintPassword = "pw"
)

// captureAuthenticator stores the most recent AuthRequest's LoginHint
// so tests can verify it threaded through from /auth/login + PAR.
// Always returns a successful AuthResult (auth correctness is tested
// elsewhere).
type captureAuthenticator struct {
	mu   sync.Mutex
	hint string
}

func (c *captureAuthenticator) Name() string             { return "password" }
func (c *captureAuthenticator) LoginURL(_ string) string { return "" }
func (c *captureAuthenticator) Authenticate(_ context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	c.mu.Lock()
	c.hint = req.LoginHint
	c.mu.Unlock()
	return &sso.AuthResult{UserID: loginHintUserID, Provider: "password"}, nil
}
func (c *captureAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("no callback")
}
func (c *captureAuthenticator) snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hint
}

// newLoginHintHarness wires the capture authenticator + PAR store so
// both the direct /auth/login path and the PAR-pushed path can be
// exercised by tests.
func newLoginHintHarness(t *testing.T) (*httptest.Server, *captureAuthenticator, oauth.PARStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: loginHintUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: loginHintClientID, Secret: loginHintSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{"https://app.example/cb"},
	})
	auth := &captureAuthenticator{}
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(auth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, auth, parStore
}

func TestLoginHint_DirectLoginThreadsToAuthenticator(t *testing.T) {
	srv, auth, _ := newLoginHintHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  loginHintClientID,
		"credential": map[string]string{"username": loginHintUserID, "password": loginHintPassword},
		"login_hint": "alice@example.com",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status=%d body=%s", resp.StatusCode, raw)
	}
	if got := auth.snapshot(); got != "alice@example.com" {
		t.Errorf("authenticator saw LoginHint=%q want %q", got, "alice@example.com")
	}
}

func TestLoginHint_PARPushSurvivesIntoAuthenticator(t *testing.T) {
	srv, auth, store := newLoginHintHarness(t)
	uri, err := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID:     loginHintClientID,
		ResponseType: "",
		RedirectURI:  "https://app.example/cb",
		LoginHint:    "bob@example.com",
		ExpiresAt:    time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("seed PAR: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   loginHintClientID,
		"credential":  map[string]string{"username": loginHintUserID, "password": loginHintPassword},
		"request_uri": uri,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status=%d body=%s", resp.StatusCode, raw)
	}
	if got := auth.snapshot(); got != "bob@example.com" {
		t.Errorf("authenticator saw LoginHint=%q want %q (pushed via PAR)", got, "bob@example.com")
	}
}

func TestLoginHint_PARPushBeatsLoginParam(t *testing.T) {
	// PAR's payload wins on conflict — same precedence as scope /
	// redirect_uri / authorization_details. The caller can't sneak
	// a different hint into the redirect-time parameter.
	srv, auth, store := newLoginHintHarness(t)
	uri, _ := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID:    loginHintClientID,
		RedirectURI: "https://app.example/cb",
		LoginHint:   "pushed@example.com",
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   loginHintClientID,
		"credential":  map[string]string{"username": loginHintUserID, "password": loginHintPassword},
		"request_uri": uri,
		"login_hint":  "tampered@attacker.example",
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	_ = resp.Body.Close()
	if got := auth.snapshot(); got != "pushed@example.com" {
		t.Errorf("LoginHint=%q want %q (PAR push must win)", got, "pushed@example.com")
	}
}

func TestLoginHint_AbsentByDefault(t *testing.T) {
	srv, auth, _ := newLoginHintHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  loginHintClientID,
		"credential": map[string]string{"username": loginHintUserID, "password": loginHintPassword},
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	_ = resp.Body.Close()
	if got := auth.snapshot(); got != "" {
		t.Errorf("LoginHint=%q want empty (no hint supplied)", got)
	}
}
