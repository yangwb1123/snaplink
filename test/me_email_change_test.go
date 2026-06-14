package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

type capturingEmailSender struct {
	mu     sync.Mutex
	target string
	token  string
	calls  int
}

func (c *capturingEmailSender) SendEmailChangeToken(_ context.Context, newEmail, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.target, c.token, c.calls = newEmail, token, c.calls+1
	return nil
}

func (c *capturingEmailSender) last() (string, string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.target, c.token, c.calls
}

func newEmailChangeHarness(t *testing.T, withFlow bool) (*httptest.Server, *defaultimpl.MemoryUserProvider, *capturingEmailSender, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice", Email: "old@example.com"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "em-app", Secret: "s", Name: "Email App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	sender := &capturingEmailSender{}
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5*time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withFlow {
		opts = append(opts,
			sso.WithEmailChangeStore(defaultimpl.NewMemoryEmailChangeStore(), time.Minute),
			sso.WithEmailChangeSender(sender),
		)
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "em-app",
			"credential": map[string]string{"username": "alice", "password": "pw"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("login: no token: %v", out)
		}
		return tok
	}
	return hs, users, sender, loginAs
}

func postEmail(t *testing.T, srv *httptest.Server, path, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestEmailChange_HappyPath(t *testing.T) {
	srv, users, sender, loginAs := newEmailChangeHarness(t, true)
	tok := loginAs()

	code, body := postEmail(t, srv, "/me/email/change", tok, map[string]any{"new_email": "new@example.com"})
	if code != http.StatusOK || body["status"] != "sent" {
		t.Fatalf("change = %d %v, want 200 sent", code, body)
	}
	target, token, calls := sender.last()
	if calls != 1 || token == "" || target != "new@example.com" {
		t.Fatalf("sender target=%q token=%q calls=%d", target, token, calls)
	}

	code, body = postEmail(t, srv, "/me/email/verify", tok, map[string]any{"token": token})
	if code != http.StatusOK || body["email"] != "new@example.com" {
		t.Fatalf("verify = %d %v, want 200 email=new@example.com", code, body)
	}
	if u, _ := users.GetByID(context.Background(), "u-alice"); u == nil || u.Email != "new@example.com" {
		t.Errorf("user email = %v, want new@example.com", u)
	}
	// Single-use: replaying the token fails oracle-safe.
	if c, b := postEmail(t, srv, "/me/email/verify", tok, map[string]any{"token": token}); c != http.StatusBadRequest || b["error"] != "email_change_invalid" {
		t.Errorf("replay = %d %v, want 400 email_change_invalid", c, b)
	}
}

func TestEmailChange_RejectsBadEmailAndToken(t *testing.T) {
	srv, _, _, loginAs := newEmailChangeHarness(t, true)
	tok := loginAs()
	if c, _ := postEmail(t, srv, "/me/email/change", tok, map[string]any{"new_email": "not-an-email"}); c != http.StatusBadRequest {
		t.Errorf("bad email = %d, want 400", c)
	}
	if c, b := postEmail(t, srv, "/me/email/verify", tok, map[string]any{"token": "bogus"}); c != http.StatusBadRequest || b["error"] != "email_change_invalid" {
		t.Errorf("bad token = %d %v, want 400 email_change_invalid", c, b)
	}
}

func TestEmailChange_RequiresBearer(t *testing.T) {
	srv, _, _, _ := newEmailChangeHarness(t, true)
	if c, _ := postEmail(t, srv, "/me/email/change", "", map[string]any{"new_email": "x@e.com"}); c != http.StatusUnauthorized {
		t.Errorf("no bearer = %d, want 401", c)
	}
}

func TestEmailChange_NotMountedWithoutFlow(t *testing.T) {
	srv, _, _, loginAs := newEmailChangeHarness(t, false)
	if c, _ := postEmail(t, srv, "/me/email/change", loginAs(), map[string]any{"new_email": "x@e.com"}); c != http.StatusNotFound {
		t.Errorf("without flow = %d, want 404 (unmounted)", c)
	}
}
