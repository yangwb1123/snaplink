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

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// capturingResetSender records the last (target, token) so the test can replay
// the token into /auth/reset-password.
type capturingResetSender struct {
	mu     sync.Mutex
	target string
	token  string
	calls  int
}

func (c *capturingResetSender) SendResetToken(_ context.Context, target, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.target, c.token, c.calls = target, token, c.calls+1
	return nil
}

func (c *capturingResetSender) last() (string, string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.target, c.token, c.calls
}

func newPasswordResetHarness(t *testing.T, withFlow bool) (*httptest.Server, *defaultimpl.MemoryPasswordCredentialStore, *capturingResetSender) {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: "u-alice", Email: "alice@example.com"})
	pw := defaultimpl.NewMemoryPasswordCredentialStore()
	_ = pw.SetPassword(ctx, "u-alice", "old-pass")
	sender := &capturingResetSender{}

	opts := []sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithPasswordCredentialStore(pw),
	}
	if withFlow {
		opts = append(opts,
			sso.WithPasswordResetStore(defaultimpl.NewMemoryPasswordResetStore(), time.Minute),
			sso.WithPasswordResetResolver(func(_ context.Context, id string) (string, error) {
				if id == "alice" || id == "alice@example.com" {
					return "u-alice", nil
				}
				return "", nil // unknown — anti-enumeration
			}),
			sso.WithPasswordResetDeliveryResolver(func(_ context.Context, userID string) (string, error) {
				if userID == "u-alice" {
					return "alice@example.com", nil
				}
				return "", nil
			}),
			sso.WithPasswordResetSender(sender),
		)
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)
	return hs, pw, sender
}

func postReset(t *testing.T, url string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestPasswordReset_HappyPath(t *testing.T) {
	srv, pw, sender := newPasswordResetHarness(t, true)
	ctx := context.Background()

	code, body := postReset(t, srv.URL+"/auth/forgot-password", map[string]any{"identifier": "alice"})
	if code != http.StatusOK || body["status"] != "sent" {
		t.Fatalf("forgot = %d %v, want 200 sent", code, body)
	}
	target, token, calls := sender.last()
	if calls != 1 || token == "" || target != "alice@example.com" {
		t.Fatalf("sender got target=%q token=%q calls=%d", target, token, calls)
	}

	code, body = postReset(t, srv.URL+"/auth/reset-password", map[string]any{"token": token, "new_password": "new-pass"})
	if code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("reset = %d %v, want 200 ok", code, body)
	}
	// New password works; old one no longer does.
	if err := pw.VerifyPassword(ctx, "u-alice", "new-pass"); err != nil {
		t.Errorf("new password does not verify: %v", err)
	}
	if err := pw.VerifyPassword(ctx, "u-alice", "old-pass"); err == nil {
		t.Error("old password still verifies after reset")
	}
	// Token is single-use: replay fails oracle-safe.
	if c, b := postReset(t, srv.URL+"/auth/reset-password", map[string]any{"token": token, "new_password": "x"}); c != http.StatusBadRequest || b["error"] != "reset_invalid" {
		t.Errorf("replay = %d %v, want 400 reset_invalid", c, b)
	}
}

func TestPasswordReset_AntiEnumeration(t *testing.T) {
	// An unknown identifier returns the SAME 200 {sent} and triggers no delivery.
	srv, _, sender := newPasswordResetHarness(t, true)
	code, body := postReset(t, srv.URL+"/auth/forgot-password", map[string]any{"identifier": "ghost"})
	if code != http.StatusOK || body["status"] != "sent" {
		t.Fatalf("unknown identifier = %d %v, want 200 sent", code, body)
	}
	if _, _, calls := sender.last(); calls != 0 {
		t.Errorf("delivery happened for an unknown identifier (calls=%d)", calls)
	}
}

func TestPasswordReset_BadTokenOracleSafe(t *testing.T) {
	srv, _, _ := newPasswordResetHarness(t, true)
	c, b := postReset(t, srv.URL+"/auth/reset-password", map[string]any{"token": "not-a-real-token", "new_password": "x"})
	if c != http.StatusBadRequest || b["error"] != "reset_invalid" {
		t.Fatalf("bad token = %d %v, want 400 reset_invalid", c, b)
	}
}

func TestPasswordReset_NotMountedWithoutFlow(t *testing.T) {
	srv, _, _ := newPasswordResetHarness(t, false)
	if c, _ := postReset(t, srv.URL+"/auth/forgot-password", map[string]any{"identifier": "alice"}); c != http.StatusNotFound {
		t.Errorf("forgot-password without flow = %d, want 404 (unmounted)", c)
	}
}
