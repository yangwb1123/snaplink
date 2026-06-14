package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newSignupHarness(t *testing.T, enabled bool) (*httptest.Server, *defaultimpl.MemoryUserProvider, *defaultimpl.MemoryPasswordCredentialStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	pw := defaultimpl.NewMemoryPasswordCredentialStore()
	opts := []sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithUserProvider(users),
		sso.WithPasswordCredentialStore(pw),
	}
	if enabled {
		opts = append(opts, sso.WithSelfServiceSignup())
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)
	return hs, users, pw
}

func postSignup(t *testing.T, srv *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/register", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSignup_HappyPath(t *testing.T) {
	srv, users, pw := newSignupHarness(t, true)
	ctx := context.Background()

	code, body := postSignup(t, srv, map[string]any{"username": "newuser", "password": "pw12345678", "email": "new@example.com"})
	if code != http.StatusCreated || body["user_id"] != "newuser" {
		t.Fatalf("signup = %d %v, want 201 user_id=newuser", code, body)
	}
	u, err := users.GetByID(ctx, "newuser")
	if err != nil || u == nil || u.Email != "new@example.com" {
		t.Errorf("created user = %v, %v", u, err)
	}
	if err := pw.VerifyPassword(ctx, "newuser", "pw12345678"); err != nil {
		t.Errorf("password not set for new user: %v", err)
	}
}

func TestSignup_DuplicateRejected(t *testing.T) {
	srv, users, _ := newSignupHarness(t, true)
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "taken", Email: "existing@example.com"})

	code, body := postSignup(t, srv, map[string]any{"username": "taken", "password": "pw12345678"})
	if code != http.StatusConflict || body["error"] != "account_exists" {
		t.Fatalf("duplicate = %d %v, want 409 account_exists", code, body)
	}
	// The existing account must be untouched (not overwritten).
	if u, _ := users.GetByID(context.Background(), "taken"); u == nil || u.Email != "existing@example.com" {
		t.Errorf("existing account was overwritten: %v", u)
	}
}

func TestSignup_RejectsMissingFields(t *testing.T) {
	srv, _, _ := newSignupHarness(t, true)
	if c, _ := postSignup(t, srv, map[string]any{"username": "x"}); c != http.StatusBadRequest {
		t.Errorf("missing password = %d, want 400", c)
	}
	if c, _ := postSignup(t, srv, map[string]any{"password": "x"}); c != http.StatusBadRequest {
		t.Errorf("missing username = %d, want 400", c)
	}
}

func TestSignup_NotMountedWhenDisabled(t *testing.T) {
	srv, _, _ := newSignupHarness(t, false)
	if c, _ := postSignup(t, srv, map[string]any{"username": "x", "password": "y"}); c != http.StatusNotFound {
		t.Errorf("disabled = %d, want 404 (unmounted)", c)
	}
}
