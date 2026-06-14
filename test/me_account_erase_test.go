package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/compliance"
	"github.com/snaplink/sso/defaultimpl"
)

func newAccountEraseHarness(t *testing.T, withErase bool) (*httptest.Server, *defaultimpl.MemoryUserProvider, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice", Email: "alice@example.com"})
	sessions := defaultimpl.NewMemorySessionManager()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "erase-app", Secret: "s", Name: "Erase App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5*time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withErase {
		opts = append(opts, sso.WithSelfServiceAccountErasure(&compliance.Eraser{Users: users, Sessions: sessions}))
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "erase-app",
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
	return hs, users, loginAs
}

func postErase(t *testing.T, srv *httptest.Server, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/me/account/erase", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST erase: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestMyAccountErase_RequiresMatchingConfirm(t *testing.T) {
	srv, users, loginAs := newAccountEraseHarness(t, true)
	// Wrong confirm → 400, account untouched.
	code, body := postErase(t, srv, loginAs(), map[string]any{"confirm": "not-me"})
	if code != http.StatusBadRequest || body["error"] != "confirmation_required" {
		t.Fatalf("wrong confirm = %d %v, want 400 confirmation_required", code, body)
	}
	if u, err := users.GetByID(context.Background(), "u-alice"); err != nil || u == nil {
		t.Error("account was erased despite a bad confirmation")
	}
}

func TestMyAccountErase_DryRunPreviewsWithoutDeleting(t *testing.T) {
	srv, users, loginAs := newAccountEraseHarness(t, true)
	code, body := postErase(t, srv, loginAs(), map[string]any{"dry_run": true})
	if code != http.StatusOK {
		t.Fatalf("dry-run = %d %v", code, body)
	}
	if body["dry_run"] != true {
		t.Errorf("dry-run report = %v, want dry_run=true", body)
	}
	// The Eraser reports the delete INTENT in dry-run (user_deleted=true means
	// "would delete"); the real assertion is that NOTHING was mutated.
	if u, err := users.GetByID(context.Background(), "u-alice"); err != nil || u == nil {
		t.Error("dry-run actually deleted the account")
	}
}

func TestMyAccountErase_HappyPath(t *testing.T) {
	srv, users, loginAs := newAccountEraseHarness(t, true)
	code, body := postErase(t, srv, loginAs(), map[string]any{"confirm": "u-alice"})
	if code != http.StatusOK {
		t.Fatalf("erase = %d %v", code, body)
	}
	if body["user_deleted"] != true {
		t.Errorf("report = %v, want user_deleted=true", body)
	}
	if u, err := users.GetByID(context.Background(), "u-alice"); err == nil && u != nil {
		t.Error("account still present after erase")
	}
}

func TestMyAccountErase_RequiresBearer(t *testing.T) {
	srv, _, _ := newAccountEraseHarness(t, true)
	if code, _ := postErase(t, srv, "", map[string]any{"confirm": "u-alice"}); code != http.StatusUnauthorized {
		t.Errorf("no bearer = %d, want 401", code)
	}
}

func TestMyAccountErase_NotMountedWithoutEraser(t *testing.T) {
	srv, _, loginAs := newAccountEraseHarness(t, false)
	if code, _ := postErase(t, srv, loginAs(), map[string]any{"confirm": "u-alice"}); code != http.StatusNotFound {
		t.Errorf("without eraser = %d, want 404 (unmounted)", code)
	}
}
