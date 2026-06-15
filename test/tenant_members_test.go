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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

func newTenantMembersHarness(t *testing.T) (*httptest.Server, sso.TenantUserStore, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "org-app", Secret: "s", Active: true,
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	store := defaultimpl.NewMemoryTenantUserStore()
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantUserStore(store),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	login := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "org-app",
			"credential": map[string]string{"username": "alice", "password": "x"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("no token: %s", raw)
		}
		return tok
	}
	return hs, store, login
}

func putJSON(t *testing.T, srv *httptest.Server, path string, body any) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestTenantMembers_AdminRosterAndSelfService(t *testing.T) {
	srv, store, login := newTenantMembersHarness(t)
	ctx := context.Background()

	// Admin adds alice to t1 as admin.
	if code := putJSON(t, srv, "/api/v1/admin/tenants/t1/members/u-alice", map[string]any{"role": "admin"}); code != http.StatusOK {
		t.Fatalf("admin PUT member status=%d", code)
	}
	// Roster lists her.
	code, body := doReq(t, srv, http.MethodGet, "/api/v1/admin/tenants/t1/members", "")
	if code != http.StatusOK {
		t.Fatalf("roster status=%d", code)
	}
	if list, _ := body["members"].([]any); len(list) != 1 {
		t.Fatalf("roster = %v, want 1", body)
	}
	// Upsert: re-PUT with a different role updates, not duplicates.
	_ = putJSON(t, srv, "/api/v1/admin/tenants/t1/members/u-alice", map[string]any{"role": "member"})
	if m, _ := store.Get(ctx, "t1", "u-alice"); m == nil || m.Role != sso.TenantRoleMember {
		t.Errorf("role not updated to member: %+v", m)
	}
	// Invalid role → 400.
	if code := putJSON(t, srv, "/api/v1/admin/tenants/t1/members/u-bob", map[string]any{"role": "owner"}); code != http.StatusBadRequest {
		t.Errorf("invalid role status=%d, want 400", code)
	}

	// Self-service: alice lists her orgs, then leaves t1.
	tok := login()
	sc, sbody := doReq(t, srv, http.MethodGet, "/me/organizations", tok)
	if sc != http.StatusOK {
		t.Fatalf("/me/organizations status=%d", sc)
	}
	if orgs, _ := sbody["organizations"].([]any); len(orgs) != 1 {
		t.Fatalf("my orgs = %v, want 1", sbody)
	}
	if lc, _ := doReq(t, srv, http.MethodDelete, "/me/organizations/t1", tok); lc != http.StatusNoContent {
		t.Fatalf("leave org status=%d, want 204", lc)
	}
	if _, err := store.Get(ctx, "t1", "u-alice"); !errors.Is(err, sso.ErrNoMembership) {
		t.Errorf("alice still a member after leaving: %v", err)
	}

	// Admin DELETE is idempotent (already gone).
	if code, _ := doReq(t, srv, http.MethodDelete, "/api/v1/admin/tenants/t1/members/u-alice", ""); code != http.StatusNoContent {
		t.Errorf("idempotent admin DELETE status=%d, want 204", code)
	}
}

func TestTenantMembers_NotMountedWithoutStore(t *testing.T) {
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	if code, _ := doReq(t, hs, http.MethodGet, "/api/v1/admin/tenants/t1/members", ""); code != http.StatusNotFound {
		t.Errorf("unmounted roster status=%d, want 404", code)
	}
}
