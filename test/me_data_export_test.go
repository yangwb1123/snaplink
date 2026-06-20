package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/compliance"
)

func newDataExportHarness(t *testing.T, withExport bool) (*httptest.Server, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice", Email: "alice@example.com", Name: "Alice"})
	sessions := defaultimpl.NewMemorySessionManager()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "exp-app", Secret: "s", Name: "Export App",
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
	if withExport {
		opts = append(opts, sso.WithSelfServiceDataExport(&compliance.Exporter{Users: users, Sessions: sessions}))
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "exp-app",
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
	return hs, loginAs
}

func TestMyDataExport_ReturnsOwnBundle(t *testing.T) {
	srv, loginAs := newDataExportHarness(t, true)
	code, body := doReq(t, srv, http.MethodGet, "/me/data-export", loginAs())
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, body)
	}
	if body["subject"] != "u-alice" {
		t.Errorf("subject = %v, want u-alice", body["subject"])
	}
	data, _ := body["data"].(map[string]any)
	if data == nil {
		t.Fatalf("export has no data section: %v", body)
	}
	if u, _ := data["user"].(map[string]any); u == nil || u["id"] != "u-alice" {
		t.Errorf("export user section = %v, want id u-alice", data["user"])
	}
}

func TestMyDataExport_RequiresBearer(t *testing.T) {
	srv, _ := newDataExportHarness(t, true)
	if code, _ := doReq(t, srv, http.MethodGet, "/me/data-export", ""); code != http.StatusUnauthorized {
		t.Errorf("no bearer = %d, want 401", code)
	}
}

func TestMyDataExport_NotMountedWithoutExporter(t *testing.T) {
	srv, loginAs := newDataExportHarness(t, false)
	if code, _ := doReq(t, srv, http.MethodGet, "/me/data-export", loginAs()); code != http.StatusNotFound {
		t.Errorf("without exporter = %d, want 404 (unmounted)", code)
	}
}
