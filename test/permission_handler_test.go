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
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/permissions"
)

const (
	permsUserID = "u-perm-alice"
	permsClient = "perm-app"
)

func newPermHarness(t *testing.T, withProvider bool) (*httptest.Server, *audit.MemorySink, string) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("perm-test"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: permsUserID})
	sessions := defaultimpl.NewMemorySessionManager()

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: permsClient, Secret: "shh", Name: "Perms App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "pw" {
				return &sso.AuthResult{UserID: permsUserID}, nil
			}
			return nil, errors.New("bad")
		},
	))

	sink := audit.NewMemorySink(100)
	rec := audit.New(sink)

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(rec),
	}

	if withProvider {
		prov := permissions.NewMemoryProvider()
		ctx := context.Background()
		_ = prov.AddRole(ctx, permsClient, permissions.Role{
			Code: "admin", Name: "Admin", Permissions: []string{"user:*", "audit:read"},
		})
		_ = prov.AssignRoles(ctx, permsUserID, permsClient, []string{"admin"})
		_ = prov.SetMenus(ctx, permsClient, permissions.MenuTree{
			{ID: "m-users", Name: "Users", Path: "/users", Permission: "user:read"},
			{ID: "m-audit", Name: "Audit", Path: "/audit", Permission: "audit:read"},
		})
		opts = append(opts, sso.WithPermissionProvider(prov))
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Bake a fresh bearer for this test.
	loginBody, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  permsClient,
		"credential": map[string]string{"username": "alice", "password": "pw"},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json",
		bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var loginResp map[string]any
	_ = json.Unmarshal(raw, &loginResp)
	tok, _ := loginResp["access_token"].(string)
	if tok == "" {
		t.Fatalf("missing token in login response: %s", raw)
	}

	return httpSrv, sink, tok
}

func getWithBearer(t *testing.T, srv *httptest.Server, path, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// ---------- /permissions/me ----------

func TestMyPermissions_HappyPath(t *testing.T) {
	srv, sink, tok := newPermHarness(t, true)

	code, body := getWithBearer(t, srv, "/permissions/me?client_id="+permsClient, tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d body=%v", code, body)
	}
	perms, _ := body["permissions"].([]any)
	if len(perms) == 0 {
		t.Errorf("permissions empty: %v", body)
	}
	// Audit emission — one permission_query/success event.
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventPermissionQuery, Outcome: audit.OutcomeSuccess})
	if len(events) == 0 {
		t.Error("no permission_query/success audit event")
	}
}

func TestMyPermissions_AudFromTokenWhenNoQuery(t *testing.T) {
	// Token issued from the harness has no aud claim — so without
	// ?client_id the handler resolves clientID="" and returns empty.
	srv, _, tok := newPermHarness(t, true)
	code, body := getWithBearer(t, srv, "/permissions/me", tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body["client_id"] != "" {
		t.Errorf("client_id = %v, want '' (token has no aud)", body["client_id"])
	}
}

func TestMyPermissions_MissingBearer(t *testing.T) {
	srv, _, _ := newPermHarness(t, true)
	code, body := getWithBearer(t, srv, "/permissions/me", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%v", code, body)
	}
}

func TestMyPermissions_NoProviderConfigured(t *testing.T) {
	srv, _, tok := newPermHarness(t, false) // no WithPermissionProvider
	code, body := getWithBearer(t, srv, "/permissions/me?client_id="+permsClient, tok)
	if code != http.StatusNotImplemented {
		t.Fatalf("status = %d body=%v", code, body)
	}
	if body["error"] != "permission_provider_not_configured" {
		t.Errorf("error = %v", body["error"])
	}
}

// ---------- /roles/me ----------

func TestMyRoles_HappyPath(t *testing.T) {
	srv, _, tok := newPermHarness(t, true)
	code, body := getWithBearer(t, srv, "/roles/me?client_id="+permsClient, tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d body=%v", code, body)
	}
	roles, _ := body["roles"].([]any)
	if len(roles) != 1 {
		t.Errorf("roles len = %d, want 1", len(roles))
	}
}

func TestMyRoles_MissingBearer(t *testing.T) {
	srv, _, _ := newPermHarness(t, true)
	code, _ := getWithBearer(t, srv, "/roles/me", "")
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d", code)
	}
}

func TestMyRoles_NoProviderConfigured(t *testing.T) {
	srv, _, tok := newPermHarness(t, false)
	code, body := getWithBearer(t, srv, "/roles/me", tok)
	if code != http.StatusNotImplemented {
		t.Fatalf("status = %d body=%v", code, body)
	}
}

// ---------- /menus/me ----------

func TestMyMenus_HappyPath(t *testing.T) {
	srv, _, tok := newPermHarness(t, true)
	code, body := getWithBearer(t, srv, "/menus/me?client_id="+permsClient, tok)
	if code != http.StatusOK {
		t.Fatalf("status = %d body=%v", code, body)
	}
	menus, _ := body["menus"].([]any)
	// Both seeded menus are visible — admin has user:* and audit:read.
	if len(menus) != 2 {
		t.Errorf("menus len = %d, want 2", len(menus))
	}
}

func TestMyMenus_MissingBearer(t *testing.T) {
	srv, _, _ := newPermHarness(t, true)
	code, _ := getWithBearer(t, srv, "/menus/me", "")
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d", code)
	}
}

func TestMyMenus_NoProviderConfigured(t *testing.T) {
	srv, _, tok := newPermHarness(t, false)
	code, body := getWithBearer(t, srv, "/menus/me", tok)
	if code != http.StatusNotImplemented {
		t.Fatalf("status = %d body=%v", code, body)
	}
}

// ---------- WithEmbedPermissionsInLogin (resolvePermissionsForLogin) ----------

func TestEmbedPermissionsInLogin(t *testing.T) {
	// Wire a Server with embed-on-login + permission provider so the
	// /auth/login response includes roles/permissions/menus.
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("embed-test"),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-embed"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "embed-app", Secret: "x", Name: "Embed",
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-embed"}, nil
		},
	))
	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(context.Background(), "embed-app", permissions.Role{
		Code: "viewer", Name: "Viewer", Permissions: []string{"x:read"},
	})
	_ = prov.AssignRoles(context.Background(), "u-embed", "embed-app", []string{"viewer"})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithEmbedPermissionsInLogin(),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	loginBody, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "embed-app",
		"credential": map[string]string{"username": "x", "password": "y"},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)

	// Embedded fields should appear in the login response.
	if _, ok := out["roles"]; !ok {
		t.Errorf("roles not embedded in login response: %s", raw)
	}
	if _, ok := out["permissions"]; !ok {
		t.Errorf("permissions not embedded: %s", raw)
	}
}
