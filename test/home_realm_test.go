package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/defaultimpl"
)

func newHomeRealmServer(t *testing.T, withConnections bool) *httptest.Server {
	t.Helper()
	opts := []sso.Option{
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withConnections {
		store := connections.NewMemoryStore()
		_ = store.Upsert(context.Background(), &connections.Connection{
			ID: "acme-okta", TenantID: "acme", Type: connections.TypeOIDC,
			DisplayName: "Acme Okta", Domains: []string{"acme.com"}, Enabled: true,
			Config: map[string]string{"oidc_client_secret": "SHOULD-NOT-LEAK"},
		})
		opts = append(opts, sso.WithConnectionStore(store))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func postHomeRealm(t *testing.T, srv *httptest.Server, loginHint string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"login_hint": loginHint})
	resp, err := http.Post(srv.URL+"/auth/home-realm", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestHomeRealm_ResolvesAndHidesSecrets(t *testing.T) {
	srv := newHomeRealmServer(t, true)

	status, body := postHomeRealm(t, srv, "alice@acme.com")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["found"] != true || body["connection_id"] != "acme-okta" || body["tenant_id"] != "acme" {
		t.Errorf("resolve = %v", body)
	}
	if body["type"] != "oidc" || body["display_name"] != "Acme Okta" {
		t.Errorf("metadata = %v", body)
	}
	// The connection's Config (which can hold secrets) MUST NOT be returned.
	if _, leaked := body["config"]; leaked {
		t.Error("config leaked into the HRD response")
	}
	for k, v := range body {
		if s, ok := v.(string); ok && s == "SHOULD-NOT-LEAK" {
			t.Errorf("a secret leaked under key %q", k)
		}
	}

	// An unmatched domain -> found:false (a routing decision, not an error).
	status2, body2 := postHomeRealm(t, srv, "x@unknown.com")
	if status2 != http.StatusOK || body2["found"] != false {
		t.Errorf("unknown domain = %d / %v", status2, body2)
	}
}

func TestHomeRealm_NotMountedWithoutStore(t *testing.T) {
	srv := newHomeRealmServer(t, false)
	if status, _ := postHomeRealm(t, srv, "alice@acme.com"); status != http.StatusNotFound {
		t.Errorf("without WithConnectionStore the endpoint must be absent (404), got %d", status)
	}
}

func newHRLoginServer(t *testing.T, withConnections bool) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "app", Secret: "s", Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u"}, nil
		}))
	opts := []sso.Option{
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withConnections {
		store := connections.NewMemoryStore()
		_ = store.Upsert(context.Background(), &connections.Connection{
			ID: "acme-okta", TenantID: "acme", Type: connections.TypeOIDC,
			DisplayName: "Acme Okta", Domains: []string{"acme.com"}, Enabled: true,
		})
		opts = append(opts, sso.WithConnectionStore(store))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func loginNoProvider(t *testing.T, srv *httptest.Server, loginHint string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client_id": "app", "login_hint": loginHint})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// TestHomeRealm_LoginFlowDirective: at /auth/login with no provider, a login
// hint whose domain maps to a connection returns the federation directive
// instead of the generic provider list.
func TestHomeRealm_LoginFlowDirective(t *testing.T) {
	srv := newHRLoginServer(t, true)

	out := loginNoProvider(t, srv, "alice@acme.com")
	if out["connection_required"] != true || out["connection_id"] != "acme-okta" {
		t.Errorf("expected a connection_required directive, got %v", out)
	}
	if _, hasProviders := out["providers"]; hasProviders {
		t.Error("the connection directive should replace the provider list")
	}

	out2 := loginNoProvider(t, srv, "x@unknown.com")
	if _, ok := out2["connection_required"]; ok {
		t.Error("an unmatched email must not produce a connection directive")
	}
	if _, hasProviders := out2["providers"]; !hasProviders {
		t.Errorf("an unmatched email should return the provider list, got %v", out2)
	}
}

// TestHomeRealm_LoginFlowByteIdenticalWithoutStore: with no connection store
// wired, /auth/login provider discovery is unchanged (no directive).
func TestHomeRealm_LoginFlowByteIdenticalWithoutStore(t *testing.T) {
	out := loginNoProvider(t, newHRLoginServer(t, false), "alice@acme.com")
	if _, ok := out["connection_required"]; ok {
		t.Error("without WithConnectionStore there must be no connection directive")
	}
	if _, hasProviders := out["providers"]; !hasProviders {
		t.Errorf("the default should return the provider list, got %v", out)
	}
}
