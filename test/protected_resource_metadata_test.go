package ssotest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newPRMServer(t *testing.T, enabled bool, prm sso.ProtectedResourceMetadata) *httptest.Server {
	t.Helper()
	opts := []sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if enabled {
		opts = append(opts, sso.WithProtectedResourceMetadata(prm))
	}
	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

func getPRM(t *testing.T, baseURL string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(baseURL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET prm: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestPRM_DerivedDefaults: with no overrides the doc derives resource (base
// URL), authorization_servers ([issuer]), jwks_uri, and bearer methods.
func TestPRM_DerivedDefaults(t *testing.T) {
	srv := newPRMServer(t, true, sso.ProtectedResourceMetadata{})
	status, body := getPRM(t, srv.URL)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["resource"] != srv.URL {
		t.Errorf("resource=%v, want %s", body["resource"], srv.URL)
	}
	as, _ := body["authorization_servers"].([]any)
	if len(as) != 1 || as[0] != "https://sso.example" {
		t.Errorf("authorization_servers=%v, want [https://sso.example]", body["authorization_servers"])
	}
	if body["jwks_uri"] != srv.URL+"/.well-known/jwks.json" {
		t.Errorf("jwks_uri=%v", body["jwks_uri"])
	}
	bm, _ := body["bearer_methods_supported"].([]any)
	if len(bm) != 1 || bm[0] != "header" {
		t.Errorf("bearer_methods_supported=%v, want [header]", body["bearer_methods_supported"])
	}
}

// TestPRM_Overrides: operator overrides win over derived defaults.
func TestPRM_Overrides(t *testing.T) {
	srv := newPRMServer(t, true, sso.ProtectedResourceMetadata{
		Resource:             "https://api.example/mcp",
		AuthorizationServers: []string{"https://as1.example", "https://as2.example"},
		ResourceName:         "Acme MCP API",
	})
	_, body := getPRM(t, srv.URL)
	if body["resource"] != "https://api.example/mcp" {
		t.Errorf("resource=%v", body["resource"])
	}
	as, _ := body["authorization_servers"].([]any)
	if len(as) != 2 {
		t.Errorf("authorization_servers=%v, want 2", body["authorization_servers"])
	}
	if body["resource_name"] != "Acme MCP API" {
		t.Errorf("resource_name=%v", body["resource_name"])
	}
}

// TestPRM_NotMountedWhenDisabled: the route is absent (404) when not wired.
func TestPRM_NotMountedWhenDisabled(t *testing.T) {
	srv := newPRMServer(t, false, sso.ProtectedResourceMetadata{})
	status, _ := getPRM(t, srv.URL)
	if status != http.StatusNotFound {
		t.Errorf("status=%d, want 404 when not wired", status)
	}
}
