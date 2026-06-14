package ssotest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestPRM_ChallengeOnResource401: a 401 from a protected resource (/me) carries
// the RFC 9728 §5.1 resource_metadata parameter pointing at the PRM document
// when PRM is enabled, so a client can discover the AS from the challenge.
func TestPRM_ChallengeOnResource401(t *testing.T) {
	srv := newPRMServer(t, true, sso.ProtectedResourceMetadata{})
	// /me requires a UserProvider (wired) — an unauthenticated GET 401s.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/me", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	wantURL := srv.URL + "/.well-known/oauth-protected-resource"
	if !strings.Contains(wa, `resource_metadata=`) || !strings.Contains(wa, wantURL) {
		t.Errorf("WWW-Authenticate = %q, want resource_metadata pointing at %s", wa, wantURL)
	}
}

// TestPRM_NoChallengeParamWhenDisabled: without PRM, the 401 challenge carries
// no resource_metadata parameter (byte-identical to before).
func TestPRM_NoChallengeParamWhenDisabled(t *testing.T) {
	srv := newPRMServer(t, false, sso.ProtectedResourceMetadata{})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/me", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if wa := resp.Header.Get("WWW-Authenticate"); strings.Contains(wa, "resource_metadata") {
		t.Errorf("WWW-Authenticate = %q, want no resource_metadata when PRM disabled", wa)
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
