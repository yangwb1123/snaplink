package sso_test

// scope_count_cap_test.go covers WithMaxScopeCount end-to-end through
// POST /auth/login: the gate lives in preAuthLoginGates (before the
// credential stage), so an over-cap request must be rejected with the
// standard invalid_scope wire code without ever reaching Authenticate.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func newScopeCapTestServer(t *testing.T, opts ...sso.Option) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "rp", Secret: "s", RedirectURIs: []string{"https://rp.test/cb"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true,
	})
	base := []sso.Option{
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	srv := sso.NewServer(append(base, opts...)...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func postLogin(t *testing.T, url string, scopes []string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "rp",
		"scope":      scopes,
		"credential": map[string]string{"username": "u", "password": "p"},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(url+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("post /auth/login: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestLogin_ScopeCountCap_Exceeded proves an over-cap scope list is rejected
// with 400 invalid_scope before the credential stage runs (an unregistered
// "password" authenticator would otherwise surface a DIFFERENT failure —
// getting invalid_scope back proves the pre-auth gate fired first).
func TestLogin_ScopeCountCap_Exceeded(t *testing.T) {
	t.Parallel()
	httpSrv := newScopeCapTestServer(t, sso.WithMaxScopeCount(2))
	status, out := postLogin(t, httpSrv.URL, []string{"a", "b", "c"})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%v)", status, out)
	}
	if out["error"] != "invalid_scope" {
		t.Fatalf("error = %v, want invalid_scope", out["error"])
	}
}

// TestLogin_ScopeCountCap_WithinLimit proves a request at-or-under the cap
// passes the gate (reaches the credential stage — here failing on the
// unregistered authenticator, NOT on invalid_scope).
func TestLogin_ScopeCountCap_WithinLimit(t *testing.T) {
	t.Parallel()
	httpSrv := newScopeCapTestServer(t, sso.WithMaxScopeCount(3))
	status, out := postLogin(t, httpSrv.URL, []string{"a", "b", "c"})
	if out["error"] == "invalid_scope" {
		t.Fatalf("at-cap request incorrectly rejected as invalid_scope (status=%d body=%v)", status, out)
	}
}

// TestLogin_ScopeCountCap_UnsetUnbounded proves the default (option never
// wired) leaves the scope count completely unbounded — byte-identical to a
// build without this feature.
func TestLogin_ScopeCountCap_UnsetUnbounded(t *testing.T) {
	t.Parallel()
	httpSrv := newScopeCapTestServer(t)
	many := make([]string, 200)
	for i := range many {
		many[i] = "s"
	}
	status, out := postLogin(t, httpSrv.URL, many)
	if out["error"] == "invalid_scope" {
		t.Fatalf("unset MaxScopeCount incorrectly enforced a cap (status=%d body=%v)", status, out)
	}
}
