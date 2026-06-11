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
	defer resp.Body.Close()
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
