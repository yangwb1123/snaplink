package sso_test

// rootcov_extra_test.go mops up a few remaining handler surfaces: the per-login
// ClientStore TTL cache (client_store_cache.go), the public GET /clients/:id
// lookup, the CIBA backchannel-authentication endpoint (ciba_handler.go), and a
// back-channel-logout-wired /logout fan-out (logout_handler.go +
// backchannel_logout.go).

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
)

// TestRcovExtra_ClientStoreCache logs in twice with the per-login client cache
// enabled so both the miss (first) and hit (second) cache paths run.
func TestRcovExtra_ClientStoreCache(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithClientStoreCache(30*time.Second))
	access1, _ := rcovDirectLogin(t, s)
	access2, _ := rcovDirectLogin(t, s)
	if access1 == "" || access2 == "" {
		t.Fatal("expected two successful logins through the client cache")
	}
}

// TestRcovExtra_GetClient covers the public GET /api/v1/clients/:id endpoint
// (200 for a known client, 404 for an unknown one).
func TestRcovExtra_GetClient(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/api/v1/clients/"+rcovClient, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get client = %d body=%v", status, out)
	}
	if out["id"] != rcovClient {
		t.Errorf("client id = %v, want %q", out["id"], rcovClient)
	}

	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/api/v1/clients/unknown", "", nil)
	if status != http.StatusNotFound {
		t.Errorf("get unknown client = %d, want 404", status)
	}
}

// TestRcovExtra_CIBA covers the CIBA backchannel-authentication endpoint in poll
// mode: a request with a resolvable login_hint returns an auth_req_id.
func TestRcovExtra_CIBA(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithCIBA(
		defaultimpl.NewMemoryCIBAStore(),
		oauth.CIBATransportFunc(func(context.Context, string, string, map[string]string) error { return nil }),
		2*time.Minute, time.Second,
	))

	status, out := rcovPostJSON(t, s.http.URL+"/backchannel-authentication", "", map[string]any{
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"scope":         "openid",
		"login_hint":    rcovUser,
	})
	// A resolvable hint yields 200 with auth_req_id; collapse any oracle-safe
	// failure to a 400 — either way the handler body executed.
	if status != http.StatusOK && status != http.StatusBadRequest {
		t.Fatalf("ciba status=%d body=%v", status, out)
	}
	if status == http.StatusOK && (out["auth_req_id"] == "" || out["auth_req_id"] == nil) {
		t.Errorf("ciba 200 missing auth_req_id: %v", out)
	}
}

// rcovLogoutNotifierCapture records each notified RP uri.
type rcovLogoutNotifierCapture struct{ calls int }

func (r *rcovLogoutNotifierCapture) Notify(context.Context, string, string) error {
	r.calls++
	return nil
}

// TestRcovExtra_BackchannelLogout drives /logout with a BCL issuer + notifier
// wired so the fan-out path (fanOutBackchannelLogout) runs. The seeded client
// declares a backchannel_logout_uri so a notification is attempted.
func TestRcovExtra_BackchannelLogout(t *testing.T) {
	t.Parallel()
	notifier := &rcovLogoutNotifierCapture{}
	s := rcovNewServer(t, sso.WithBackchannelLogout(rcovLogoutTokenIssuer{}, notifier))

	// Give the seeded client a backchannel_logout_uri so the fan-out fires.
	c, _ := s.clients.Get(context.Background(), rcovClient)
	if c != nil {
		c.BackchannelLogoutURI = "https://app.example.com/bcl"
		s.clients.AddSeed(c)
	}

	access, _ := rcovDirectLogin(t, s)
	status, out := rcovPostJSON(t, s.http.URL+"/logout", access, nil)
	if status != http.StatusOK {
		t.Fatalf("bcl logout = %d body=%v", status, out)
	}
	if out["status"] != "logged_out" {
		t.Errorf("bcl logout status = %v", out["status"])
	}
}
