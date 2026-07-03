package degradation

import (
	"net/http"
	"testing"
)

// testPolicy mirrors the endpoint sets the delivery layer wires from
// shared/core's path table, so the decision table below is exercised against
// realistic paths.
func testPolicy() Policy {
	return Policy{
		ProbePaths:     []string{"/livez", "/readyz", "/metrics"},
		ReadOnlyExempt: []string{"/token", "/token/introspect"},
		AuthOnlyAllow:  []string{"/auth/", "/token", "/.well-known/"},
		LocalOnlyBlock: []string{"/ssf/receive", "/fetch", "/auth/home-realm"},
	}
}

func TestPolicy_Allow(t *testing.T) {
	p := testPolicy()
	cases := []struct {
		name   string
		mode   Mode
		method string
		path   string
		want   bool
	}{
		// Probes always pass, even in maintenance.
		{"probe livez maintenance", ModeMaintenance, http.MethodGet, "/livez", true},
		{"probe metrics maintenance", ModeMaintenance, http.MethodGet, "/metrics", true},

		// Normal permits everything.
		{"normal admin write", ModeNormal, http.MethodPost, "/api/v1/admin/clients", true},

		// read_only: reads pass, mutations blocked except the token plane.
		{"readonly GET userinfo", ModeReadOnly, http.MethodGet, "/userinfo", true},
		{"readonly POST token", ModeReadOnly, http.MethodPost, "/token", true},
		{"readonly POST introspect", ModeReadOnly, http.MethodPost, "/token/introspect", true},
		{"readonly POST revoke blocked", ModeReadOnly, http.MethodPost, "/token/revoke", false},
		{"readonly POST admin blocked", ModeReadOnly, http.MethodPost, "/api/v1/admin/clients", false},
		{"readonly POST login blocked", ModeReadOnly, http.MethodPost, "/auth/login", false},

		// auth_only: only the auth + token + discovery plane.
		{"authonly POST login", ModeAuthOnly, http.MethodPost, "/auth/login", true},
		{"authonly POST mfa", ModeAuthOnly, http.MethodPost, "/auth/mfa", true},
		{"authonly POST token", ModeAuthOnly, http.MethodPost, "/token", true},
		{"authonly GET jwks", ModeAuthOnly, http.MethodGet, "/.well-known/jwks.json", true},
		{"authonly GET admin blocked", ModeAuthOnly, http.MethodGet, "/api/v1/admin/tokens", false},
		{"authonly POST scim blocked", ModeAuthOnly, http.MethodPost, "/api/v1/scim/v2/Users", false},
		{"authonly GET userinfo blocked", ModeAuthOnly, http.MethodGet, "/userinfo", false},
		{"authonly GET me blocked", ModeAuthOnly, http.MethodGet, "/me", false},

		// local_only: remote-dependent endpoints blocked, everything else served.
		{"localonly POST login allowed", ModeLocalOnly, http.MethodPost, "/auth/login", true},
		{"localonly GET admin allowed", ModeLocalOnly, http.MethodGet, "/api/v1/admin/clients", true},
		{"localonly POST ssf blocked", ModeLocalOnly, http.MethodPost, "/ssf/receive", false},
		{"localonly GET fetch blocked", ModeLocalOnly, http.MethodGet, "/fetch", false},
		{"localonly GET home-realm blocked", ModeLocalOnly, http.MethodGet, "/auth/home-realm", false},
	}
	for _, tc := range cases {
		if got := p.Allow(tc.mode, tc.method, tc.path); got != tc.want {
			t.Errorf("%s: Allow(%q, %s, %s) = %v, want %v", tc.name, tc.mode, tc.method, tc.path, got, tc.want)
		}
	}
}

// TestPolicy_UnknownModeFailsOpen guards the invariant that a mode the decision
// function does not recognize never sheds traffic.
func TestPolicy_UnknownModeFailsOpen(t *testing.T) {
	if !testPolicy().Allow("future_mode", http.MethodPost, "/api/v1/admin/clients") {
		t.Fatal("unknown mode must fail open (permit)")
	}
}
