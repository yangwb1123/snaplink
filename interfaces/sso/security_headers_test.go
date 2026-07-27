package sso_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/handler"
)

// shNewServer builds the minimal Server the security-headers tests need:
// enough wiring for Handler() to route /health and POST /logout — nothing else.
func shNewServer(extra ...sso.Option) *sso.Server {
	opts := []sso.Option{
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
	}
	opts = append(opts, extra...)
	return sso.NewServer(opts...)
}

func TestSecurityHeaders_OffByDefault(t *testing.T) {
	t.Parallel()
	h := shNewServer().Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	for _, name := range []string{"Content-Security-Policy", "Permissions-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("%s = %q, want unset (feature is off by default)", name, got)
		}
	}
}

func TestSecurityHeaders_EnabledOnRouterEndpoint(t *testing.T) {
	t.Parallel()
	h := shNewServer(sso.WithSecurityHeaders()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'nonce-") {
		t.Errorf("Content-Security-Policy = %q, want a script-src nonce", csp)
	}
	if pp := rec.Header().Get("Permissions-Policy"); pp == "" {
		t.Error("Permissions-Policy not set")
	}
}

func TestSecurityHeaders_ProbeEndpointsStayHeaderFree(t *testing.T) {
	t.Parallel()
	h := shNewServer(sso.WithSecurityHeaders()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, sso.PathLivez, nil))

	if csp := rec.Header().Get("Content-Security-Policy"); csp != "" {
		t.Errorf("/livez must stay outside the security-headers middleware, got CSP=%q", csp)
	}
}


func TestSecurityHeadersPolicy_OverridesCSPDirectives(t *testing.T) {
	t.Parallel()
	h := shNewServer(sso.WithSecurityHeadersPolicy(handler.SecurityHeadersPolicy{
		CSPDirectives: []string{"default-src 'none'", "script-src 'self'"},
	})).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("Content-Security-Policy = %q, want the operator-supplied directive", csp)
	}
}

func TestClearSiteData_OnLogout(t *testing.T) {
	t.Parallel()
	sessMgr := defaultimpl.NewMemorySessionManager()
	sess, err := sessMgr.Create(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	srv := shNewServer(sso.WithSecurityHeaders(), sso.WithSessionManager(sessMgr))

	body := strings.NewReader(`{"session_id":"` + sess.ID + `"}`)
	req := httptest.NewRequest(http.MethodPost, sso.PathLogout, body)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /logout status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Clear-Site-Data"); got != `"cache", "cookies", "storage"` {
		t.Errorf("Clear-Site-Data = %q", got)
	}
}

func TestClearSiteData_AbsentWhenSecurityHeadersOff(t *testing.T) {
	t.Parallel()
	sessMgr := defaultimpl.NewMemorySessionManager()
	sess, err := sessMgr.Create(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	srv := shNewServer(sso.WithSessionManager(sessMgr))

	body := strings.NewReader(`{"session_id":"` + sess.ID + `"}`)
	req := httptest.NewRequest(http.MethodPost, sso.PathLogout, body)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /logout status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Clear-Site-Data"); got != "" {
		t.Errorf("Clear-Site-Data = %q, want unset (feature off)", got)
	}
}
