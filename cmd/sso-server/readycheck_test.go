package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestAppendReadyCheck_MemoryNoOps proves the type-assertion gate
// holds for memory-backed stores. Plain map-backed stores do not
// implement Ping(ctx) — the helper must skip them silently rather
// than register a check that would always fail.
func TestAppendReadyCheck_MemoryNoOps(t *testing.T) {
	memStore := struct{}{}
	opts := serverbuildsign.AppendReadyCheck(nil, "noop", memStore)
	if len(opts) != 0 {
		t.Fatalf("memory candidate added %d opts; want 0", len(opts))
	}
}

// TestAppendReadyCheck_SQLitePings proves a Pinger-implementing
// candidate produces exactly one [sso.WithReadyCheck] option.
func TestAppendReadyCheck_SQLitePings(t *testing.T) {
	called := false
	candidate := pingerStub{fn: func(context.Context) error {
		called = true
		return nil
	}}
	opts := serverbuildsign.AppendReadyCheck(nil, "sqlite-stub", candidate)
	if len(opts) != 1 {
		t.Fatalf("Pinger candidate added %d opts; want 1", len(opts))
	}
	// Applying the option to a real server + invoking /readyz exercises
	// the registered Check, proving it routes through the candidate's
	// Ping method.
	srv := sso.NewServer(opts...)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz code = %d body=%s; want 200", rec.Code, rec.Body.String())
	}
	if !called {
		t.Fatal("registered ReadyCheck did not invoke candidate.Ping")
	}
}

// TestBuildApp_ReadyCheck_SQLiteFlipsTo503 is the end-to-end
// proof: a server wired against SQLite identity stores starts ready,
// then flips to 503 the moment any underlying DB stops pinging.
// This is the operational contract /readyz exists to satisfy — a
// pod with broken SQLite must be pulled from the LB.
func TestBuildApp_ReadyCheck_SQLiteFlipsTo503(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "identity.db") + "?_journal=WAL"
	cfg := &config.Config{}
	cfg.Identity = config.IdentityConfig{
		Backend: "sqlite",
		SQLite:  config.IdentitySQLiteConfig{DSN: dsn},
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	// Initial /readyz should report every sqlite check as "ok".
	rec1 := callReadyz(t, a)
	if rec1.Code != http.StatusOK {
		t.Fatalf("initial /readyz code = %d body=%s; want 200", rec1.Code, rec1.Body.String())
	}
	checks1 := decodeReadyz(t, rec1)
	for _, k := range []string{"sqlite-identity-clients", "sqlite-identity-users", "sqlite-identity-sessions"} {
		if checks1[k] != "ok" {
			t.Fatalf("initial check %q = %q; want ok", k, checks1[k])
		}
	}

	// Closing the ClientStore yanks its underlying *sql.DB. The next
	// Ping must error; /readyz must flip to 503 and surface the
	// failing check's name so operators know what broke.
	closer, ok := a.clientStore.(interface{ Close() error })
	if !ok {
		t.Fatal("sqlite client store does not implement Close — test setup bug")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close client store: %v", err)
	}

	rec2 := callReadyz(t, a)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-close /readyz code = %d body=%s; want 503", rec2.Code, rec2.Body.String())
	}
	checks2 := decodeReadyz(t, rec2)
	if v, present := checks2["sqlite-identity-clients"]; !present || v == "ok" {
		t.Fatalf("post-close clients check = %q present=%v; want non-ok value", v, present)
	}
}

func callReadyz(t *testing.T, a *app) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	a.server.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeReadyz(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /readyz: %v body=%s", err, rec.Body.String())
	}
	return body.Checks
}

type pingerStub struct {
	fn func(context.Context) error
}

func (p pingerStub) Ping(ctx context.Context) error {
	if p.fn == nil {
		return errors.New("pingerStub: no fn")
	}
	return p.fn(ctx)
}

// pingerLimiter is a ratelimit.Limiter that also implements Ping —
// mirrors the shape of *ratelimit.SQLiteLimiter so tests for the
// serverbuildsign.AppendRateLimitReadyChecks wiring don't need a real SQLite DSN.
type pingerLimiter struct{ pingerStub }

func (p pingerLimiter) Allow(_ string) (bool, time.Duration) { return true, 0 }

// TestSanitizeReadyCheckSuffix_Paths verifies the kebab conversion
// for the URL prefixes operators typically supply in YAML — these
// names surface in the /readyz payload so they need to stay
// readable, stable, and collision-resistant across rule sets.
func TestSanitizeReadyCheckSuffix_Paths(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/token", "token"},
		{"/token/revoke", "token-revoke"},
		{"/api/v1/admin/", "api-v1-admin"},
		{"", ""},
		{"///", ""},
		{"a.b_c", "a-b-c"},
		{"FOO/bar", "FOO-bar"},
	}
	for _, c := range cases {
		if got := serverbuildsign.SanitizeReadyCheckSuffix(c.in); got != c.want {
			t.Errorf("serverbuildsign.SanitizeReadyCheckSuffix(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// TestAppendRateLimitReadyChecks_MixedBackends proves the helper
// registers a Ready check for every Ping-implementing limiter (the
// SQLite case) and silently skips memory-backed peers. The
// resulting /readyz body MUST surface the SQLite limiters by their
// sanitized prefix name and MUST NOT surface the memory ones.
func TestAppendRateLimitReadyChecks_MixedBackends(t *testing.T) {
	okPing := func(context.Context) error { return nil }
	policy := ratelimit.Policy{
		Default: pingerLimiter{pingerStub: pingerStub{fn: okPing}}, // pretend-SQLite default
		Prefixes: []ratelimit.PrefixRule{
			{Prefix: "/token", Limiter: pingerLimiter{pingerStub: pingerStub{fn: okPing}}},
			{Prefix: "/par", Limiter: ratelimit.NewMemoryLimiter(1, 1)}, // memory, no Ping
			{Prefix: "/token/revoke", Limiter: pingerLimiter{pingerStub: pingerStub{fn: okPing}}},
		},
	}
	opts := serverbuildsign.AppendRateLimitReadyChecks(nil, policy)
	if got, want := len(opts), 3; got != want {
		t.Fatalf("serverbuildsign.AppendRateLimitReadyChecks returned %d opts; want %d (default + /token + /token/revoke)", got, want)
	}

	srv := sso.NewServer(opts...)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz code=%d body=%s; want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /readyz: %v body=%s", err, rec.Body.String())
	}
	for _, name := range []string{"sqlite-ratelimit-default", "sqlite-ratelimit-token", "sqlite-ratelimit-token-revoke"} {
		if got, ok := body.Checks[name]; !ok || got != "ok" {
			t.Errorf("check %q = %q present=%v; want ok / present", name, got, ok)
		}
	}
	for _, name := range []string{"sqlite-ratelimit-par"} {
		if _, ok := body.Checks[name]; ok {
			t.Errorf("memory limiter incorrectly registered: %q present in /readyz checks=%v", name, body.Checks)
		}
	}
}

// TestAppendRateLimitReadyChecks_EmptyPolicy proves the helper is a
// no-op when neither a Default nor any Prefixes are configured —
// guards against a startup regression that would register a stray
// failing check for an unwired rate limiter.
func TestAppendRateLimitReadyChecks_EmptyPolicy(t *testing.T) {
	opts := serverbuildsign.AppendRateLimitReadyChecks(nil, ratelimit.Policy{})
	if len(opts) != 0 {
		t.Fatalf("empty policy produced %d opts; want 0", len(opts))
	}
}
