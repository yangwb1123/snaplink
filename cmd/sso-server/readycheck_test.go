package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/config"
)

// TestAppendReadyCheck_MemoryNoOps proves the type-assertion gate
// holds for memory-backed stores. Plain map-backed stores do not
// implement Ping(ctx) — the helper must skip them silently rather
// than register a check that would always fail.
func TestAppendReadyCheck_MemoryNoOps(t *testing.T) {
	memStore := struct{}{}
	opts := appendReadyCheck(nil, "noop", memStore)
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
	opts := appendReadyCheck(nil, "sqlite-stub", candidate)
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
	defer a.registry.Close()

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
