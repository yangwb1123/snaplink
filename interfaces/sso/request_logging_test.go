package sso_test

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// capturingDebugLogger records every Debug() call's fields so a test can
// assert on exactly what WithRequestLogging's middleware chose to log,
// without a mocking library — a real spi.Logger implementation, per repo
// convention.
type capturingDebugLogger struct {
	mu     sync.Mutex
	fields []any
}

func (l *capturingDebugLogger) Info(string, ...any)  {}
func (l *capturingDebugLogger) Error(string, ...any) {}
func (l *capturingDebugLogger) Debug(_ string, keysAndValues ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields = append(l.fields, keysAndValues...)
}

func (l *capturingDebugLogger) has(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, f := range l.fields {
		if s, ok := f.(string); ok && s == key {
			return true
		}
	}
	return false
}

// newRequestLoggingTestServer builds a minimal real Server (memory client
// store, client_credentials grant) wired with WithRequestLogging(logBodies),
// so a real /token round trip can be driven through the actual middleware
// chain (wrapInnerMiddlewares), not a unit call to the middleware alone.
func newRequestLoggingTestServer(t *testing.T, logBodies bool) (*httptest.Server, *capturingDebugLogger) {
	t.Helper()
	logger := &capturingDebugLogger{}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "rl-client", Secret: "rl-secret", Active: true,
		TokenStrategy: "jwt",
	})
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithLogger(logger),
		sso.WithRequestLogging(logBodies),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, logger
}

// tokenRequestBody drives a real client_credentials /token round trip so the
// middleware chain sees both a real request body and a real response body.
func tokenRequestBody(t *testing.T, hs *httptest.Server) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"rl-client"},
		"client_secret": {"rl-secret"},
	}
	resp, err := hs.Client().Post(hs.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	_ = resp.Body.Close()
}

// TestWithRequestLogging_LogBodiesTrue_IncludesBodies is the regression test
// for a bug where WithRequestLogging's logBodies parameter was silently
// discarded (the middleware was always invoked with bodies disabled,
// regardless of what the caller passed) — proves the parameter now actually
// reaches middleware.RequestLogger and bodies appear in the log fields.
func TestWithRequestLogging_LogBodiesTrue_IncludesBodies(t *testing.T) {
	hs, logger := newRequestLoggingTestServer(t, true)
	tokenRequestBody(t, hs)

	if !logger.has("request_body") {
		t.Error("logBodies=true: expected \"request_body\" field in debug log, got none")
	}
	if !logger.has("response_body") {
		t.Error("logBodies=true: expected \"response_body\" field in debug log, got none")
	}
}

// TestWithRequestLogging_LogBodiesFalse_OmitsBodies proves the flag's OFF
// side still works — a regression guard so a future fix can't flip the bug
// to "always logs bodies" instead of properly threading the parameter.
func TestWithRequestLogging_LogBodiesFalse_OmitsBodies(t *testing.T) {
	hs, logger := newRequestLoggingTestServer(t, false)
	tokenRequestBody(t, hs)

	if logger.has("request_body") {
		t.Error("logBodies=false: \"request_body\" field must be absent")
	}
	if logger.has("response_body") {
		t.Error("logBodies=false: \"response_body\" field must be absent")
	}
	// The request must still be logged (debugRequestLogging itself is on) —
	// just without bodies.
	if !logger.has("status") {
		t.Error("logBodies=false: request logging itself should still be active (\"status\" field missing)")
	}
}
