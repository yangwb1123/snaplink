package ssotest

import "github.com/yangwb1123/snaplink/shared/spi"

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// fakeContext is a stand-alone HandlerContext for unit-testing middleware
// without standing up a Server + Router.
type fakeContext struct {
	r       *http.Request
	w       http.ResponseWriter
	jsonCb  func(code int, v any)
	jsonHit bool
	code    int
	body    any
	store   map[string]any
	aborted bool
}

func newFake(method, url string) *fakeContext {
	r := httptest.NewRequest(method, url, nil)
	return &fakeContext{
		r:     r,
		w:     httptest.NewRecorder(),
		store: map[string]any{},
	}
}

func (c *fakeContext) Request() *http.Request              { return c.r }
func (c *fakeContext) ResponseWriter() http.ResponseWriter { return c.w }
func (c *fakeContext) Param(string) string                 { return "" }
func (c *fakeContext) Query(string) string                 { return "" }
func (c *fakeContext) Bind(any) error                      { return errors.New("no body") }
func (c *fakeContext) JSON(code int, v any) {
	c.jsonHit = true
	c.code = code
	c.body = v
	// A JSON write from Auth/CORS is a terminal response: the chain must
	// stop, matching the real contexts' abort-after-write contract.
	c.aborted = true
	if c.jsonCb != nil {
		c.jsonCb(code, v)
	}
}
func (c *fakeContext) Redirect(int, string)                    {}
func (c *fakeContext) Set(k string, v any)                     { c.store[k] = v }
func (c *fakeContext) Get(k string) any                        { return c.store[k] }
func (c *fakeContext) Abort()                                  { c.aborted = true }
func (c *fakeContext) Aborted() bool                           { return c.aborted }
func (c *fakeContext) Written() bool                           { return c.jsonHit }
func (c *fakeContext) SetResponseWriter(w http.ResponseWriter) { c.w = w }

// ---------- AuthMiddleware ----------

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	issuer := defaultimpl.NewSessionTokenIssuer()
	mw := sso.AuthMiddleware(issuer)

	ctx := newFake(http.MethodGet, "/secret")
	mw(ctx)
	if !ctx.jsonHit || ctx.code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", ctx.code)
	}
}

func TestAuthMiddleware_NonBearerScheme(t *testing.T) {
	issuer := defaultimpl.NewSessionTokenIssuer()
	mw := sso.AuthMiddleware(issuer)

	ctx := newFake(http.MethodGet, "/secret")
	ctx.r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	mw(ctx)
	if !ctx.jsonHit || ctx.code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 (non-bearer scheme)", ctx.code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	issuer := defaultimpl.NewSessionTokenIssuer()
	mw := sso.AuthMiddleware(issuer)

	ctx := newFake(http.MethodGet, "/secret")
	ctx.r.Header.Set("Authorization", "Bearer not-a-real-token")
	mw(ctx)
	if !ctx.jsonHit || ctx.code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 (invalid token)", ctx.code)
	}
}

func TestAuthMiddleware_ValidTokenPasses(t *testing.T) {
	issuer := defaultimpl.NewSessionTokenIssuer()
	tok, err := issuer.Issue(context.Background(), &sso.Subject{ID: "u-1"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mw := sso.AuthMiddleware(issuer)

	ctx := newFake(http.MethodGet, "/secret")
	ctx.r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	mw(ctx)
	if ctx.jsonHit {
		t.Errorf("AuthMiddleware should NOT short-circuit for a valid token; got code=%d body=%v", ctx.code, ctx.body)
	}
}

// ---------- CORS (legacy) ----------

func TestCORS_AllowedOriginMatched(t *testing.T) {
	mw := sso.CORS([]string{"https://app.example.com"})
	ctx := newFake(http.MethodGet, "/x")
	ctx.r.Header.Set("Origin", "https://app.example.com")
	mw(ctx)
	if got := ctx.w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestCORS_WildcardOrigin(t *testing.T) {
	mw := sso.CORS([]string{"*"})
	ctx := newFake(http.MethodGet, "/x")
	ctx.r.Header.Set("Origin", "https://anything.example")
	mw(ctx)
	if got := ctx.w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestCORS_DisallowedOriginNoHeader(t *testing.T) {
	mw := sso.CORS([]string{"https://app.example.com"})
	ctx := newFake(http.MethodGet, "/x")
	ctx.r.Header.Set("Origin", "https://attacker.com")
	mw(ctx)
	if got := ctx.w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin echoed back: %q", got)
	}
}

func TestCORS_PreflightShortCircuits(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/preflight", nil)
	r.Header.Set("Origin", "*")
	mw := sso.CORS([]string{"*"})

	ctx := &fakeContext{r: r, w: rec, store: map[string]any{}}
	mw(ctx)
	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight code = %d, want 204", rec.Code)
	}
}

// ---------- LoggerMiddleware ----------

type captureLogger struct {
	infos []logEntry
}
type logEntry struct {
	msg string
	kvs []any
}

func (c *captureLogger) Info(msg string, kvs ...any)  { c.infos = append(c.infos, logEntry{msg, kvs}) }
func (c *captureLogger) Error(msg string, kvs ...any) {}
func (c *captureLogger) Debug(msg string, kvs ...any) {}

func TestLoggerMiddleware_LogsMethodAndPath(t *testing.T) {
	log := &captureLogger{}
	mw := sso.LoggerMiddleware(log)
	ctx := newFake(http.MethodPost, "/login")
	mw(ctx)
	if len(log.infos) != 1 {
		t.Fatalf("got %d log calls, want 1", len(log.infos))
	}
	entry := log.infos[0]
	if entry.msg != "request" {
		t.Errorf("msg = %q", entry.msg)
	}
	// kvs come as flat key-value pairs.
	got := flattenKVs(entry.kvs)
	if got["method"] != http.MethodPost {
		t.Errorf("method = %v", got["method"])
	}
	if got["path"] != "/login" {
		t.Errorf("path = %v", got["path"])
	}
}

func TestNopLogger_DoesNotPanic(t *testing.T) {
	var l spi.Logger = spi.NopLogger{}
	l.Info("x", "k", "v")
	l.Error("x", "k", "v")
	l.Debug("x", "k", "v")
}

// ---------- CorrelationMiddleware (Decision 7) ----------

// TestCorrelationMiddleware_GeneratesRequestID proves the request-id
// contract without a provider: preserve incoming or generate a fresh
// 32-hex, stamped on both the response and the request header (audit +
// access-log RequestID source).
func TestCorrelationMiddleware_GeneratesRequestID(t *testing.T) {
	mw := sso.CorrelationMiddleware("test")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
	got := w.Header().Get("X-Request-Id")
	if got == "" {
		t.Fatal("X-Request-Id not set on response")
	}
	if len(got) != 32 { // 16 bytes -> 32 hex chars
		t.Errorf("X-Request-Id length = %d, want 32", len(got))
	}
	if r.Header.Get("X-Request-Id") != got {
		t.Errorf("request header id = %q, want response %q", r.Header.Get("X-Request-Id"), got)
	}
}

func TestCorrelationMiddleware_PreservesIncomingRequestID(t *testing.T) {
	mw := sso.CorrelationMiddleware("test")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Request-Id", "client-supplied-id")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
	if got := w.Header().Get("X-Request-Id"); got != "client-supplied-id" {
		t.Errorf("X-Request-Id = %q, want preserved", got)
	}
}

// TestCorrelationMiddleware_NoProvider_NoTraceHeaders pins the deliberate
// no-OTel contract (Decision 12): with the SDK no-op provider the span
// context is invalid, so X-Trace-Id and Traceparent are absent — the legacy
// middleware used to mint its own traceparent here, which is exactly the
// removed behavior (Decision 7).
func TestCorrelationMiddleware_NoProvider_NoTraceHeaders(t *testing.T) {
	mw := sso.CorrelationMiddleware("test")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
	if got := w.Header().Get("Traceparent"); got != "" {
		t.Errorf("Traceparent = %q, want absent without a provider", got)
	}
	if got := w.Header().Get("X-Trace-Id"); got != "" {
		t.Errorf("X-Trace-Id = %q, want absent without a provider", got)
	}
}

func TestCorrelationMiddleware_RequestIDsAreUnique(t *testing.T) {
	mw := sso.CorrelationMiddleware("test")
	seen := map[string]bool{}
	for range 20 {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
		id := w.Header().Get("X-Request-Id")
		if seen[id] {
			t.Fatalf("duplicate request id: %q", id)
		}
		seen[id] = true
	}
}

// ---------- helpers ----------

func flattenKVs(kvs []any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kvs); i += 2 {
		k, _ := kvs[i].(string)
		m[k] = kvs[i+1]
	}
	return m
}
