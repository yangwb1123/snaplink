package ssotest

import "github.com/yangwb1123/snaplink/shared/spi"

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if c.jsonCb != nil {
		c.jsonCb(code, v)
	}
}
func (c *fakeContext) Redirect(int, string) {}
func (c *fakeContext) Set(k string, v any)  { c.store[k] = v }
func (c *fakeContext) Get(k string) any     { return c.store[k] }

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

// ---------- TracingMiddleware ----------

func TestTracingMiddleware_GeneratesRequestID(t *testing.T) {
	mw := sso.TracingMiddleware()
	ctx := newFake(http.MethodGet, "/x")
	mw(ctx)
	got := ctx.w.Header().Get("X-Request-Id")
	if got == "" {
		t.Fatal("X-Request-Id not set on response")
	}
	if len(got) != 32 { // 16 bytes -> 32 hex chars
		t.Errorf("X-Request-Id length = %d, want 32", len(got))
	}
}

func TestTracingMiddleware_PreservesIncomingRequestID(t *testing.T) {
	mw := sso.TracingMiddleware()
	ctx := newFake(http.MethodGet, "/x")
	ctx.r.Header.Set("X-Request-Id", "client-supplied-id")
	mw(ctx)
	if got := ctx.w.Header().Get("X-Request-Id"); got != "client-supplied-id" {
		t.Errorf("X-Request-Id = %q, want preserved", got)
	}
}

func TestTracingMiddleware_StartsTraceparentWhenAbsent(t *testing.T) {
	mw := sso.TracingMiddleware()
	ctx := newFake(http.MethodGet, "/x")
	mw(ctx)
	if got := ctx.w.Header().Get("Traceparent"); got == "" {
		t.Error("Traceparent not set")
	}
}

func TestTracingMiddleware_PreservesIncomingTraceparent(t *testing.T) {
	mw := sso.TracingMiddleware()
	ctx := newFake(http.MethodGet, "/x")
	// W3C traceparent format: 00-<trace>-<span>-<flags>
	incoming := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	ctx.r.Header.Set("Traceparent", incoming)
	mw(ctx)
	out := ctx.w.Header().Get("Traceparent")
	// We don't preserve verbatim — middleware starts a child span and
	// emits a NEW traceparent. The trace-id field (segment 2) must
	// match the incoming one.
	gotParts := strings.Split(out, "-")
	wantParts := strings.Split(incoming, "-")
	if len(gotParts) != 4 || len(wantParts) != 4 {
		t.Fatalf("malformed traceparent: in=%q out=%q", incoming, out)
	}
	if gotParts[1] != wantParts[1] {
		t.Errorf("trace-id = %q, want %q", gotParts[1], wantParts[1])
	}
	if gotParts[2] == wantParts[2] {
		t.Errorf("span-id should be different (fresh child), got same as incoming: %q", gotParts[2])
	}
}

func TestTracingMiddleware_RequestIDsAreUnique(t *testing.T) {
	mw := sso.TracingMiddleware()
	seen := map[string]bool{}
	for range 20 {
		ctx := newFake(http.MethodGet, "/x")
		mw(ctx)
		id := ctx.w.Header().Get("X-Request-Id")
		if seen[id] {
			t.Fatalf("duplicate request id: %q", id)
		}
		seen[id] = true
	}
}

func TestRequestIDMiddleware_AliasOfTracing(t *testing.T) {
	mw := sso.RequestIDMiddleware()
	ctx := newFake(http.MethodGet, "/x")
	mw(ctx)
	if got := ctx.w.Header().Get("X-Request-Id"); got == "" {
		t.Error("RequestIDMiddleware (legacy alias) didn't set X-Request-Id")
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
