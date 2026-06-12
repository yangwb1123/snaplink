package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/ratelimit"
)

func TestMemoryLimiter_AllowsBurstThenRejects(t *testing.T) {
	// 1 token/sec, burst 3 — first three calls succeed, fourth rejected.
	lim := ratelimit.NewMemoryLimiter(1, 3)
	for i := range 3 {
		ok, _ := lim.Allow("k1")
		if !ok {
			t.Errorf("call %d denied within burst", i)
		}
	}
	ok, retry := lim.Allow("k1")
	if ok {
		t.Errorf("4th call should be denied")
	}
	if retry <= 0 {
		t.Errorf("retry-after should be positive on denial, got %v", retry)
	}
}

func TestMemoryLimiter_BucketsAreIndependent(t *testing.T) {
	lim := ratelimit.NewMemoryLimiter(1, 2)
	// Exhaust k1.
	_, _ = lim.Allow("k1")
	_, _ = lim.Allow("k1")
	if ok, _ := lim.Allow("k1"); ok {
		t.Errorf("k1 should be exhausted")
	}
	// k2 still has its full burst.
	if ok, _ := lim.Allow("k2"); !ok {
		t.Errorf("k2 should not be affected by k1 exhaustion")
	}
}

func TestMemoryLimiter_RetryAfterIsBounded(t *testing.T) {
	// rate 10/sec, burst 1 — second call rejected, retry ~100ms.
	lim := ratelimit.NewMemoryLimiter(10, 1)
	_, _ = lim.Allow("k")
	ok, retry := lim.Allow("k")
	if ok {
		t.Fatal("2nd call should be denied at rate=10/s burst=1")
	}
	if retry < 50*time.Millisecond || retry > 200*time.Millisecond {
		t.Errorf("retry-after = %v, want ~100ms", retry)
	}
}

func TestMiddleware_NilPolicyIsIdentity(t *testing.T) {
	// Empty Policy (no Default, no Prefixes) lets everything through.
	mw := ratelimit.Middleware(ratelimit.Policy{})
	called := 0
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))
	for range 5 {
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("call got %d, want 200", rec.Code)
		}
	}
	if called != 5 {
		t.Errorf("inner called %d times, want 5", called)
	}
}

func TestMiddleware_DefaultLimiterApplied(t *testing.T) {
	lim := ratelimit.NewMemoryLimiter(1, 2)
	mw := ratelimit.Middleware(ratelimit.Policy{
		Default: lim,
		Key:     func(_ *http.Request) string { return "fixed" },
	})
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	statuses := make([]int, 4)
	for i := range 4 {
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		statuses[i] = rec.Code
	}
	// Burst 2 → first two 200, last two 429.
	want := []int{200, 200, 429, 429}
	for i, s := range statuses {
		if s != want[i] {
			t.Errorf("call %d status = %d, want %d", i, s, want[i])
		}
	}
}

func TestMiddleware_PrefixRuleOverridesDefault(t *testing.T) {
	tight := ratelimit.NewMemoryLimiter(1, 1) // 1 then denied
	loose := ratelimit.NewMemoryLimiter(100, 100)

	mw := ratelimit.Middleware(ratelimit.Policy{
		Default: loose,
		Prefixes: []ratelimit.PrefixRule{
			{Prefix: "/auth/login", Limiter: tight},
		},
		Key: func(_ *http.Request) string { return "k" },
	})
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// /auth/login: tight bucket — 2nd call denied.
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/auth/login first = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("/auth/login second = %d, want 429", rec.Code)
	}
	// /health: loose bucket — still allowed.
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health = %d, want 200 (loose bucket)", rec.Code)
	}
}

func TestMiddleware_Returns429WithRetryAfter(t *testing.T) {
	mw := ratelimit.Middleware(ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(1, 1),
		Key:     func(_ *http.Request) string { return "k" },
	})
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Consume the burst.
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	// Next call rejected; verify headers + body.
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing on 429")
	}
	if rec.Body.String() != `{"error":"rate_limited"}` {
		t.Errorf("body = %q, want JSON error envelope", rec.Body.String())
	}
}

func TestKeyByClientIP_UsesValidatedIPWhenMiddlewarePresent(t *testing.T) {
	// When middleware.TrustedProxies is in the chain, KeyByClientIP
	// returns the validated real client IP stored in the request context
	// rather than reading the raw X-Forwarded-For header. Here the proxy
	// tier (10.0.0.1) is trusted and the real client (1.2.3.4) is the
	// first untrusted entry to its left.
	tp, err := middleware.NewTrustedProxies([]string{"10.0.0.0/8"}, 1)
	if err != nil {
		t.Fatalf("NewTrustedProxies: %v", err)
	}
	var got string
	h := tp.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = ratelimit.KeyByClientIP(r)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "1.2.3.4" {
		t.Errorf("validated IP = %q, want 1.2.3.4", got)
	}
}

func TestKeyByClientIP_WithoutMiddleware_FallsBackToRemoteAddr(t *testing.T) {
	// Without TrustedProxies middleware in the chain, KeyByClientIP does
	// NOT read the raw X-Forwarded-For header (which would be forgeable).
	// It falls back to r.RemoteAddr — the direct TCP peer — which is the
	// correct secure-by-default behavior behind a layer-4 load balancer
	// that does not inject XFF.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	if got := ratelimit.KeyByClientIP(r); got != "10.0.0.1" {
		t.Errorf("no middleware fallback = %q, want 10.0.0.1 (RemoteAddr)", got)
	}
}

func TestKeyByClientIP_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.1:9999"
	if got := ratelimit.KeyByClientIP(r); got != "192.0.2.1" {
		t.Errorf("RemoteAddr fallback = %q, want 192.0.2.1", got)
	}
}

func TestKeyByClientIDOrIP_HonorsBasicAuthClientID(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.SetBasicAuth("acme-app", "secret")
	if got := ratelimit.KeyByClientIDOrIP(r); got != "client:acme-app" {
		t.Errorf("Basic-auth keying = %q, want client:acme-app", got)
	}
}

func TestKeyByClientIDOrIP_FallsBackToIPWithoutBasicAuth(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.RemoteAddr = "192.0.2.5:5555"
	if got := ratelimit.KeyByClientIDOrIP(r); got != "192.0.2.5" {
		t.Errorf("no Basic-auth → IP fallback = %q, want 192.0.2.5", got)
	}
}

func TestKeyByClientIDOrIP_DoesNotConsumeBody(t *testing.T) {
	// Per-client keying MUST NOT read r.Body, or downstream handlers
	// can't parse it. Verify by setting a body and confirming it's
	// still readable end-to-end.
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("client_id=in-body&client_secret=x"))
	r.RemoteAddr = "10.0.0.2:5555"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_ = ratelimit.KeyByClientIDOrIP(r)

	buf := make([]byte, 64)
	n, _ := r.Body.Read(buf)
	if n == 0 {
		t.Fatal("KeyByClientIDOrIP consumed r.Body — downstream handlers will see empty input")
	}
}
