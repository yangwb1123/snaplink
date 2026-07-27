package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
)

func TestMemoryLimiter_AllowsBurstThenRejects(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestMemoryLimiter_DenyAllRateZero_RetryAfterIsZero(t *testing.T) {
	t.Parallel()
	// perSecond=0 + burst exhausted must deny with retryAfter=0 — the same
	// "no useful retry-after" contract SQLiteLimiter's consumeToken
	// documents for its denyAll branch (sqlite_limiter.go). Before the
	// fix, MemoryLimiter derived retryAfter from the underlying
	// rate.Reservation, whose Delay() reports a ~292-year InfDuration
	// sentinel for a zero rate instead of 0 — a backend-drift bug that
	// would surface as a multi-billion-second Retry-After header.
	lim := ratelimit.NewMemoryLimiter(0, 3)
	for i := range 3 {
		ok, _ := lim.Allow("k")
		if !ok {
			t.Fatalf("call %d denied within burst", i)
		}
	}
	ok, retry := lim.Allow("k")
	if ok {
		t.Fatal("4th call should be denied — burst exhausted, rate=0 never refills")
	}
	if retry != 0 {
		t.Fatalf("retry-after = %v, want 0 (denyAll, matching SQLiteLimiter peer)", retry)
	}
}

func TestMiddleware_NilPolicyIsIdentity(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestKeyByClientIP_IgnoresXFFWithoutTrustedProxies(t *testing.T) {
	t.Parallel()
	// Without TrustedProxies middleware, XFF must NOT be trusted — a client
	// can set any XFF value to forge their bucket key and bypass rate limiting.
	// KeyByClientIP must key on RemoteAddr (the TCP peer) in this case.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	if got := ratelimit.KeyByClientIP(r); got != "10.0.0.1" {
		t.Errorf("no TrustedProxies → RemoteAddr = %q, want 10.0.0.1 (XFF must not be trusted)", got)
	}
}

func TestKeyByClientIP_FallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.1:9999"
	if got := ratelimit.KeyByClientIP(r); got != "192.0.2.1" {
		t.Errorf("RemoteAddr fallback = %q, want 192.0.2.1", got)
	}
}

func TestKeyByClientIDOrIP_HonorsBasicAuthClientID(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.SetBasicAuth("acme-app", "secret")
	if got := ratelimit.KeyByClientIDOrIP(r); got != "client:acme-app" {
		t.Errorf("Basic-auth keying = %q, want client:acme-app", got)
	}
}

func TestKeyByClientIDOrIP_FallsBackToIPWithoutBasicAuth(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.RemoteAddr = "192.0.2.5:5555"
	if got := ratelimit.KeyByClientIDOrIP(r); got != "192.0.2.5" {
		t.Errorf("no Basic-auth → IP fallback = %q, want 192.0.2.5", got)
	}
}

func TestKeyByClientIDOrIP_DoesNotConsumeBody(t *testing.T) {
	t.Parallel()
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

func TestMemoryLimiter_PrunesSampled(t *testing.T) {
	t.Parallel()
	// Verify that pruning is NOT called on every Allow — only once per
	// 64 calls. Strategy: seed a bucket with an already-expired lastSeen,
	// then confirm the expired entry is cleaned up once the prune fires
	// on that same shard.
	//
	// pruneLocked only scans the shard of the key that triggered the
	// sampled prune event, not all shards. The seed key ("stale-25") and
	// the 64th probe key ("probe-62") both map to FNV-32a shard 12
	// (numShards=16), so the first prune event guaranteed hits the stale
	// entry's shard. The +1 seed offset means the global calls counter
	// first hits a multiple of 64 at probe iteration 62.
	lim := ratelimit.NewMemoryLimiterWithStalePrune(1e9, 1<<30, 1*time.Millisecond)

	// Seed one bucket under a key we will never touch again.
	// "stale-25" hashes to shard 12 (same as "probe-62").
	lim.Allow("stale-25")
	if lim.Buckets() != 1 {
		t.Fatal("expected 1 bucket after seed")
	}

	// Sleep past the stale horizon so the seeded bucket qualifies for pruning.
	time.Sleep(10 * time.Millisecond)

	// Drive Allow calls on rotating probe keys. "probe-62" maps to shard 12
	// and arrives when the global counter first hits 64 (seed=1, probe-0..62
	// add 63 more → total=64). That prune event scans shard 12, removes
	// the stale "stale-25" entry, and Buckets() drops below i+2.
	pruned := false
	for i := range 128 {
		lim.Allow("probe-" + strconv.Itoa(i))
		if lim.Buckets() < i+2 {
			// Stale bucket removed: total < seed + probes so far.
			pruned = true
			break
		}
	}
	if !pruned {
		t.Error("stale bucket was not pruned within 128 Allow calls")
	}
}

// TestMemoryLimiter_StartPrunerSweepsAllShards proves the background pruner
// cleans up stale entries across EVERY shard on its own — unlike the sampled
// inline prune (which only ever scans the ONE shard the sampled Allow call
// hashed to), a high-cardinality attack spread across many shards can't
// outrun it. No further Allow calls are made after seeding, so any cleanup
// observed must come from the background sweep, not the inline path.
func TestMemoryLimiter_StartPrunerSweepsAllShards(t *testing.T) {
	t.Parallel()
	lim := ratelimit.NewMemoryLimiterWithStalePrune(1e9, 1<<30, 1*time.Millisecond)

	// Seed one bucket per shard-ish key so entries spread across shards.
	for i := range 32 {
		lim.Allow("seed-" + strconv.Itoa(i))
	}
	if got := lim.Buckets(); got != 32 {
		t.Fatalf("Buckets() after seeding = %d, want 32", got)
	}

	time.Sleep(10 * time.Millisecond) // past the 1ms stale horizon

	lim.StartPruner(5 * time.Millisecond)
	defer func() { _ = lim.Close() }()

	deadline := time.Now().Add(2 * time.Second)
	for lim.Buckets() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("background pruner never cleared all shards, Buckets() = %d", lim.Buckets())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestMemoryLimiter_StartPrunerThenClose proves Close stops the background
// pruner cleanly and is safe to call even when StartPruner was never called.
func TestMemoryLimiter_StartPrunerThenClose(t *testing.T) {
	t.Parallel()
	lim := ratelimit.NewMemoryLimiter(1e9, 1<<30)
	lim.StartPruner(5 * time.Millisecond)
	if err := lim.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A limiter that never started a pruner must also Close cleanly.
	lim2 := ratelimit.NewMemoryLimiter(1e9, 1<<30)
	if err := lim2.Close(); err != nil {
		t.Fatalf("Close (no pruner started): %v", err)
	}
}

func TestKeyBySubject_UsesAuthenticatedSubject(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r = r.WithContext(middleware.WithSubject(r.Context(), "alice"))
	if got := ratelimit.KeyBySubject(r); got != "sub:alice" {
		t.Errorf("subject key = %q, want sub:alice", got)
	}
}

func TestKeyBySubject_FallsBackToIPWhenNoSubject(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	r.RemoteAddr = "192.0.2.7:8888"
	if got := ratelimit.KeyBySubject(r); got != "192.0.2.7" {
		t.Errorf("fallback = %q, want 192.0.2.7", got)
	}
}
