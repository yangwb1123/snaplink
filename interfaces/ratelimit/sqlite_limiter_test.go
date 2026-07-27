package ratelimit

import (
	"path/filepath"
	"testing"
	"time"
)

func newSQLiteLimiterForTest(t *testing.T, perSec float64, burst int) *SQLiteLimiter {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "rl.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	lim, err := NewSQLiteLimiter(dsn, perSec, burst, "")
	if err != nil {
		t.Fatalf("NewSQLiteLimiter: %v", err)
	}
	t.Cleanup(func() { _ = lim.Close() })
	return lim
}

func TestSQLiteLimiter_BurstAllowedThenDenied(t *testing.T) {
	t.Parallel()
	// Burst=3, rate=0/sec — exactly 3 requests succeed then deny.
	lim := newSQLiteLimiterForTest(t, 0, 3)
	for i := range 3 {
		ok, _ := lim.Allow("alice")
		if !ok {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	ok, _ := lim.Allow("alice")
	if ok {
		t.Fatal("4th request allowed past burst — bucket math wrong")
	}
}

func TestSQLiteLimiter_RefillAfterIdle(t *testing.T) {
	t.Parallel()
	// A controlled clock keeps DB or race-detector latency from becoming an
	// accidental refill before the immediate second request.
	lim := newSQLiteLimiterForTest(t, 10, 1)
	now := time.Unix(1_700_000_000, 0)
	lim.now = func() time.Time { return now }

	ok, _ := lim.Allow("alice")
	if !ok {
		t.Fatal("first request denied — bucket should start full")
	}
	// Immediately drained.
	ok, _ = lim.Allow("alice")
	if ok {
		t.Fatal("immediate second request allowed — refill should not have happened yet")
	}
	now = now.Add(110 * time.Millisecond)
	ok, _ = lim.Allow("alice")
	if !ok {
		t.Fatal("post-refill request denied — token did not refill")
	}
}

func TestSQLiteLimiter_RetryAfterIsPositiveOnDenial(t *testing.T) {
	t.Parallel()
	lim := newSQLiteLimiterForTest(t, 1, 1) // 1 token, refilling at 1/sec
	_, _ = lim.Allow("alice")
	_, retry := lim.Allow("alice")
	if retry <= 0 {
		t.Fatalf("Retry-After should be positive on denial, got %v", retry)
	}
	// Should be close to 1s (full token refill at 1/sec).
	if retry > 2*time.Second {
		t.Fatalf("Retry-After unreasonably high: %v (expected ~1s)", retry)
	}
}

func TestSQLiteLimiter_KeysIsolated(t *testing.T) {
	t.Parallel()
	lim := newSQLiteLimiterForTest(t, 0, 1)
	if ok, _ := lim.Allow("alice"); !ok {
		t.Fatal("alice first request denied")
	}
	// alice is drained.
	if ok, _ := lim.Allow("alice"); ok {
		t.Fatal("alice second request allowed")
	}
	// bob has his own bucket.
	if ok, _ := lim.Allow("bob"); !ok {
		t.Fatal("bob request denied by alice's bucket exhaustion")
	}
}

func TestSQLiteLimiter_BucketNamesIsolated(t *testing.T) {
	t.Parallel()
	// Two limiters sharing one DB but with distinct bucket_names
	// must not pollute each other's keys.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	limA, err := NewSQLiteLimiter(dsn, 0, 1, "login")
	if err != nil {
		t.Fatalf("limA: %v", err)
	}
	defer func() { _ = limA.Close() }()
	limB, err := NewSQLiteLimiter(dsn, 0, 1, "send-code")
	if err != nil {
		t.Fatalf("limB: %v", err)
	}
	defer func() { _ = limB.Close() }()

	if ok, _ := limA.Allow("alice"); !ok {
		t.Fatal("limA first call denied")
	}
	if ok, _ := limA.Allow("alice"); ok {
		t.Fatal("limA second call allowed — burst should be 1")
	}
	// limB shares the DB but has its own bucket_name scope.
	if ok, _ := limB.Allow("alice"); !ok {
		t.Fatal("limB denied — bucket_name scoping leaked across limiters")
	}
}

func TestSQLiteLimiter_CrossInstanceSharing(t *testing.T) {
	t.Parallel()
	// The whole point: a request that drained the bucket on
	// "replica A" must be visible to "replica B" before B grants
	// the next request.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	limA, err := NewSQLiteLimiter(dsn, 0, 1, "")
	if err != nil {
		t.Fatalf("limA: %v", err)
	}
	defer func() { _ = limA.Close() }()
	limB, err := NewSQLiteLimiter(dsn, 0, 1, "")
	if err != nil {
		t.Fatalf("limB: %v", err)
	}
	defer func() { _ = limB.Close() }()

	if ok, _ := limA.Allow("alice"); !ok {
		t.Fatal("limA first allow denied")
	}
	// B sees A's exhaustion.
	if ok, _ := limB.Allow("alice"); ok {
		t.Fatal("limB allowed — cross-replica defense broken (bucket not shared)")
	}
}

func TestSQLiteLimiter_BurstClampToOneWhenZero(t *testing.T) {
	t.Parallel()
	// Burst=0 must clamp to 1 — matches NewMemoryLimiter contract,
	// rate.NewLimiter would otherwise refuse every request.
	lim := newSQLiteLimiterForTest(t, 0, 0)
	if ok, _ := lim.Allow("alice"); !ok {
		t.Fatal("burst=0 → clamp to 1; first call should succeed")
	}
}

func TestSQLiteLimiter_DenyWhenRateAndBurstExhausted(t *testing.T) {
	t.Parallel()
	// perSecond=0 + burst exhausted → permanent deny, no useful
	// retry-after (would be infinity).
	lim := newSQLiteLimiterForTest(t, 0, 1)
	_, _ = lim.Allow("alice") // drain
	ok, retry := lim.Allow("alice")
	if ok {
		t.Fatal("exhausted bucket with rate=0 should deny")
	}
	if retry != 0 {
		t.Fatalf("Retry-After should be 0 when refill rate=0, got %v", retry)
	}
}
