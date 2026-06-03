package redis

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLimiter_UnderAndOverLimit(t *testing.T) {
	mr, rdb := newTestClient(t)
	_ = mr
	lim := NewLimiter(rdb, 3, time.Minute, "login")

	// First 3 requests in the window are admitted.
	for i := 0; i < 3; i++ {
		ok, retry := lim.Allow("1.2.3.4")
		if !ok {
			t.Fatalf("request %d under the limit must be allowed", i+1)
		}
		if retry != 0 {
			t.Fatalf("request %d under the limit must have zero retry-after, got %v", i+1, retry)
		}
	}
	// 4th exceeds the limit.
	ok, retry := lim.Allow("1.2.3.4")
	if ok {
		t.Fatal("4th request over the limit must be denied")
	}
	if retry <= 0 {
		t.Fatalf("denied request must carry a positive retry-after, got %v", retry)
	}
	if retry > time.Minute {
		t.Fatalf("retry-after must not exceed the window, got %v", retry)
	}
}

func TestLimiter_PerKeyIsolation(t *testing.T) {
	_, rdb := newTestClient(t)
	lim := NewLimiter(rdb, 1, time.Minute, "")

	if ok, _ := lim.Allow("ip-a"); !ok {
		t.Fatal("first hit for ip-a must be allowed")
	}
	if ok, _ := lim.Allow("ip-a"); ok {
		t.Fatal("second hit for ip-a must be denied")
	}
	// A different key has its own counter.
	if ok, _ := lim.Allow("ip-b"); !ok {
		t.Fatal("first hit for ip-b must be allowed (separate counter)")
	}
}

func TestLimiter_WindowResetAfterTTL(t *testing.T) {
	mr, rdb := newTestClient(t)
	lim := NewLimiter(rdb, 2, 10*time.Second, "")

	for i := 0; i < 2; i++ {
		if ok, _ := lim.Allow("k"); !ok {
			t.Fatalf("hit %d must be allowed", i+1)
		}
	}
	if ok, _ := lim.Allow("k"); ok {
		t.Fatal("3rd hit must be denied within the window")
	}

	// Advance miniredis past the window so the counter key expires; the
	// next hit opens a fresh window.
	mr.FastForward(11 * time.Second)

	if ok, _ := lim.Allow("k"); !ok {
		t.Fatal("hit after the window TTL must be allowed (window reset)")
	}
}

func TestLimiter_ConcurrentIncrSingleCounter(t *testing.T) {
	_, rdb := newTestClient(t)
	const limit = 50
	lim := NewLimiter(rdb, limit, time.Minute, "")

	const goroutines = 200
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if ok, _ := lim.Allow("hot"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// INCR is atomic, so EXACTLY limit requests must be admitted — no
	// over-count from a lost update, no under-count from a double-decrement.
	if allowed != limit {
		t.Fatalf("concurrent INCR must admit exactly %d, got %d", limit, allowed)
	}
}

func TestLimiter_DenyAllFromRate(t *testing.T) {
	_, rdb := newTestClient(t)
	// perSecond<=0 yields a deny-all limiter (mirrors the token-bucket
	// peers configured to never refill).
	lim := NewLimiterFromRate(rdb, 0, 5, "")
	if ok, _ := lim.Allow("k"); !ok {
		t.Fatal("first hit fills the single allowance")
	}
	if ok, _ := lim.Allow("k"); ok {
		t.Fatal("deny-all limiter must reject the second hit")
	}
}

func TestLimiter_FromRateWindow(t *testing.T) {
	_, rdb := newTestClient(t)
	// 10 req/s, burst 10 => window 1s, limit 10.
	lim := NewLimiterFromRate(rdb, 10, 10, "")
	for i := 0; i < 10; i++ {
		if ok, _ := lim.Allow("k"); !ok {
			t.Fatalf("hit %d within burst must be allowed", i+1)
		}
	}
	if ok, _ := lim.Allow("k"); ok {
		t.Fatal("hit past the burst must be denied")
	}
}

func TestLimiter_Ping(t *testing.T) {
	_, rdb := newTestClient(t)
	lim := NewLimiter(rdb, 1, time.Second, "")
	if err := lim.Ping(context.Background()); err != nil {
		t.Fatalf("Ping on a live miniredis must succeed: %v", err)
	}
	var nilStore *Limiter
	if err := nilStore.Ping(context.Background()); err == nil {
		t.Fatal("Ping on a nil store must error, not panic")
	}
}
