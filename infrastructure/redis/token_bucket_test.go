package redis

import (
	"testing"
	"time"
)

// TestTokenBucketLimiter_BurstThenDrip proves the smoothing shape: burst
// tokens are admitted back-to-back, the next is denied, and after a refill
// delay (FastForward on the miniredis clock) admission resumes — no 2x
// fixed-window edge burst.
func TestTokenBucketLimiter_BurstThenDrip(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	l := NewTokenBucketLimiter(rdb, 10, 4, "test")
	key := "ip-1"

	// Burst: 4 admissions, 5th denied.
	for i := 0; i < 4; i++ {
		if ok, _ := l.Allow(key); !ok {
			t.Fatalf("admission %d denied within burst", i+1)
		}
	}
	if ok, retry := l.Allow(key); ok {
		t.Fatal("5th admission allowed; bucket must be empty after burst")
	} else if retry <= 0 {
		t.Fatalf("retryAfter = %v, want > 0", retry)
	}
	// Refill at rate 10/s against the SERVER clock (miniredis TIME is the
	// real wall clock; a real sleep is the honest way to advance it).
	// Deterministic under load: ANY sleep >= 400ms refills >= burst (4
	// tokens at 10/s), so after 500ms the bucket is guaranteed FULL again —
	// 4 admissions succeed, the 5th is denied. A shorter sleep cannot
	// happen, so no timing margin is asserted.
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 4; i++ {
		if ok, _ := l.Allow(key); !ok {
			t.Fatalf("admission %d denied after full refill", i+1)
		}
	}
	if ok, _ := l.Allow(key); ok {
		t.Fatal("5th admission allowed after refill — bucket must be empty again")
	}
}

// TestTokenBucketLimiter_KeysAreIsolated proves one key's exhaustion does
// not affect another key's bucket (no shared-state bug in the Lua state).
func TestTokenBucketLimiter_KeysAreIsolated(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	l := NewTokenBucketLimiter(rdb, 1, 2, "test")

	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a: admission 1 denied")
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a: admission 2 denied")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a: 3rd admission allowed")
	}
	// b has its own full bucket.
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b: admission denied (keys must be isolated)")
	}
}

// TestTokenBucketLimiter_BucketNamesAreIsolated proves separate bucketName
// keyspaces (one per Policy prefix rule) do not collide.
func TestTokenBucketLimiter_BucketNamesAreIsolated(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	l1 := NewTokenBucketLimiter(rdb, 1, 1, "login")
	l2 := NewTokenBucketLimiter(rdb, 1, 1, "token")

	if ok, _ := l1.Allow("k"); !ok {
		t.Fatal("l1 denied")
	}
	if ok, _ := l1.Allow("k"); ok {
		t.Fatal("l1 allowed twice (burst 1)")
	}
	if ok, _ := l2.Allow("k"); !ok {
		t.Fatal("l2 denied — bucket names must be independent keyspaces")
	}
}

// TestTokenBucketLimiter_IdleReset proves the idle TTL: after the bucket
// key expires untouched, the bucket is full again (the limiter's window
// reset, equivalent to the fixed-window peer).
func TestTokenBucketLimiter_IdleReset(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	l := NewTokenBucketLimiter(rdb, 1, 1, "test")
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("admission denied")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("admission allowed twice (burst 1)")
	}
	// The key's PX idle expiry IS advanced by FastForward (TTL machinery,
	// unlike TIME): after the idle TTL elapses untouched the bucket key is
	// gone and the next admission sees a fresh full bucket.
	mr.FastForward(10 * time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("admission denied after idle expiry — bucket should be full")
	}
}
