package redis

import (
	"context"
	"testing"
	"time"
)

func TestIdempotentCacheNonpositiveTTLIsFinite(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		mr, rdb := newTestClient(t)
		cache := NewIdempotentCache(rdb)
		if err := cache.Set(t.Context(), "operation", []byte("response"), ttl); err != nil {
			t.Fatal(err)
		}
		if got := mr.TTL(idemKey("operation")); got != time.Minute {
			t.Fatalf("TTL = %v, want one minute", got)
		}
		mr.FastForward(time.Minute)
		if _, hit, err := cache.Get(t.Context(), "operation"); hit || err != nil {
			t.Fatalf("expired response = %v %v", hit, err)
		}
	}
}

// TestIdempotentCache_RoundTripAndTTL proves the Redis-backed cache: Get
// returns the Set body, a missing key is a miss, and a server-side TTL
// expires the entry without a local prune loop.
func TestIdempotentCache_RoundTripAndTTL(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	c := NewIdempotentCache(rdb)
	ctx := context.Background()

	if _, ok, err := c.Get(ctx, "missing"); err != nil || ok {
		t.Fatalf("Get(missing) = (%v, %v), want miss", ok, err)
	}
	if err := c.Set(ctx, "k1", []byte(`{"access_token":"abc"}`), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	body, ok, err := c.Get(ctx, "k1")
	if err != nil || !ok || string(body) != `{"access_token":"abc"}` {
		t.Fatalf("Get(k1) = (%q, %v, %v), want the stored body", body, ok, err)
	}
	// Overwrite replaces the cached body.
	if err := c.Set(ctx, "k1", []byte(`{"access_token":"def"}`), time.Minute); err != nil {
		t.Fatalf("Set overwrite: %v", err)
	}
	body, ok, _ = c.Get(ctx, "k1")
	if !ok || string(body) != `{"access_token":"def"}` {
		t.Fatalf("Get after overwrite = %q, %v", body, ok)
	}
	// Short TTL expires the entry (miniredis clock: fast-forward past it).
	if err := c.Set(ctx, "k2", []byte("x"), 50*time.Millisecond); err != nil {
		t.Fatalf("Set k2: %v", err)
	}
	mr.FastForward(60 * time.Millisecond)
	if _, ok, err := c.Get(ctx, "k2"); err != nil || ok {
		t.Fatalf("Get(k2) after TTL = (%v, %v), want miss", ok, err)
	}
}
