package defaultimpl_test

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

func TestMemoryIdempotentCacheCopiesBuffersAndDefaultsTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, time.Minute} {
		cache := defaultimpl.NewMemoryIdempotentCache(ttl)
		body := []byte("original")
		if err := cache.Set(t.Context(), "operation", body, 0); err != nil {
			t.Fatal(err)
		}
		body[0] = 'X'
		got, hit, err := cache.Get(t.Context(), "operation")
		if err != nil || !hit || string(got) != "original" {
			t.Fatalf("stored caller buffer: %q %v %v", got, hit, err)
		}
		got[0] = 'Y'
		again, _, _ := cache.Get(t.Context(), "operation")
		if string(again) != "original" {
			t.Fatalf("returned shared buffer: %q", again)
		}
		cache.Close()
	}
}

func TestMemoryIdempotentCacheHonorsExplicitShortTTL(t *testing.T) {
	cache := defaultimpl.NewMemoryIdempotentCache(time.Hour)
	defer cache.Close()
	if err := cache.Set(t.Context(), "operation", []byte("response"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, hit, err := cache.Get(t.Context(), "operation"); hit || err != nil {
		t.Fatalf("expired response = %v %v", hit, err)
	}
}
