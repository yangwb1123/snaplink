package ratelimit

import (
	"testing"
	"time"
)

func FuzzMemoryLimiterAllow(f *testing.F) {
	seeds := []string{
		"user:alice",
		"ip:10.0.0.1",
		"client:app-1",
		"global",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		limiter := NewMemoryLimiter(100, 10)
		allowed, wait := limiter.Allow(key)
		// Must not panic
		_ = allowed
		_ = wait
	})
}

func FuzzMemoryLimiterStalePrune(f *testing.F) {
	seeds := []string{
		"key-1",
		"",
		"very-long-key-that-might-cause-issues-with-hashing",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		limiter := NewMemoryLimiterWithStalePrune(10, 5, time.Second)
		limiter.Allow(key)
	})
}
