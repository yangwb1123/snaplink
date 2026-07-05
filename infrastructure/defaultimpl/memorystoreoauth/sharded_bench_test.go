package memorystoreoauth

// Concurrent-load benchmarks for the sharded-lock memory OAuth stores.
// A single-goroutine benchmark can't show a lock-sharding win — there's
// no contention to reduce — so these drive b.RunParallel across
// GOMAXPROCS goroutines, each independently issuing + consuming its own
// code/request_uri. That's the realistic shape of production traffic
// (every login mints and consumes ONE auth code; nobody shares a code
// across requests), and it's exactly the pattern a single global mutex
// serializes and mapShardCount independent shards parallelize.

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

func BenchmarkMemoryAuthCodeStore_ConcurrentIssueConsume(b *testing.B) {
	store := NewMemoryAuthCodeStore()
	ctx := context.Background()
	info := &oauth.AuthCode{
		UserID:      "user-1234567890",
		ClientID:    "web-app",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid", "profile", "email"},
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			code, err := GenerateAuthCode()
			if err != nil {
				b.Fatal(err)
			}
			if err := store.Issue(ctx, code, info); err != nil {
				b.Fatal(err)
			}
			if _, err := store.Consume(ctx, code); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkMemoryPARStore_ConcurrentIssueConsume(b *testing.B) {
	store := NewMemoryPARStore()
	ctx := context.Background()
	req := &oauth.PARRequest{
		ClientID:     "web-app",
		ResponseType: "code",
		RedirectURI:  "https://app.example.com/callback",
		Scope:        []string{"openid", "profile", "email"},
		ExpiresAt:    time.Now().Add(90 * time.Second),
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			uri, err := store.Issue(ctx, req)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := store.Consume(ctx, uri); err != nil {
				b.Fatal(err)
			}
		}
	})
}
