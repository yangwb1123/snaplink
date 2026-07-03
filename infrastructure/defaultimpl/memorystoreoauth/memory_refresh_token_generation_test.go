package memorystoreoauth_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreoauth"
	"github.com/snaplink/sso/protocols/oauth"
)

// TestMemoryRefreshTokenStore_GenerationRoundTrip proves the rotation-generation
// counter (token-policy max_refresh_depth input) survives Issue and is returned
// by BOTH the non-destructive Inspect and the single-use Consume.
func TestMemoryRefreshTokenStore_GenerationRoundTrip(t *testing.T) {
	t.Parallel()
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	if err := s.Issue(ctx, "tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", Generation: 3,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	insp, err := s.Inspect(ctx, "tok")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if insp.Generation != 3 {
		t.Fatalf("Inspect Generation = %d, want 3", insp.Generation)
	}
	cons, err := s.Consume(ctx, "tok")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if cons.Generation != 3 {
		t.Fatalf("Consume Generation = %d, want 3", cons.Generation)
	}
}

// TestMemoryRefreshTokenStore_GenerationDefaultsZero proves a token issued
// WITHOUT a Generation (a pre-feature caller) reads back 0 — the backward-compat
// default that keeps an un-capped fleet byte-identical.
func TestMemoryRefreshTokenStore_GenerationDefaultsZero(t *testing.T) {
	t.Parallel()
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	if err := s.Issue(ctx, "tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cons, err := s.Consume(ctx, "tok")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if cons.Generation != 0 {
		t.Fatalf("Generation = %d, want 0 (default)", cons.Generation)
	}
}

// TestMemoryRefreshTokenStore_GenerationRace exercises concurrent Issue /
// Inspect / Consume of distinct generation-carrying tokens under -race to prove
// the added field is copied under the store mutex like every other field.
func TestMemoryRefreshTokenStore_GenerationRace(t *testing.T) {
	t.Parallel()
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tok := fmt.Sprintf("tok-%d", n)
			if err := s.Issue(ctx, tok, &oauth.RefreshToken{
				UserID: "u", ClientID: "c", Generation: n,
				ExpiresAt: time.Now().Add(time.Hour),
			}); err != nil {
				t.Errorf("Issue %s: %v", tok, err)
				return
			}
			if insp, err := s.Inspect(ctx, tok); err == nil && insp.Generation != n {
				t.Errorf("Inspect %s Generation = %d, want %d", tok, insp.Generation, n)
			}
			if cons, err := s.Consume(ctx, tok); err == nil && cons.Generation != n {
				t.Errorf("Consume %s Generation = %d, want %d", tok, cons.Generation, n)
			}
		}(i)
	}
	wg.Wait()
}
