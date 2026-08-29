package redis

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/rotation"
)

func testClientSecretWarningClaim() rotation.ClientSecretWarningClaim {
	return rotation.ClientSecretWarningClaim{
		ClientID:        "client-1",
		Window:          7 * 24 * time.Hour,
		Day:             time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC),
		SecretExpiresAt: time.Date(2026, time.January, 9, 0, 0, 0, 0, time.UTC),
	}
}

func TestClientSecretWarningClaimStore_AtomicAcrossInstances(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	stores := []*ClientSecretWarningClaimStore{
		NewClientSecretWarningClaimStore(rdb),
		NewClientSecretWarningClaimStore(rdb),
	}
	claim := testClientSecretWarningClaim()
	const attempts = 64
	type result struct {
		won bool
		err error
	}
	results := make(chan result, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		store := stores[i%len(stores)]
		go func(store *ClientSecretWarningClaimStore) {
			defer wg.Done()
			won, err := store.Claim(context.Background(), claim)
			results <- result{won: won, err: err}
		}(store)
	}
	wg.Wait()
	close(results)

	winners := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("claim: %v", result.err)
		}
		if result.won {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent Redis winners = %d, want 1", winners)
	}
	// A fresh store wrapper is the scanner-process-restart shape; the marker
	// remains in the same shared Redis instance.
	if won, err := NewClientSecretWarningClaimStore(rdb).Claim(context.Background(), claim); err != nil || won {
		t.Fatalf("claim after store restart = (%v, %v), want (false, nil)", won, err)
	}
}

func TestClientSecretWarningClaimStore_ClaimComponentsAndTTL(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	store := NewClientSecretWarningClaimStore(rdb)
	ctx := context.Background()
	claim := testClientSecretWarningClaim()

	if won, err := store.Claim(ctx, claim); err != nil || !won {
		t.Fatalf("first claim = (%v, %v), want (true, nil)", won, err)
	}
	if won, err := store.Claim(ctx, claim); err != nil || won {
		t.Fatalf("same claim = (%v, %v), want (false, nil)", won, err)
	}
	changedGeneration := claim
	changedGeneration.SecretExpiresAt = claim.SecretExpiresAt.Add(time.Hour)
	if won, err := store.Claim(ctx, changedGeneration); err != nil || !won {
		t.Fatalf("changed generation = (%v, %v), want (true, nil)", won, err)
	}
	changedDay := claim
	changedDay.Day = claim.Day.Add(24 * time.Hour)
	if won, err := store.Claim(ctx, changedDay); err != nil || !won {
		t.Fatalf("changed day = (%v, %v), want (true, nil)", won, err)
	}

	keys, err := rdb.Keys(ctx, clientSecretWarningKeyPrefix+"*").Result()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("claim keys = %d, want 3", len(keys))
	}
	for _, key := range keys {
		if len(key) != len(clientSecretWarningKeyPrefix)+64 {
			t.Fatalf("claim key length = %d, want %d", len(key), len(clientSecretWarningKeyPrefix)+64)
		}
		if strings.Contains(key, claim.ClientID) {
			t.Fatalf("claim key contains raw client ID: %q", key)
		}
		ttl, err := rdb.PTTL(ctx, key).Result()
		if err != nil {
			t.Fatalf("pttl %q: %v", key, err)
		}
		if ttl <= 0 || ttl > clientSecretWarningClaimTTL {
			t.Fatalf("claim TTL = %v, want in (0, %v]", ttl, clientSecretWarningClaimTTL)
		}
		value, err := rdb.Get(ctx, key).Result()
		if err != nil {
			t.Fatalf("get %q: %v", key, err)
		}
		if value != "1" {
			t.Fatalf("claim value = %q, want marker 1", value)
		}
	}

	mr.FastForward(clientSecretWarningClaimTTL + time.Second)
	if won, err := store.Claim(ctx, claim); err != nil || !won {
		t.Fatalf("claim after bounded TTL = (%v, %v), want (true, nil)", won, err)
	}
}

func TestClientSecretWarningClaimStore_NilRedisFails(t *testing.T) {
	if won, err := NewClientSecretWarningClaimStore(nil).Claim(context.Background(), testClientSecretWarningClaim()); err == nil || won {
		t.Fatalf("nil Redis claim = (%v, %v), want (false, error)", won, err)
	}
}
