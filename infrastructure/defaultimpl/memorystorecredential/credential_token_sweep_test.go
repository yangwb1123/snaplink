package memorystorecredential

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestSweepExpiredCredentialEntries_StrictBoundary(t *testing.T) {
	now := time.Now()
	entries := map[string]*core.EmailChangeToken{
		"expired":  {ExpiresAt: now.Add(-time.Nanosecond)},
		"boundary": {ExpiresAt: now},
		"live":     {ExpiresAt: now.Add(time.Nanosecond)},
	}
	var lastSweep atomic.Int64
	sweepExpiredCredentialEntries(&lastSweep, entries, now, func(entry *core.EmailChangeToken) time.Time {
		return entry.ExpiresAt
	})

	if _, ok := entries["expired"]; ok {
		t.Error("strictly expired entry remains")
	}
	for _, key := range []string{"boundary", "live"} {
		if _, ok := entries[key]; !ok {
			t.Errorf("entry %q was swept", key)
		}
	}
}

func TestMemoryEmailChangeStore_IssueSweepsExpired(t *testing.T) {
	store := NewMemoryEmailChangeStore()
	store.tokens["expired"] = &core.EmailChangeToken{
		Token: "expired", ExpiresAt: time.Now().Add(-time.Hour),
	}
	store.lastSweep.Store(0)
	if err := store.Issue(context.Background(), &core.EmailChangeToken{
		Token: "live", UserID: "user", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, ok := store.tokens["expired"]; ok {
		t.Error("expired email-change token remains")
	}
	if _, ok := store.tokens["live"]; !ok {
		t.Error("live email-change token was swept")
	}
}

func TestMemoryPasswordResetStore_IssueSweepsExpired(t *testing.T) {
	store := NewMemoryPasswordResetStore()
	store.tokens["expired"] = &core.PasswordResetToken{
		Token: "expired", ExpiresAt: time.Now().Add(-time.Hour),
	}
	store.lastSweep.Store(0)
	if err := store.Issue(context.Background(), &core.PasswordResetToken{
		Token: "live", UserID: "user", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, ok := store.tokens["expired"]; ok {
		t.Error("expired password-reset token remains")
	}
	if _, ok := store.tokens["live"]; !ok {
		t.Error("live password-reset token was swept")
	}
}

func TestMemoryCredentialStoresConcurrentIssueConsume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("email-change", func(t *testing.T) {
		store := NewMemoryEmailChangeStore()
		runConcurrentCredentialOps(t, func(i int) error {
			token := fmt.Sprintf("email-%d", i)
			return store.Issue(ctx, &core.EmailChangeToken{Token: token, UserID: "user", ExpiresAt: time.Now().Add(time.Hour)})
		}, func(i int) {
			_, _ = store.Consume(ctx, fmt.Sprintf("email-%d", i))
		})
	})
	t.Run("password-reset", func(t *testing.T) {
		store := NewMemoryPasswordResetStore()
		runConcurrentCredentialOps(t, func(i int) error {
			token := fmt.Sprintf("reset-%d", i)
			return store.Issue(ctx, &core.PasswordResetToken{Token: token, UserID: "user", ExpiresAt: time.Now().Add(time.Hour)})
		}, func(i int) {
			_, _ = store.Consume(ctx, fmt.Sprintf("reset-%d", i))
		})
	})
}

func runConcurrentCredentialOps(t *testing.T, issue func(int) error, consume func(int)) {
	t.Helper()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		worker := worker
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				id := worker*25 + i
				if err := issue(id); err != nil {
					t.Errorf("Issue: %v", err)
				}
				consume(id)
			}
		}()
	}
	wg.Wait()
}
