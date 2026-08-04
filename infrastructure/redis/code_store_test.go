package redis

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestCodeStore_SaveVerifySingleUse(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()

	if err := s.Save(ctx, "phone:+15551234", "123456", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.Verify(ctx, "phone:+15551234", "123456"); err != nil {
		t.Fatalf("verify correct code: %v", err)
	}
	// Single-use: the correct code is consumed.
	if err := s.Verify(ctx, "phone:+15551234", "123456"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("re-verify should be ErrCodeInvalid, got %v", err)
	}
}

func TestCodeStore_EnforcesSharedSendQuotasAndRefunds(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	quota := authenticators.CodeSendQuota{IdentityLimit: 1, TenantLimit: 2, Window: time.Hour}
	s := NewCodeStoreWithQuota(rdb, quota)
	s.cooldown = 0
	ctxA := spi.WithCodeSendTenant(context.Background(), "tenant-a")
	if err := s.Save(ctxA, "email:a@example.com", "one", time.Minute); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if err := s.Save(ctxA, "email:a@example.com", "blocked", time.Minute); !errors.Is(err, spi.ErrCodeSendQuotaExceeded) {
		t.Fatalf("identity quota = %v", err)
	}
	if err := s.Save(ctxA, "email:b@example.com", "two", time.Minute); err != nil {
		t.Fatalf("second tenant send: %v", err)
	}
	if err := s.Save(ctxA, "email:c@example.com", "blocked", time.Minute); !errors.Is(err, spi.ErrCodeSendQuotaExceeded) {
		t.Fatalf("tenant quota = %v", err)
	}
	if err := s.Invalidate(ctxA, "email:b@example.com", "two"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if err := s.Save(ctxA, "email:c@example.com", "after-refund", time.Minute); err != nil {
		t.Fatalf("quota refund: %v", err)
	}
	ctxB := spi.WithCodeSendTenant(context.Background(), "tenant-b")
	if err := s.Save(ctxB, "email:a@example.com", "isolated", time.Minute); err != nil {
		t.Fatalf("tenant isolation: %v", err)
	}
}

func TestCodeStore_QuotaReservationIsAtomicAcrossReplicas(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	quota := authenticators.CodeSendQuota{IdentityLimit: 5, TenantLimit: 5, Window: time.Hour}
	stores := []*CodeStore{NewCodeStoreWithQuota(rdb, quota), NewCodeStoreWithQuota(rdb, quota)}
	for _, store := range stores {
		store.cooldown = 0
	}
	ctx := spi.WithCodeSendTenant(context.Background(), "tenant-concurrent")
	var successes atomic.Int64
	var unexpected atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := stores[i%len(stores)].Save(ctx, "email:shared@example.com", "code", time.Minute)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, spi.ErrCodeSendQuotaExceeded) {
				unexpected.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := successes.Load(); got != 5 {
		t.Fatalf("successful reservations = %d, want exactly 5", got)
	}
	if got := unexpected.Load(); got != 0 {
		t.Fatalf("unexpected store errors = %d", got)
	}
}

func TestCodeStore_WrongCodeIsRetryable(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()

	if err := s.Save(ctx, "email:a@b.c", "999000", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	// A wrong attempt fails but MUST NOT consume the code (typo retry).
	if err := s.Verify(ctx, "email:a@b.c", "111111"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("wrong code should be ErrCodeInvalid, got %v", err)
	}
	if err := s.Verify(ctx, "email:a@b.c", "999000"); err != nil {
		t.Fatalf("correct code after a typo should still verify, got %v", err)
	}
}

func TestCodeStore_UnknownAndExpired(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()

	if err := s.Verify(ctx, "never", "000000"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("unknown key should be ErrCodeInvalid, got %v", err)
	}

	if err := s.Save(ctx, "k", "424242", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	mr.FastForward(time.Minute + time.Second)
	if err := s.Verify(ctx, "k", "424242"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("expired code should be ErrCodeInvalid, got %v", err)
	}
}

func TestCodeStore_InvalidatesAfterMaxFailedAttempts(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()
	if err := s.Save(ctx, "attempts", "424242", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	for i := 0; i < authenticators.DefaultCodeMaxAttempts; i++ {
		if err := s.Verify(ctx, "attempts", "000000"); !errors.Is(err, authenticators.ErrCodeInvalid) {
			t.Fatalf("failed attempt %d: %v", i+1, err)
		}
	}
	if err := s.Verify(ctx, "attempts", "424242"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("correct code after exhaustion = %v, want ErrCodeInvalid", err)
	}
}

func TestCodeStore_InvalidateIsConditionalAndReleasesCooldown(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()
	if err := s.Save(ctx, "delivery", "current", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.Invalidate(ctx, "delivery", "stale"); err != nil {
		t.Fatalf("invalidate stale: %v", err)
	}
	if err := s.Verify(ctx, "delivery", "current"); err != nil {
		t.Fatalf("stale invalidation removed current code: %v", err)
	}
	if err := s.Save(ctx, "retry", "failed-delivery", time.Minute); err != nil {
		t.Fatalf("save failed delivery: %v", err)
	}
	if err := s.Invalidate(ctx, "retry", "failed-delivery"); err != nil {
		t.Fatalf("invalidate current: %v", err)
	}
	if err := s.Save(ctx, "retry", "replacement", time.Minute); err != nil {
		t.Fatalf("immediate retry should not be on cooldown: %v", err)
	}
}
