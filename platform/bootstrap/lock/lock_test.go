package lock_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/bootstrap/lock"
	"github.com/snaplink/sso/platform/bootstrap/locknoop"
)

// Contract: noop always succeeds, returns zero token, Renew/Release nil.
func TestNoop_AlwaysSucceeds(t *testing.T) {
	l := noop.New()
	h1, err := l.TryAcquire(context.Background(), "k", time.Second)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if h1.FencingToken() != 0 {
		t.Errorf("noop FencingToken = %d, want 0", h1.FencingToken())
	}
	if err := h1.Renew(context.Background()); err != nil {
		t.Errorf("Renew: %v", err)
	}

	// Concurrent acquire on same key also succeeds — noop has no state.
	h2, err := l.TryAcquire(context.Background(), "k", time.Second)
	if err != nil {
		t.Fatalf("second TryAcquire: %v", err)
	}
	_ = h2.Release(context.Background())
	_ = h1.Release(context.Background())

	// Release after Release is idempotent.
	if err := h1.Release(context.Background()); err != nil {
		t.Errorf("second Release: %v", err)
	}
}

// Sentinel identity check — anything testing for ErrLocked uses errors.Is.
func TestSentinels_AreUnique(t *testing.T) {
	if lock.ErrLocked == lock.ErrLockLost {
		t.Fatal("ErrLocked and ErrLockLost must be distinct sentinels")
	}
}
