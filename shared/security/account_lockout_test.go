package security_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/security"
)

// MemoryAccountLockout is the in-process AccountLockout. These tests
// exercise the sliding-window read-modify-write directly (no server
// harness) so the threshold / auto-unlock / window-reset arithmetic
// is pinned independently of the login orchestrator.

func TestMemoryAccountLockout_Defaults(t *testing.T) {
	t.Parallel()
	m := security.NewMemoryAccountLockout()
	if m.MaxFailures != security.DefaultLockoutMaxFailures {
		t.Errorf("MaxFailures = %d, want %d", m.MaxFailures, security.DefaultLockoutMaxFailures)
	}
	if m.LockoutDuration != security.DefaultLockoutDuration {
		t.Errorf("LockoutDuration = %v, want %v", m.LockoutDuration, security.DefaultLockoutDuration)
	}
	if m.FailureWindow != security.DefaultLockoutFailureWindow {
		t.Errorf("FailureWindow = %v, want %v", m.FailureWindow, security.DefaultLockoutFailureWindow)
	}
}

func TestMemoryAccountLockout_LocksAtThreshold(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := security.NewMemoryAccountLockout()
	m.MaxFailures = 3
	m.LockoutDuration = time.Hour

	const key = "c1:alice"

	// Fresh key — not locked.
	locked, _, err := m.IsLocked(ctx, key)
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if locked {
		t.Fatal("fresh key reported locked")
	}

	// Failures below threshold do not lock.
	for i := 0; i < 2; i++ {
		locked, _, err := m.RegisterFailure(ctx, key)
		if err != nil {
			t.Fatalf("RegisterFailure: %v", err)
		}
		if locked {
			t.Fatalf("locked after %d failures, threshold is 3", i+1)
		}
	}

	// Crossing the threshold engages the lock and returns until > now.
	locked, until, err := m.RegisterFailure(ctx, key)
	if err != nil {
		t.Fatalf("RegisterFailure: %v", err)
	}
	if !locked {
		t.Fatal("not locked after crossing threshold")
	}
	if !until.After(time.Now()) {
		t.Errorf("lock until %v is not in the future", until)
	}

	// IsLocked now reports the lock + the same expiry.
	locked, until2, err := m.IsLocked(ctx, key)
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if !locked {
		t.Fatal("IsLocked false after lockout engaged")
	}
	if !until2.Equal(until) {
		t.Errorf("IsLocked until %v != RegisterFailure until %v", until2, until)
	}

	// A subsequent failure against an already-locked key stays locked
	// and keeps the SAME expiry (no extension on each grind attempt).
	locked, until3, err := m.RegisterFailure(ctx, key)
	if err != nil {
		t.Fatalf("RegisterFailure: %v", err)
	}
	if !locked || !until3.Equal(until) {
		t.Errorf("already-locked failure changed state: locked=%v until=%v", locked, until3)
	}
}

func TestMemoryAccountLockout_RegisterSuccessResets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := security.NewMemoryAccountLockout()
	m.MaxFailures = 3

	const key = "c1:bob"
	if _, _, err := m.RegisterFailure(ctx, key); err != nil {
		t.Fatalf("RegisterFailure: %v", err)
	}
	if _, _, err := m.RegisterFailure(ctx, key); err != nil {
		t.Fatalf("RegisterFailure: %v", err)
	}
	// Success clears the counter back to zero.
	if err := m.RegisterSuccess(ctx, key); err != nil {
		t.Fatalf("RegisterSuccess: %v", err)
	}
	// A fresh run must climb back to the threshold from 0 — two more
	// failures (which previously would have hit 4) must NOT lock.
	for i := 0; i < 2; i++ {
		locked, _, err := m.RegisterFailure(ctx, key)
		if err != nil {
			t.Fatalf("RegisterFailure: %v", err)
		}
		if locked {
			t.Fatalf("locked after reset+%d failures; counter not cleared", i+1)
		}
	}
}

func TestMemoryAccountLockout_RegisterSuccessIdempotent(t *testing.T) {
	t.Parallel()
	m := security.NewMemoryAccountLockout()
	// Success on a never-seen key is a no-op, never an error.
	if err := m.RegisterSuccess(context.Background(), "c1:never"); err != nil {
		t.Fatalf("RegisterSuccess on unknown key: %v", err)
	}
}

func TestMemoryAccountLockout_AutoUnlockOnExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := security.NewMemoryAccountLockout()
	m.MaxFailures = 1
	// Sub-millisecond lock so the test doesn't sleep meaningfully.
	m.LockoutDuration = time.Millisecond

	const key = "c1:carol"
	locked, _, err := m.RegisterFailure(ctx, key)
	if err != nil {
		t.Fatalf("RegisterFailure: %v", err)
	}
	if !locked {
		t.Fatal("MaxFailures=1 should lock on first failure")
	}

	// Wait past the lock expiry; IsLocked must auto-unlock lazily.
	time.Sleep(2 * time.Millisecond)
	locked, _, err = m.IsLocked(ctx, key)
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if locked {
		t.Fatal("lock did not auto-expire")
	}
}

func TestMemoryAccountLockout_SlidingWindowReset(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := security.NewMemoryAccountLockout()
	m.MaxFailures = 3
	// A 1ns window means every subsequent failure lands outside the
	// window of the first → the counter resets to a fresh 1 instead of
	// accumulating, so the threshold is never reached.
	m.FailureWindow = time.Nanosecond

	const key = "c1:dave"
	for i := 0; i < 5; i++ {
		locked, _, err := m.RegisterFailure(ctx, key)
		if err != nil {
			t.Fatalf("RegisterFailure: %v", err)
		}
		if locked {
			t.Fatalf("locked at attempt %d despite window reset between each failure", i+1)
		}
		time.Sleep(time.Millisecond) // ensure now-firstFailureAt > window
	}
}

func TestMemoryAccountLockout_EmptyKeyNoOp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := security.NewMemoryAccountLockout()

	locked, _, err := m.IsLocked(ctx, "")
	if err != nil || locked {
		t.Errorf("IsLocked(\"\") = (%v, _, %v), want (false, _, nil)", locked, err)
	}
	locked, _, err = m.RegisterFailure(ctx, "")
	if err != nil || locked {
		t.Errorf("RegisterFailure(\"\") = (%v, _, %v), want (false, _, nil)", locked, err)
	}
	if err := m.RegisterSuccess(ctx, ""); err != nil {
		t.Errorf("RegisterSuccess(\"\") = %v, want nil", err)
	}
}

func TestMemoryAccountLockout_LockoutKeyAdditionalFields(t *testing.T) {
	t.Parallel()
	// "target" and "identifier" are accepted credential fields beyond
	// the username/email/phone covered elsewhere.
	if got := security.LockoutKey("c1", map[string]string{"target": "+15551234"}); got != "c1:+15551234" {
		t.Errorf("LockoutKey target = %q", got)
	}
	if got := security.LockoutKey("c1", map[string]string{"identifier": "device-7"}); got != "c1:device-7" {
		t.Errorf("LockoutKey identifier = %q", got)
	}
}

func TestMemoryAccountLockout_ConcurrentFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := security.NewMemoryAccountLockout()
	m.MaxFailures = 50
	m.LockoutDuration = time.Hour

	const key = "c1:concurrent"
	const n = 200
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() {
			_, _, _ = m.RegisterFailure(ctx, key)
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	// After 200 concurrent failures with threshold 50 the key MUST be
	// locked — the RMW is mutex-guarded so the increment never races.
	locked, _, err := m.IsLocked(ctx, key)
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if !locked {
		t.Fatal("key not locked after 200 concurrent failures (threshold 50)")
	}
}
