package redis

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// newTestLockout builds a Redis AccountLockout over a fresh miniredis with a
// fast policy (3 failures, 1-minute lock, 1-hour window) so the table-driven
// timing assertions stay quick. Overriding the exported fields after
// construction mirrors exactly how cmd applies cfg overrides.
func newTestLockout(t *testing.T) (*goredis.Client, *AccountLockout) {
	t.Helper()
	_, rdb := newTestClient(t)
	l := NewAccountLockout(rdb)
	l.MaxFailures = 3
	l.LockoutDuration = time.Minute
	l.FailureWindow = time.Hour
	return rdb, l
}

func TestAccountLockoutDefaults(t *testing.T) {
	_, rdb := newTestClient(t)
	l := NewAccountLockout(rdb)
	if l.MaxFailures != 5 || l.LockoutDuration != 15*time.Minute || l.FailureWindow != time.Hour {
		t.Fatalf("defaults diverge from memory peer: %+v", l)
	}
}

func TestAccountLockoutEngageAndAutoUnlock(t *testing.T) {
	_, l := newTestLockout(t)
	ctx := context.Background()
	const key = "app:alice"

	for i := 1; i <= 2; i++ {
		locked, _, err := l.RegisterFailure(ctx, key)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if locked {
			t.Fatalf("locked early at failure %d", i)
		}
	}
	if locked, _, _ := l.IsLocked(ctx, key); locked {
		t.Fatal("IsLocked true below threshold")
	}

	locked, until, err := l.RegisterFailure(ctx, key)
	if err != nil {
		t.Fatalf("threshold failure: %v", err)
	}
	if !locked || until.IsZero() || !until.After(time.Now()) {
		t.Fatalf("threshold did not engage: locked=%v until=%v", locked, until)
	}
	gotLocked, gotUntil, _ := l.IsLocked(ctx, key)
	if !gotLocked || !gotUntil.Equal(until) {
		t.Fatalf("IsLocked mismatch: locked=%v until=%v want=%v", gotLocked, gotUntil, until)
	}
}

// TestAccountLockoutAutoUnlock proves the lock marker's PX expiry auto-unlocks
// after LockoutDuration without any background sweep.
func TestAccountLockoutAutoUnlock(t *testing.T) {
	mr, rdb := newTestClient(t)
	l := NewAccountLockout(rdb)
	l.MaxFailures, l.LockoutDuration, l.FailureWindow = 1, time.Minute, time.Hour
	ctx := context.Background()
	const key = "app:bob"

	if locked, _, _ := l.RegisterFailure(ctx, key); !locked {
		t.Fatal("single failure with MaxFailures=1 must lock")
	}
	mr.FastForward(61 * time.Second)
	if locked, _, _ := l.IsLocked(ctx, key); locked {
		t.Fatal("lock did not auto-unlock after LockoutDuration")
	}
}

// TestAccountLockoutAlreadyLocked: once locked, further failures return the
// SAME deadline and never advance the counter (matches the memory peer).
func TestAccountLockoutAlreadyLocked(t *testing.T) {
	rdb, l := newTestLockout(t)
	ctx := context.Background()
	const key = "app:carol"

	var lockedUntil time.Time
	for i := 1; i <= 3; i++ {
		_, until, _ := l.RegisterFailure(ctx, key)
		lockedUntil = until
	}
	for range 4 {
		locked, until, _ := l.RegisterFailure(ctx, key)
		if !locked || !until.Equal(lockedUntil) {
			t.Fatalf("already-locked drift: locked=%v until=%v want=%v", locked, until, lockedUntil)
		}
	}
	// Counter must be pinned at the threshold — no increments after engage.
	n, err := rdb.Get(ctx, lockoutFailKey(key)).Int()
	if err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if n != 3 {
		t.Fatalf("counter advanced past threshold under lock: %d", n)
	}
}

func TestAccountLockoutRegisterSuccessClears(t *testing.T) {
	rdb, l := newTestLockout(t)
	ctx := context.Background()
	const key = "app:dave"

	_, _, _ = l.RegisterFailure(ctx, key)
	_, _, _ = l.RegisterFailure(ctx, key)
	if err := l.RegisterSuccess(ctx, key); err != nil {
		t.Fatalf("success: %v", err)
	}
	exists, _ := rdb.Exists(ctx, lockoutFailKey(key), lockoutUntilKey(key)).Result()
	if exists != 0 {
		t.Fatalf("RegisterSuccess left %d keys", exists)
	}
	// After a reset, a single fresh failure must NOT relock (counter from 0).
	if locked, _, _ := l.RegisterFailure(ctx, key); locked {
		t.Fatal("counter not reset by RegisterSuccess")
	}
}

// TestAccountLockoutSlidingWindow: when FailureWindow elapses, the counter key
// expires so the next failure starts a fresh window at 1.
func TestAccountLockoutSlidingWindow(t *testing.T) {
	mr, rdb := newTestClient(t)
	l := NewAccountLockout(rdb)
	l.MaxFailures, l.LockoutDuration, l.FailureWindow = 3, time.Minute, time.Hour
	ctx := context.Background()
	const key = "app:erin"

	_, _, _ = l.RegisterFailure(ctx, key) // count 1
	_, _, _ = l.RegisterFailure(ctx, key) // count 2
	mr.FastForward(61 * time.Minute)      // window elapses -> counter expires

	if locked, _, _ := l.RegisterFailure(ctx, key); locked {
		t.Fatal("stale pre-window failures must not count toward lock")
	}
	if n, _ := rdb.Get(ctx, lockoutFailKey(key)).Int(); n != 1 {
		t.Fatalf("window did not reset: counter=%d want 1", n)
	}
}

func TestAccountLockoutEmptyKey(t *testing.T) {
	_, l := newTestLockout(t)
	ctx := context.Background()
	if locked, _, err := l.IsLocked(ctx, ""); locked || err != nil {
		t.Fatalf("empty IsLocked: %v %v", locked, err)
	}
	if locked, _, err := l.RegisterFailure(ctx, ""); locked || err != nil {
		t.Fatalf("empty RegisterFailure: %v %v", locked, err)
	}
	if err := l.RegisterSuccess(ctx, ""); err != nil {
		t.Fatalf("empty RegisterSuccess: %v", err)
	}
}

// TestAccountLockoutAtomicThreshold fires MaxFailures concurrent failures; the
// atomic Lua INCR+check means EXACTLY one call observes the threshold crossing
// (a non-atomic read-modify-write — the per-pod bug — would engage twice or
// never with exactly N callers).
func TestAccountLockoutAtomicThreshold(t *testing.T) {
	_, rdb := newTestClient(t)
	l := NewAccountLockout(rdb)
	const n = 16
	l.MaxFailures, l.LockoutDuration, l.FailureWindow = n, time.Minute, time.Hour
	ctx := context.Background()
	const key = "app:frank"

	results := make(chan bool, n)
	for range n {
		go func() {
			locked, _, err := l.RegisterFailure(ctx, key)
			if err != nil {
				t.Errorf("concurrent failure: %v", err)
			}
			results <- locked
		}()
	}
	engaged := 0
	for range n {
		if <-results {
			engaged++
		}
	}
	if engaged != 1 {
		t.Fatalf("threshold engaged %d times, want exactly 1", engaged)
	}
	if locked, _, _ := l.IsLocked(ctx, key); !locked {
		t.Fatal("account not locked after threshold reached")
	}
}

// TestAccountLockoutKeysShareSlot guards the registerFailureScript: its two
// keys (counter + lock marker) MUST share a Redis Cluster slot via the {key}
// hash tag, else the EVAL is a CROSSSLOT error on a real cluster.
func TestAccountLockoutKeysShareSlot(t *testing.T) {
	for _, k := range []string{"app:alice", "tenant:abc/web:user@x", "weird}id", "k"} {
		assertSameSlot(t, "lockout key="+k, lockoutFailKey(k), lockoutUntilKey(k))
	}
}
