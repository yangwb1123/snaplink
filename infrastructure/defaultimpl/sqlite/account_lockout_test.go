package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newAccountLockoutForTest(t *testing.T) *AccountLockout {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "lockout.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	lockout, err := NewAccountLockout(dsn)
	if err != nil {
		t.Fatalf("NewAccountLockout: %v", err)
	}
	// Tight numbers so tests stay fast.
	lockout.MaxFailures = 3
	lockout.LockoutDuration = 200 * time.Millisecond
	lockout.FailureWindow = time.Minute
	t.Cleanup(func() { _ = lockout.Close() })
	return lockout
}

func TestAccountLockout_FirstFailureNoLock(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	locked, _, err := lockout.RegisterFailure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RegisterFailure: %v", err)
	}
	if locked {
		t.Fatal("single failure must not lock")
	}
}

func TestAccountLockout_ThresholdLocks(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	ctx := context.Background()
	for i := 0; i < lockout.MaxFailures-1; i++ {
		locked, _, err := lockout.RegisterFailure(ctx, "alice")
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if locked {
			t.Fatalf("failure %d locked too early", i)
		}
	}
	locked, until, err := lockout.RegisterFailure(ctx, "alice")
	if err != nil {
		t.Fatalf("threshold-crossing failure: %v", err)
	}
	if !locked {
		t.Fatal("threshold crossing must lock")
	}
	if until.IsZero() || !until.After(time.Now()) {
		t.Fatalf("until must be in the future, got %v", until)
	}
}

func TestAccountLockout_IsLockedReportsState(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	ctx := context.Background()

	// Not yet locked.
	locked, _, err := lockout.IsLocked(ctx, "alice")
	if err != nil {
		t.Fatalf("IsLocked initial: %v", err)
	}
	if locked {
		t.Fatal("unknown key must not be locked")
	}

	for range lockout.MaxFailures {
		_, _, _ = lockout.RegisterFailure(ctx, "alice")
	}

	locked, _, err = lockout.IsLocked(ctx, "alice")
	if err != nil {
		t.Fatalf("IsLocked post-threshold: %v", err)
	}
	if !locked {
		t.Fatal("IsLocked must report true after threshold")
	}
}

func TestAccountLockout_RegisterSuccessClears(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	ctx := context.Background()

	_, _, _ = lockout.RegisterFailure(ctx, "alice")
	_, _, _ = lockout.RegisterFailure(ctx, "alice")
	if err := lockout.RegisterSuccess(ctx, "alice"); err != nil {
		t.Fatalf("RegisterSuccess: %v", err)
	}
	// After success, the counter resets — next failure should not be
	// the threshold-crossing one.
	locked, _, _ := lockout.RegisterFailure(ctx, "alice")
	if locked {
		t.Fatal("RegisterSuccess did not clear the counter")
	}
}

func TestAccountLockout_AutoUnlockAfterDuration(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	ctx := context.Background()

	for range lockout.MaxFailures {
		_, _, _ = lockout.RegisterFailure(ctx, "alice")
	}
	locked, _, _ := lockout.IsLocked(ctx, "alice")
	if !locked {
		t.Fatal("expected locked immediately after threshold")
	}
	time.Sleep(lockout.LockoutDuration + 50*time.Millisecond)
	locked, _, _ = lockout.IsLocked(ctx, "alice")
	if locked {
		t.Fatal("auto-unlock failed — IsLocked still true past LockoutDuration")
	}
}

func TestAccountLockout_KeysIsolated(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	ctx := context.Background()

	for range lockout.MaxFailures {
		_, _, _ = lockout.RegisterFailure(ctx, "alice")
	}
	// bob's counter is untouched.
	locked, _, _ := lockout.IsLocked(ctx, "bob")
	if locked {
		t.Fatal("bob locked by alice's failures — keys not isolated")
	}
}

func TestAccountLockout_EmptyKeyIsNoOp(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	ctx := context.Background()
	for range 10 {
		locked, _, err := lockout.RegisterFailure(ctx, "")
		if err != nil {
			t.Fatalf("RegisterFailure(\"\"): %v", err)
		}
		if locked {
			t.Fatal("empty key must never lock")
		}
	}
	locked, _, _ := lockout.IsLocked(ctx, "")
	if locked {
		t.Fatal("IsLocked(\"\") must be false")
	}
	if err := lockout.RegisterSuccess(ctx, ""); err != nil {
		t.Fatalf("RegisterSuccess(\"\"): %v", err)
	}
}

func TestAccountLockout_AlreadyLockedDoesNotResetCounter(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	ctx := context.Background()
	for range lockout.MaxFailures {
		_, _, _ = lockout.RegisterFailure(ctx, "alice")
	}
	// Additional failures while locked should still return locked + same until.
	locked, until1, _ := lockout.RegisterFailure(ctx, "alice")
	if !locked {
		t.Fatal("RegisterFailure while locked must return locked=true")
	}
	locked, until2, _ := lockout.RegisterFailure(ctx, "alice")
	if !locked {
		t.Fatal("RegisterFailure while locked (second extra) must still be true")
	}
	// until shouldn't extend just because more failures hit during the
	// lock — the contract is "lock for LockoutDuration from the
	// threshold-crossing failure," not from every subsequent failure.
	if until2.After(until1) {
		t.Fatalf("until extended on subsequent failure (%v > %v) — lock duration must be fixed", until2, until1)
	}
}

func TestAccountLockout_SlidingWindowResetsAfterExpiry(t *testing.T) {
	t.Parallel()
	lockout := newAccountLockoutForTest(t)
	lockout.FailureWindow = 100 * time.Millisecond
	ctx := context.Background()

	// Two failures within the window — not enough to lock.
	_, _, _ = lockout.RegisterFailure(ctx, "alice")
	_, _, _ = lockout.RegisterFailure(ctx, "alice")

	// Wait for the window to expire.
	time.Sleep(150 * time.Millisecond)

	// Next failure should re-start the counter at 1, not the
	// threshold-crossing 3rd failure.
	locked, _, _ := lockout.RegisterFailure(ctx, "alice")
	if locked {
		t.Fatal("post-window failure locked — sliding-window reset did not kick in")
	}
}

func TestAccountLockout_CrossInstanceSharing(t *testing.T) {
	t.Parallel()
	// The whole reason for the SQLite backend: an attacker rotating
	// targets across replicas can't stay under each replica's local
	// threshold because the counter is shared.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	lockoutA, err := NewAccountLockout(dsn)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer func() { _ = lockoutA.Close() }()
	lockoutA.MaxFailures = 3
	lockoutB, err := NewAccountLockout(dsn)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	defer func() { _ = lockoutB.Close() }()
	lockoutB.MaxFailures = 3

	// Two failures via A.
	_, _, _ = lockoutA.RegisterFailure(context.Background(), "alice")
	_, _, _ = lockoutA.RegisterFailure(context.Background(), "alice")

	// Third failure via B should cross the threshold because the
	// counter is shared.
	locked, _, _ := lockoutB.RegisterFailure(context.Background(), "alice")
	if !locked {
		t.Fatal("B did not see A's failures — cross-replica defense broken")
	}
}

// TestAccountLockout_ConcurrentCrossReplicaNoLostUpdates regression-tests
// RegisterFailure's read-modify-write against a GENUINE lost-update race: two
// separate *AccountLockout instances (simulating two replicas sharing one
// SQLite file — the exact "cluster-shared deployment" this backend exists
// for) both increment the SAME key concurrently. Each process's own
// connection pool serializes ITS OWN calls (SetMaxOpenConns(1)), but that
// does nothing for a concurrent writer in a DIFFERENT process — only a real
// BEGIN IMMEDIATE (see beginImmediateRMW) takes SQLite's file-level RESERVED
// lock immediately, forcing the other replica's transaction to wait
// (busy_timeout) rather than both reading the same stale counter and one
// overwriting the other's increment. If RegisterFailure ever regresses to
// db.BeginTx's isolation-level hint (a no-op under modernc.org/sqlite), this
// test will flake by observing a final count below want.
func TestAccountLockout_ConcurrentCrossReplicaNoLostUpdates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "concurrent.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	const perReplica = 15
	const replicas = 2
	want := perReplica * replicas

	instances := make([]*AccountLockout, replicas)
	for i := range instances {
		l, err := NewAccountLockout(dsn)
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
		defer func() { _ = l.Close() }()
		l.MaxFailures = want + 1 // never actually lock — isolate the counter race
		instances[i] = l
	}

	var wg sync.WaitGroup
	for _, l := range instances {
		for i := 0; i < perReplica; i++ {
			wg.Add(1)
			go func(l *AccountLockout) {
				defer wg.Done()
				if _, _, err := l.RegisterFailure(context.Background(), "bob"); err != nil {
					t.Errorf("RegisterFailure: %v", err)
				}
			}(l)
		}
	}
	wg.Wait()

	failures, _, _, err := lockoutRowFor(context.Background(), mustConn(t, instances[0].db), "bob")
	if err != nil {
		t.Fatalf("lockoutRowFor: %v", err)
	}
	if failures != want {
		t.Fatalf("failures = %d, want %d — a concurrent RegisterFailure lost an update", failures, want)
	}
}

// mustConn pins a connection from db for a single read, matching the shape
// RegisterFailure itself uses (lockoutRowFor takes a *sql.Conn).
func mustConn(t *testing.T, db *sql.DB) *sql.Conn {
	t.Helper()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
