package securitystore

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

func TestLockoutCompetingAbsentKeyAcrossPools(t *testing.T) {
	db, dsn := fixture(t)
	a, err := NewAccountLockoutWithDB(db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAccountLockoutWithDB(openPool(t, dsn), pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	a.MaxFailures, b.MaxFailures = 32, 32
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ready, start := make(chan struct{}, 32), make(chan struct{})
	replies := make(chan bool, 32)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			store := []*AccountLockout{a, b}[i%2]
			locked, _, err := store.RegisterFailure(ctx, "client:用户 ")
			if err != nil {
				t.Errorf("contender=%d: %v", i, err)
			}
			replies <- locked
		}(i)
	}
	for range 32 {
		<-ready
	}
	close(start)
	wg.Wait()
	close(replies)
	locks := 0
	for locked := range replies {
		if locked {
			locks++
		}
	}
	if locks != 1 || scalar(t, db, "SELECT failures FROM account_lockouts WHERE key=$1", "client:用户 ") != 32 {
		t.Fatalf("locks=%d; expected one threshold crossing and all 32 increments", locks)
	}
}

func TestLockoutWindowExpiryResetAndReopen(t *testing.T) {
	db, dsn := fixture(t)
	a, err := NewAccountLockoutWithDB(db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	key := "client-a:opaque "
	for range a.MaxFailures {
		if _, _, err := a.RegisterFailure(t.Context(), key); err != nil {
			t.Fatal(err)
		}
	}
	b, err := NewAccountLockoutWithDB(openPool(t, dsn), pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	if locked, _, err := b.IsLocked(t.Context(), key); err != nil || !locked {
		t.Fatalf("reopen lock=%v error=%v", locked, err)
	}
	if _, _, err := b.RegisterFailure(t.Context(), key); err != nil || scalar(t, db, "SELECT failures FROM account_lockouts WHERE key=$1", key) != int64(a.MaxFailures) {
		t.Fatal("active lock changed failure count", err)
	}
	exec(t, db, "UPDATE account_lockouts SET first_failure_at=$2 WHERE key=$1", key, time.Now().Add(-2*time.Hour).UnixNano())
	if locked, _, err := b.RegisterFailure(t.Context(), key); err != nil || locked {
		t.Fatal("peer's expired failure window did not reset active lock", err)
	}
	exec(t, db, "UPDATE account_lockouts SET locked_until=$2 WHERE key=$1", key, time.Now().Add(-time.Minute).UnixNano())
	if locked, _, err := b.IsLocked(t.Context(), key); err != nil || locked || scalar(t, db, "SELECT locked_until FROM account_lockouts WHERE key=$1", key) != 0 {
		t.Fatal("expired lock not compare-cleared", err)
	}
	if err := b.RegisterSuccess(t.Context(), key); err != nil || scalar(t, db, "SELECT COUNT(*) FROM account_lockouts") != 0 {
		t.Fatal("success did not delete state", err)
	}
}

func TestLockoutExactIntegerOpaqueKeysCancelAndOverflow(t *testing.T) {
	db, _ := fixture(t)
	a, err := NewAccountLockoutWithDB(db, pg.DialectPostgres)
	if err != nil {
		t.Fatal(err)
	}
	a.MaxFailures = math.MaxInt64
	exec(t, db, "INSERT INTO account_lockouts(key,failures,first_failure_at) VALUES($1,$2,$3)", "client:a", int64(9007199254740993), time.Now().UnixNano())
	if _, _, err := a.RegisterFailure(t.Context(), "client:a"); err != nil || scalar(t, db, "SELECT failures FROM account_lockouts WHERE key=$1", "client:a") != 9007199254740994 {
		t.Fatal("int64 increment lost precision", err)
	}
	if _, _, err := a.RegisterFailure(t.Context(), "client:a "); err != nil || scalar(t, db, "SELECT failures FROM account_lockouts WHERE key=$1", "client:a ") != 1 {
		t.Fatal("trailing-space key collapsed", err)
	}
	exec(t, db, "UPDATE account_lockouts SET failures=$2 WHERE key=$1", "client:a", int64(math.MaxInt64))
	if _, _, err := a.RegisterFailure(t.Context(), "client:a"); err == nil || scalar(t, db, "SELECT failures FROM account_lockouts WHERE key=$1", "client:a") != math.MaxInt64 {
		t.Fatal("overflow did not reject and preserve state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := a.RegisterFailure(ctx, "cancelled"); err == nil || scalar(t, db, "SELECT COUNT(*) FROM account_lockouts WHERE key='cancelled'") != 0 {
		t.Fatal("cancelled write was published")
	}
	if locked, _, err := a.IsLocked(ctx, ""); locked || err != nil {
		t.Fatal("empty-key peer no-op changed", err)
	}
}
