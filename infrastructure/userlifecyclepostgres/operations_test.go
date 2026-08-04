package userlifecyclepostgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "lifecycle.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE user_lifecycle_records (user_id TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at_ns BIGINT NOT NULL)`,
		`CREATE TABLE user_lifecycle_history (user_id TEXT NOT NULL, sequence BIGINT NOT NULL, from_state TEXT NOT NULL, to_state TEXT NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL, transition_at_ns BIGINT NOT NULL, PRIMARY KEY (user_id, sequence))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create test schema: %v", err)
		}
	}
	return &Store{db: db}
}

func TestStorePersistsStateHistoryAndConflicts(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	rec, err := store.Get(ctx, "u1")
	if err != nil || rec.State != userlifecycle.StateActive || len(rec.History) != 0 {
		t.Fatalf("implicit record = (%+v, %v), want active with empty history", rec, err)
	}
	at := time.Now().UTC().Truncate(time.Nanosecond)
	suspend := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateSuspended, "hold", "admin", at)
	if err := store.Append(ctx, "u1", suspend); err != nil {
		t.Fatalf("Append: %v", err)
	}
	rec, err = (&Store{db: store.db}).Get(ctx, "u1")
	if err != nil || rec.State != userlifecycle.StateSuspended || len(rec.History) != 1 {
		t.Fatalf("persisted record = (%+v, %v)", rec, err)
	}
	if !rec.History[0].At.Equal(at) || rec.History[0].Reason != "hold" || rec.History[0].Actor != "admin" {
		t.Fatalf("persisted transition = %+v, want exact history", rec.History[0])
	}
	stale := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "", "admin", at)
	if err := store.Append(ctx, "u1", stale); !errors.Is(err, userlifecycle.ErrStateConflict) {
		t.Fatalf("stale Append = %v, want ErrStateConflict", err)
	}
}

func TestStoreSeedListAndDuplicateSeed(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	seed := userlifecycle.NewTransition(userlifecycle.StateNone, userlifecycle.StateInvited, "", "system", time.Now())
	if err := store.Append(ctx, "invited", seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := store.Append(ctx, "invited", seed); !errors.Is(err, userlifecycle.ErrStateConflict) {
		t.Fatalf("duplicate seed = %v, want ErrStateConflict", err)
	}
	for _, userID := range []string{"b", "a"} {
		transition := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "system", time.Now())
		if err := store.Append(ctx, userID, transition); err != nil {
			t.Fatalf("Append(%s): %v", userID, err)
		}
	}
	users, err := store.ListByState(ctx, userlifecycle.StateInactive)
	if err != nil || len(users) != 2 || users[0] != "a" || users[1] != "b" {
		t.Fatalf("ListByState = (%v, %v), want [a b]", users, err)
	}
}

func TestStoreConcurrentStaleTransitionHasSingleWinner(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	transitions := []userlifecycle.Transition{
		userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateSuspended, "", "a", time.Now()),
		userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "b", time.Now()),
	}
	start := make(chan struct{})
	errs := make(chan error, len(transitions))
	var wg sync.WaitGroup
	for _, transition := range transitions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- store.Append(ctx, "u1", transition)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	var applied, conflicted int
	for err := range errs {
		if err == nil {
			applied++
		} else if errors.Is(err, userlifecycle.ErrStateConflict) {
			conflicted++
		} else {
			t.Fatalf("unexpected Append error: %v", err)
		}
	}
	if applied != 1 || conflicted != 1 {
		t.Fatalf("applied=%d conflicted=%d, want one each", applied, conflicted)
	}
	rec, err := store.Get(ctx, "u1")
	if err != nil || len(rec.History) != 1 {
		t.Fatalf("winner record = (%+v, %v), want one history entry", rec, err)
	}
}

func TestStoreRollsBackStateWhenHistoryWriteFails(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `DROP TABLE user_lifecycle_history`); err != nil {
		t.Fatalf("drop history: %v", err)
	}
	transition := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateSuspended, "", "admin", time.Now())
	if err := store.Append(ctx, "u1", transition); err == nil {
		t.Fatal("Append succeeded without the history table")
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_lifecycle_records WHERE user_id = ?`, "u1").Scan(&count); err != nil {
		t.Fatalf("count records: %v", err)
	}
	if count != 0 {
		t.Fatalf("state row survived failed history write: count=%d", count)
	}
}

func TestNewWithDBRequiresDatabase(t *testing.T) {
	t.Parallel()
	if _, err := NewWithDB(nil, ""); err == nil {
		t.Fatal("NewWithDB(nil) succeeded")
	}
}

func TestPostgresStorePersistsAcrossInstances(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set")
	}
	dialect := postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	db, err := postgresbackend.Open(postgresbackend.Config{DSN: dsn, Dialect: dialect})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	first, err := NewWithDB(db, dialect)
	if err != nil {
		t.Fatalf("NewWithDB: %v", err)
	}
	userID := fmt.Sprintf("lifecycle-integration-%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM user_lifecycle_records WHERE user_id = $1`, userID) })
	transition := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateSuspended, "integration", "test", time.Now())
	if err := first.Append(context.Background(), userID, transition); err != nil {
		t.Fatalf("Append: %v", err)
	}
	second, err := NewWithDB(db, dialect)
	if err != nil {
		t.Fatalf("second NewWithDB: %v", err)
	}
	rec, err := second.Get(context.Background(), userID)
	if err != nil || rec.State != userlifecycle.StateSuspended || len(rec.History) != 1 {
		t.Fatalf("second instance record = (%+v, %v)", rec, err)
	}
}
