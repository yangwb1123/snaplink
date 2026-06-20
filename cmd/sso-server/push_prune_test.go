package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
)

func TestRunPushApprovalPrune_RemovesExpiredAtInterval(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "push.db") + "?_journal=WAL"
	store, err := sqlitestores.NewPushApprovalStore(dsn)
	if err != nil {
		t.Fatalf("NewPushApprovalStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	now := time.Now().UTC()
	mustPut := func(id string, expires time.Time) {
		if err := store.Put(ctx, &defaultimpl.PushApproval{
			ID:        id,
			SubjectID: "alice",
			Status:    defaultimpl.PushApprovalPending,
			CreatedAt: now,
			ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
	}
	mustPut("old-1", now.Add(-1*time.Second))
	mustPut("old-2", now.Add(-500*time.Millisecond))
	mustPut("fresh", now.Add(1*time.Hour))

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go runPushApprovalPrune(runCtx, done, store, 30*time.Millisecond, quietLogger(), nil)

	// Wait for at least one tick.
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("scheduler didn't exit after cancel")
	}

	// fresh survives; olds are gone.
	if _, err := store.Get(ctx, "fresh"); err != nil {
		t.Errorf("fresh got pruned: %v", err)
	}
	for _, id := range []string{"old-1", "old-2"} {
		if _, err := store.Get(ctx, id); err == nil {
			t.Errorf("expired %q survived prune", id)
		}
	}
}

func TestRunPushApprovalPrune_ExitsOnCtxCancelBeforeFirstTick(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "push.db") + "?_journal=WAL"
	store, _ := sqlitestores.NewPushApprovalStore(dsn)
	defer func() { _ = store.Close() }()

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go runPushApprovalPrune(runCtx, done, store, 1*time.Hour, quietLogger(), nil)

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("scheduler didn't honor immediate cancel")
	}
}

func TestRunPushApprovalPrune_PruneErrorDoesNotStopLoop(t *testing.T) {
	// Close the store so Prune returns "closed" errors; the loop
	// should still respect ctx cancel without hanging.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "push.db") + "?_journal=WAL"
	store, _ := sqlitestores.NewPushApprovalStore(dsn)
	_ = store.Close()

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go runPushApprovalPrune(runCtx, done, store, 30*time.Millisecond, quietLogger(), nil)

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("scheduler hung after Prune error")
	}
}
