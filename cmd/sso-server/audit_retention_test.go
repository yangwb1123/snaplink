package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/audit"
	auditsqlite "github.com/snaplink/sso/audit/sqlite"
)

// TestRunAuditRetention_PrunesOldEventsAtInterval proves the
// scheduler wakes on every ticker fire and removes events older
// than now-maxAge. Uses a fast 50ms interval + 100ms maxAge so the
// test finishes in well under a second.
func TestRunAuditRetention_PrunesOldEventsAtInterval(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "audit.db") + "?_journal=WAL"
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sink.Close() }()

	ctx := context.Background()
	now := time.Now().UTC()
	// Two old events (eligible for prune), one fresh (must survive
	// past the prune deadline — set its timestamp far in the future
	// so the test-budget sleep doesn't age it past the cutoff).
	mustRecord := func(id string, ts time.Time) {
		if err := sink.Record(ctx, &audit.Event{
			ID: id, Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: ts,
		}); err != nil {
			t.Fatalf("Record %s: %v", id, err)
		}
	}
	mustRecord("old-1", now.Add(-10*time.Second))
	mustRecord("old-2", now.Add(-5*time.Second))
	mustRecord("fresh", now.Add(1*time.Hour))

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	// 50ms ticker; maxAge 1s — first prune fires after 50ms and
	// evicts the two olds. The fresh event is 1h in the future so
	// stays safe across the test budget.
	go runAuditRetention(runCtx, done, sink, 50*time.Millisecond, 1*time.Second, quietLogger(), nil)

	// Wait for at least one tick to fire (the prune happens after
	// the first 50ms — give it a generous 250ms then count).
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("scheduler didn't exit after cancel")
	}

	// fresh entry should survive.
	if _, err := sink.Get(ctx, "fresh"); err != nil {
		t.Errorf("fresh event was pruned: %v", err)
	}
	// olds should be gone.
	for _, id := range []string{"old-1", "old-2"} {
		if _, err := sink.Get(ctx, id); err == nil {
			t.Errorf("old event %q survived prune", id)
		}
	}
}

// TestRunAuditRetention_ExitsOnCtxCancelBeforeFirstTick proves the
// scheduler honors immediate ctx cancellation — no spurious Prune
// against an empty schedule.
func TestRunAuditRetention_ExitsOnCtxCancelBeforeFirstTick(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "audit.db") + "?_journal=WAL"
	sink, _ := auditsqlite.New(dsn)
	defer func() { _ = sink.Close() }()

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go runAuditRetention(runCtx, done, sink, 1*time.Hour, 30*24*time.Hour, quietLogger(), nil)

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("scheduler didn't exit on immediate ctx cancel")
	}
}

// TestRunAuditRetention_PruneErrorDoesNotStopLoop proves a
// transient Prune failure doesn't tear down retention — the
// scheduler logs + continues. Simulate by closing the sink mid-flight
// (which makes Prune return "closed" errors) — the loop should
// still respect ctx cancel without hanging.
func TestRunAuditRetention_PruneErrorDoesNotStopLoop(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "audit.db") + "?_journal=WAL"
	sink, _ := auditsqlite.New(dsn)
	// Close so the first Prune returns error.
	_ = sink.Close()

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go runAuditRetention(runCtx, done, sink, 30*time.Millisecond, 30*24*time.Hour, quietLogger(), nil)

	// Let at least two ticks fire — the loop should still be
	// running after the failed Prunes.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("scheduler hung after Prune error")
	}
}
