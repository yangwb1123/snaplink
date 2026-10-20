package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/internal/pgtest"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func graceLifecycleConfig(t *testing.T, backend string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.OAuth.Backend = "memory"
	cfg.OAuth.RefreshToken.Enabled = true
	cfg.OAuth.RefreshToken.TTL = time.Hour
	cfg.OAuth.RefreshToken.RotationGraceWindow = time.Minute
	cfg.OAuth.RefreshToken.RotationGraceBackend = backend
	cfg.OAuth.SQLite.DSN = filepath.Join(t.TempDir(), "grace.db")
	return cfg
}

func waitGraceLifecycle(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("grace lifecycle did not drain")
	}
}

func TestRefreshGraceBuildFailureAfterLaterWiringError(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres", "memory", "disabled"} {
		t.Run(backend, func(t *testing.T) {
			cfg := graceLifecycleConfig(t, backend)
			if backend == "disabled" {
				cfg.OAuth.RefreshToken.RotationGraceWindow = 0
			}
			b := &appBuilder{cfg: cfg, logger: spi.NopLogger{}, schemaCtx: t.Context()}
			if backend == "postgres" {
				pool, err := sql.Open("pgx", pgtest.Schema(t))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = pool.Close() })
				b.pgDB = pool
			}
			t.Cleanup(func() {
				if b.refreshGracePruneCancel != nil {
					b.refreshGracePruneCancel()
					waitGraceLifecycle(t, b.refreshGracePruneDone)
				}
				closeIfCloser(b.refreshTokenStore)
			})
			cfg.CIBA.Enabled, cfg.CIBA.Backend = true, "invalid-lifecycle-test"
			err := b.wireOAuthGrantStores()
			if err == nil || !strings.Contains(err.Error(), "unknown ciba.backend") {
				t.Fatalf("want later wiring error, got %v", err)
			}
			if backend == "memory" || backend == "disabled" {
				if b.refreshGracePruneCancel != nil || b.refreshGracePruneDone != nil {
					t.Fatal("unowned grace cleanup handles acquired")
				}
				b.closeBuildFailure()
				return
			}
			assertGraceBuildFailureCleanup(t, b)
		})
	}
}

func assertGraceBuildFailureCleanup(t *testing.T, b *appBuilder) {
	t.Helper()
	if len(b.storageHealthSources) != 1 {
		t.Fatalf("grace health sources = %d, want 1", len(b.storageHealthSources))
	}
	source := b.storageHealthSources[0]
	if err := source.Ping(t.Context()); err != nil {
		t.Fatalf("grace was not live before failure cleanup: %v", err)
	}
	b.externalAuditClose = func(context.Context) error {
		select {
		case <-b.refreshGracePruneDone:
		default:
			t.Error("unrelated audit cleanup reached before grace drain/close")
		}
		return nil
	}
	b.closeBuildFailure()
	select {
	case <-b.refreshGracePruneDone:
	default:
		t.Fatal("failure cleanup returned without grace drain/close")
	}
	if err := source.Ping(t.Context()); err == nil {
		t.Fatal("grace store survived failure cleanup")
	}
	if b.pgDB != nil {
		if err := b.pgDB.PingContext(t.Context()); err != nil {
			t.Fatalf("caller-owned PostgreSQL pool closed: %v", err)
		}
	}
	b.closeBuildFailure()
}

func TestRefreshGraceBuildFailureClosesOwnedDatabase(t *testing.T) {
	store, err := sqlite.NewRefreshGraceStoreWithDSN(filepath.Join(t.TempDir(), "grace.db"), time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	db := store.DB()
	logger := spi.NopLogger{}
	done := closeGraceAfterPrune(store.CleanupDone(), store, logger)
	b := &appBuilder{logger: logger, refreshGracePruneCancel: store.CleanupStop(), refreshGracePruneDone: done}
	t.Cleanup(func() {
		store.CleanupStop()()
		waitGraceLifecycle(t, done)
	})
	b.closeBuildFailure()
	waitGraceLifecycle(t, done)
	if err := db.PingContext(t.Context()); err == nil {
		t.Fatal("owned SQLite database survived failure cleanup")
	}
	b.closeBuildFailure()
}

func TestRefreshGraceBuildAppTransfersSuccessfulOwnership(t *testing.T) {
	a, err := buildApp(graceLifecycleConfig(t, "sqlite"), spi.NopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	store, ok := a.server.RefreshGrace().(*sqlite.RefreshGraceStore)
	if !ok {
		t.Fatal("stock SQLite grace store not installed")
	}
	db := store.DB()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		shutdownSubsystems(ctx, a, spi.NopLogger{})
		// Also clean up on a failed handoff assertion, without racing Close.
		store.CleanupStop()()
		waitGraceLifecycle(t, store.CleanupDone())
		for db.PingContext(ctx) == nil && ctx.Err() == nil {
			time.Sleep(time.Millisecond)
		}
		// Captured sql.DB.Close is safe even if the wrapper is still closing.
		_ = db.Close()
		closeAppStores(a)
	})
	if a.refreshGracePruneCancel == nil || a.refreshGracePruneDone == nil {
		t.Fatal("successful build lost grace cleanup ownership")
	}
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatalf("successful build closed live grace database: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	shutdownSchedulers(ctx, a, spi.NopLogger{})
	waitGraceLifecycle(t, a.refreshGracePruneDone)
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("stock shutdown did not close owned grace database")
	}
}

type graceCloseSignal chan struct{}

func (closed graceCloseSignal) Close() error { close(closed); return nil }

func TestRefreshGraceDrainWaitHonorsDeadline(t *testing.T) {
	pruned, closed, canceled := make(chan struct{}), make(graceCloseSignal), make(chan struct{})
	logger := spi.NopLogger{}
	done := closeGraceAfterPrune(pruned, closed, logger)
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(pruned) })
		waitGraceLifecycle(t, done)
	})
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	stopScheduler(ctx, logger, func() { close(canceled) }, done, "grace drain timed out")
	select {
	case <-canceled:
	default:
		t.Fatal("expired drain did not cancel pruning")
	}
	select {
	case <-closed:
		t.Fatal("database closed under a blocked pruning worker")
	default:
	}
	release.Do(func() { close(pruned) })
	waitGraceLifecycle(t, done)
	select {
	case <-closed:
	default:
		t.Fatal("asynchronous drain did not close the database")
	}
}

func TestRefreshGraceShutdownDrainsThenClosesOwnedDatabase(t *testing.T) {
	store, err := sqlite.NewRefreshGraceStoreWithDSN(filepath.Join(t.TempDir(), "grace.db"), time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	db := store.DB()
	logger := spi.NopLogger{}
	done := closeGraceAfterPrune(store.CleanupDone(), store, logger)
	select {
	case <-done:
		t.Fatal("grace database closed while the runtime was active")
	default:
	}
	a := &app{refreshGracePruneCancel: store.CleanupStop(), refreshGracePruneDone: done}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	shutdownSchedulers(ctx, a, logger)
	select {
	case <-done:
	default:
		t.Fatal("shutdown returned before grace resources drained")
	}
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("DSN-owned database survived shutdown")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
}
