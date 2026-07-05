package serverbuildstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	auditsqlite "github.com/snaplink/sso/platform/audit/sqlite"

	"github.com/snaplink/sso/config"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/snapshot"
	storageinline "github.com/snaplink/sso/interfaces/snapshot/storageinline"
)

func TestBuildCIBA_MemorySqliteRedisUnknownBackendAndTransport(t *testing.T) {
	t.Parallel()
	store, transport, sqliteStore, err := BuildCIBA(config.CIBAConfig{}, testLogger(), nil)
	if err != nil || store == nil || transport == nil || sqliteStore != nil {
		t.Fatalf("memory: store=%v transport=%v sqliteStore=%v err=%v", store, transport, sqliteStore, err)
	}
	if _, _, _, err := BuildCIBA(config.CIBAConfig{Backend: "sqlite"}, testLogger(), nil); err == nil {
		t.Fatal("expected error: sqlite backend requires sqlite_dsn")
	}
	if _, _, _, err := BuildCIBA(config.CIBAConfig{Backend: "redis"}, testLogger(), nil); err == nil {
		t.Fatal("expected error: redis backend without a redis client")
	}
	if _, _, _, err := BuildCIBA(config.CIBAConfig{Backend: "carrier-pigeon"}, testLogger(), nil); err == nil {
		t.Fatal("expected error: unknown backend")
	}
	if _, _, _, err := BuildCIBA(config.CIBAConfig{Transport: "carrier-pigeon"}, testLogger(), nil); err == nil {
		t.Fatal("expected error: unknown transport")
	}
}

func TestBuildCIBA_SqliteReturnsTypedHandle(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "ciba.db") + "?_journal=WAL"
	store, transport, sqliteStore, err := BuildCIBA(config.CIBAConfig{Backend: "sqlite", SQLiteDSN: dsn}, testLogger(), nil)
	if err != nil {
		t.Fatalf("BuildCIBA: %v", err)
	}
	if store == nil || transport == nil || sqliteStore == nil {
		t.Fatal("sqlite backend must return a non-nil typed handle for readyz + prune wiring")
	}
}

// waitClosed fails the test if done is not closed within the timeout — the
// shared shutdown contract every RunX background loop in this file honors
// (close done on ctx cancellation).
func waitClosed(t *testing.T, done <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("loop did not close its done channel after context cancellation")
	}
}

func TestRunCIBAPrune_ExitsOnContextCancel(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "ciba-prune.db") + "?_journal=WAL"
	store, err := sqlitestores.NewCIBAStore(dsn)
	if err != nil {
		t.Fatalf("NewCIBAStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go RunCIBAPrune(ctx, done, store, time.Hour, testLogger(), nil)
	cancel()
	waitClosed(t, done, 2*time.Second)
}

func TestRunSnapshotRetention_ExitsOnContextCancel(t *testing.T) {
	t.Parallel()
	var storage snapshot.Storage = storageinline.New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go RunSnapshotRetention(ctx, done, storage, time.Hour, 5, testLogger(), nil)
	cancel()
	waitClosed(t, done, 2*time.Second)
}

func TestRunAuditRetention_ExitsOnContextCancel(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit-retention.db") + "?_journal=WAL"
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("auditsqlite.New: %v", err)
	}
	defer func() { _ = sink.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go RunAuditRetention(ctx, done, sink, time.Hour, 30*24*time.Hour, testLogger(), nil)
	cancel()
	waitClosed(t, done, 2*time.Second)
}
