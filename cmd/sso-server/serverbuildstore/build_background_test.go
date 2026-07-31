package serverbuildstore

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"

	"github.com/yangwb1123/snaplink/config"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	storageinline "github.com/yangwb1123/snaplink/interfaces/snapshot/storageinline"
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

// countingLogger is a real spi.Logger that tallies Error calls so a test can
// prove a recovered panic was routed through the logger — mirrors the
// identically-named helper in domains/metering/recorder_test.go.
type countingLogger struct {
	mu      sync.Mutex
	errMsgs []string
}

func (l *countingLogger) Info(string, ...any)  {}
func (l *countingLogger) Debug(string, ...any) {}
func (l *countingLogger) Error(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errMsgs = append(l.errMsgs, msg)
}
func (l *countingLogger) errorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errMsgs)
}

// panickySnapshotStorage panics on its first List call and behaves like an
// empty inline store afterward — used to prove pruneSnapshotSafe's recover()
// keeps RunSnapshotRetention's ticker loop (and the whole process) alive
// across a panicking Storage implementation, rather than letting the panic
// escape an unrecovered permanent background goroutine (fatal to the entire
// process, not just this retention tick).
type panickySnapshotStorage struct {
	mu    sync.Mutex
	calls int
}

func (p *panickySnapshotStorage) Put(context.Context, string, []byte) error { return nil }
func (p *panickySnapshotStorage) Get(context.Context, string) ([]byte, error) {
	return nil, snapshot.ErrSnapshotNotFound
}
func (p *panickySnapshotStorage) Delete(context.Context, string) error { return nil }
func (p *panickySnapshotStorage) List(context.Context) ([]string, error) {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if n == 1 {
		panic("simulated storage panic")
	}
	return nil, nil
}
func (p *panickySnapshotStorage) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// waitFor polls fn at 5ms intervals until it returns true or budget elapses.
func waitFor(t *testing.T, budget time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", budget)
}

// TestRunSnapshotRetention_RecoversStoragePanic proves pruneSnapshotSafe's
// recover() keeps the permanent RunSnapshotRetention goroutine (and thus the
// whole process) alive when the operator-selected snapshot.Storage panics on
// one tick. Pre-fix (no recover around the storage.List/Delete calls) this
// panic would propagate out of an unrecovered goroutine and crash the entire
// test binary — not just fail this assertion.
func TestRunSnapshotRetention_RecoversStoragePanic(t *testing.T) {
	t.Parallel()
	storage := &panickySnapshotStorage{}
	logger := &countingLogger{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	// Short interval so both the panicking first tick and a healthy
	// second tick fire within the test budget.
	go RunSnapshotRetention(ctx, done, storage, 20*time.Millisecond, 5, logger, nil)

	waitFor(t, 2*time.Second, func() bool { return storage.callCount() >= 2 })
	if logger.errorCount() == 0 {
		t.Fatal("expected the recovered panic to be logged via logger.Error")
	}

	cancel()
	waitClosed(t, done, 2*time.Second)
}
