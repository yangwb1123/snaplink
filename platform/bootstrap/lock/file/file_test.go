//go:build unix

package file_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/bootstrap/lock"
	"github.com/snaplink/sso/platform/bootstrap/lock/file"
)

func TestAcquireRelease_RoundTrip(t *testing.T) {
	l := file.New(t.TempDir())
	h, err := l.TryAcquire(context.Background(), "boot", time.Second)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if h.FencingToken() == 0 {
		t.Errorf("file FencingToken should be non-zero (process-local seq), got 0")
	}
	if err := h.Renew(context.Background()); err != nil {
		t.Errorf("Renew (no-op): %v", err)
	}
	if err := h.Release(context.Background()); err != nil {
		t.Errorf("Release: %v", err)
	}
}

func TestSecondAcquire_GetsErrLocked(t *testing.T) {
	dir := t.TempDir()
	l := file.New(dir)
	h, err := l.TryAcquire(context.Background(), "boot", time.Second)
	if err != nil {
		t.Fatalf("first TryAcquire: %v", err)
	}
	t.Cleanup(func() { _ = h.Release(context.Background()) })

	// Same process, different Lock value, same file → flock blocks the
	// second descriptor immediately.
	l2 := file.New(dir)
	if _, err := l2.TryAcquire(context.Background(), "boot", time.Second); !errors.Is(err, lock.ErrLocked) {
		t.Errorf("second TryAcquire err = %v, want ErrLocked", err)
	}
}

func TestReleaseThenReacquire(t *testing.T) {
	dir := t.TempDir()
	l := file.New(dir)
	h, err := l.TryAcquire(context.Background(), "boot", time.Second)
	if err != nil {
		t.Fatalf("first TryAcquire: %v", err)
	}
	if err := h.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// After release another runner should be able to take the lock.
	h2, err := l.TryAcquire(context.Background(), "boot", time.Second)
	if err != nil {
		t.Fatalf("second TryAcquire after release: %v", err)
	}
	_ = h2.Release(context.Background())
}

func TestRelease_Idempotent(t *testing.T) {
	l := file.New(t.TempDir())
	h, err := l.TryAcquire(context.Background(), "k", time.Second)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if err := h.Release(context.Background()); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := h.Release(context.Background()); err != nil {
		t.Errorf("second Release should be nil, got %v", err)
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	l := file.New(t.TempDir())
	if _, err := l.TryAcquire(context.Background(), "", time.Second); err == nil {
		t.Fatal("expected error for empty key")
	}
}
