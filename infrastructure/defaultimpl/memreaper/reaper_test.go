package memreaper

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestStart_SweepsRepeatedlyUntilClosed(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	r := Start(5*time.Millisecond, func(time.Time) { calls.Add(1) })
	t.Cleanup(func() { _ = r.Close() })

	deadline := time.Now().Add(500 * time.Millisecond)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("sweep called %d times, want >= 3", got)
	}
}

func TestStart_NonPositiveIntervalReturnsNil(t *testing.T) {
	t.Parallel()
	if r := Start(0, func(time.Time) {}); r != nil {
		t.Errorf("Start(0, ...) = %v, want nil", r)
	}
	if r := Start(-time.Second, func(time.Time) {}); r != nil {
		t.Errorf("Start(-1s, ...) = %v, want nil", r)
	}
}

func TestReaper_CloseStopsFurtherSweeps(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	r := Start(2*time.Millisecond, func(time.Time) { calls.Add(1) })

	time.Sleep(20 * time.Millisecond)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	afterClose := calls.Load()
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != afterClose {
		t.Errorf("sweep count grew from %d to %d after Close", afterClose, got)
	}
}

func TestReaper_CloseIsIdempotentAndNilSafe(t *testing.T) {
	t.Parallel()
	r := Start(10*time.Millisecond, func(time.Time) {})
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	var nilReaper *Reaper
	if err := nilReaper.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}
