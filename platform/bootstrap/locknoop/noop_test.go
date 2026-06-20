package noop_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/bootstrap/lock"
	"github.com/snaplink/sso/platform/bootstrap/locknoop"
)

func TestNew_SatisfiesInterface(t *testing.T) {
	var _ lock.Lock = noop.New()
}

func TestTryAcquire_AlwaysSucceeds(t *testing.T) {
	l := noop.New()
	h, err := l.TryAcquire(context.Background(), "any-key", time.Second)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if h == nil {
		t.Fatal("Handle nil — caller expects non-nil even from noop")
	}
}

func TestHandle_RenewReleaseAreIdempotent(t *testing.T) {
	l := noop.New()
	h, _ := l.TryAcquire(context.Background(), "k", time.Second)

	for range 3 {
		if err := h.Renew(context.Background()); err != nil {
			t.Errorf("Renew: %v", err)
		}
	}
	for range 2 {
		if err := h.Release(context.Background()); err != nil {
			t.Errorf("Release (double): %v", err)
		}
	}
}

func TestHandle_FencingTokenIsZero(t *testing.T) {
	// Contract: noop has no monotonic token because nothing's actually
	// fenced. Document it via test so the operator's mental model of
	// "noop returns 0" stays sticky.
	l := noop.New()
	h, _ := l.TryAcquire(context.Background(), "k", time.Second)
	if got := h.FencingToken(); got != 0 {
		t.Errorf("FencingToken = %d, want 0 (noop has no real fence)", got)
	}
}

func TestConcurrentAcquireOK(t *testing.T) {
	// Even though noop doesn't actually serialize, simultaneous calls
	// must not panic or race.
	l := noop.New()
	done := make(chan struct{}, 20)
	for range 20 {
		go func() {
			defer func() { done <- struct{}{} }()
			h, err := l.TryAcquire(context.Background(), "k", time.Second)
			if err != nil {
				t.Errorf("TryAcquire: %v", err)
			}
			_ = h.Renew(context.Background())
			_ = h.Release(context.Background())
		}()
	}
	for range 20 {
		<-done
	}
}
