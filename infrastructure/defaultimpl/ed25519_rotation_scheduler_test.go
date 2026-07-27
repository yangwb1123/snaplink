package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

// TestStartRotation_RotatesAndRetires drives the scheduler with short
// intervals: it must rotate (new kid != old), invoke OnRotate, and
// eventually retire the demoted key from JWKS after the grace period.
func TestStartRotation_RotatesAndRetires(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	seedKID := iss.KeyID()

	rotated := make(chan [2]string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := iss.StartRotation(ctx, defaultimpl.RotationConfig{
		Interval:    15 * time.Millisecond,
		GracePeriod: 20 * time.Millisecond,
		OnRotate:    func(o, n string) { rotated <- [2]string{o, n} },
	})

	var first [2]string
	select {
	case first = <-rotated:
	case <-time.After(time.Second):
		t.Fatal("no rotation observed")
	}
	if first[0] != seedKID {
		t.Errorf("first rotation oldKID = %q, want seed %q", first[0], seedKID)
	}
	if first[0] == first[1] {
		t.Fatal("rotation produced identical kids")
	}

	// The demoted seed key should leave JWKS once its grace elapses.
	deadline := time.Now().Add(time.Second)
	for {
		jwks, _ := iss.JWKS(ctx)
		present := false
		for _, k := range jwks {
			if k.Kid == seedKID {
				present = true
			}
		}
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("demoted seed key never retired from JWKS")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rotation loop did not stop on ctx cancel")
	}
}

// TestStartRotation_DisabledWhenIntervalZero proves a zero interval is a
// no-op returning an already-closed channel.
func TestStartRotation_DisabledWhenIntervalZero(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	done := iss.StartRotation(context.Background(), defaultimpl.RotationConfig{})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disabled scheduler should return a closed channel")
	}
}
