package wasmauthz_test

// Authorize round-trip + fail-closed tests. policy.wasm is a real compiled
// WASM module (see testdata/policy.c) implementing a small, deterministic
// test policy; malformed.wasm/trap.wasm/infiniteloop.wasm each exercise ONE
// distinct fail-closed path (malformed JSON response, guest trap, timeout)
// per the package doc's "Fail-closed" contract: every Authorize error MUST
// be treated by the caller as a denial.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/lifecycle/wasmauthz"
)

func newTestEngine(t *testing.T, fixture string) *wasmauthz.Engine {
	t.Helper()
	eng, err := wasmauthz.New(context.Background(), loadFixture(t, fixture))
	if err != nil {
		t.Fatalf("New(%s): %v", fixture, err)
	}
	t.Cleanup(func() { _ = eng.Close(context.Background()) })
	return eng
}

func TestAuthorize_AllowAliceRead(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(t, "policy.wasm")
	dec, err := eng.Authorize(context.Background(), wasmauthz.Request{
		Subject: "alice", Action: "read", Resource: "doc:1",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("Decision = %+v, want Allowed=true (alice may read)", dec)
	}
	if dec.Reason != "alice may read" {
		t.Errorf("Reason = %q, want %q", dec.Reason, "alice may read")
	}
}

func TestAuthorize_AllowAdminContextOverride(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(t, "policy.wasm")
	dec, err := eng.Authorize(context.Background(), wasmauthz.Request{
		Subject: "bob", Action: "delete", Resource: "doc:9",
		Context: map[string]string{"role": "admin"},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("Decision = %+v, want Allowed=true (admin context override)", dec)
	}
	if dec.Reason != "context.role=admin override" {
		t.Errorf("Reason = %q, want %q", dec.Reason, "context.role=admin override")
	}
}

func TestAuthorize_Deny(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(t, "policy.wasm")
	dec, err := eng.Authorize(context.Background(), wasmauthz.Request{
		Subject: "bob", Action: "delete", Resource: "doc:9",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if dec.Allowed {
		t.Fatalf("Decision = %+v, want Allowed=false (no matching rule)", dec)
	}
	if dec.Reason != "no matching policy rule" {
		t.Errorf("Reason = %q, want %q", dec.Reason, "no matching policy rule")
	}
}

func TestAuthorize_MalformedResponse_FailsClosed(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(t, "malformed.wasm")
	dec, err := eng.Authorize(context.Background(), wasmauthz.Request{Subject: "alice", Action: "read"})
	if err == nil {
		t.Fatal("Authorize with a malformed-JSON guest response succeeded, want an error")
	}
	if !errors.Is(err, wasmauthz.ErrGuestFault) {
		t.Fatalf("error = %v, want ErrGuestFault", err)
	}
	if dec != (wasmauthz.Decision{}) {
		t.Fatalf("Decision on error = %+v, want zero value", dec)
	}
}

func TestAuthorize_GuestTrap_FailsClosed(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(t, "trap.wasm")
	_, err := eng.Authorize(context.Background(), wasmauthz.Request{Subject: "alice", Action: "read"})
	if err == nil {
		t.Fatal("Authorize against a guest that traps (unreachable) succeeded, want an error")
	}
}

func TestAuthorize_Timeout_FailsClosed(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(t, "infiniteloop.wasm")
	// A short deadline on the CALLER's context, well under
	// wasmauthz.DefaultCallTimeout, so the test proves ctx cancellation
	// actually interrupts a genuinely looping guest without waiting for the
	// package's own (much longer) default bound.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := eng.Authorize(ctx, wasmauthz.Request{Subject: "alice", Action: "read"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Authorize against an infinite-looping guest succeeded, want a timeout error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Authorize took %v to fail, want it bounded by the short context deadline", elapsed)
	}
}

func TestAuthorize_NilEngine_FailsClosed(t *testing.T) {
	t.Parallel()
	var eng *wasmauthz.Engine
	_, err := eng.Authorize(context.Background(), wasmauthz.Request{Subject: "alice", Action: "read"})
	if err == nil {
		t.Fatal("nil *Engine Authorize succeeded, want an error")
	}
}

func TestAuthorize_AfterClose_FailsClosed(t *testing.T) {
	t.Parallel()
	eng, err := wasmauthz.New(context.Background(), loadFixture(t, "policy.wasm"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = eng.Authorize(context.Background(), wasmauthz.Request{Subject: "alice", Action: "read"})
	if err == nil {
		t.Fatal("Authorize after Close succeeded, want an error")
	}
}
