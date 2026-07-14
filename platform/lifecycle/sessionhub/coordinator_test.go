package sessionhub

import (
	"context"
	"errors"
	"testing"
	"time"
)

// recordingSessionTerminator is a real, minimal CoreSessionTerminator that
// records what it was asked to destroy — no Memory* implementation of this
// single-method narrow interface exists to reuse (it's a structural adapter
// over core.SessionManager.Destroy), so a tiny in-package recorder is the
// standard way to observe Coordinator's orchestration in a unit test.
type recordingSessionTerminator struct {
	destroyed []string
	err       error
}

func (r *recordingSessionTerminator) Destroy(_ context.Context, sessionID string) error {
	r.destroyed = append(r.destroyed, sessionID)
	return r.err
}

type recordingOIDCTrigger struct {
	calls []struct{ subject, sid string }
}

func (r *recordingOIDCTrigger) TriggerBackchannelLogout(_ context.Context, subject, sid string) {
	r.calls = append(r.calls, struct{ subject, sid string }{subject, sid})
}

type recordingSAMLTrigger struct {
	calls []struct{ subject, exclude string }
}

func (r *recordingSAMLTrigger) Fanout(_ context.Context, subject, excludeSPEntityID string) {
	r.calls = append(r.calls, struct{ subject, exclude string }{subject, excludeSPEntityID})
}

func TestCoordinator_Logout_OnlyCoreLeg(t *testing.T) {
	t.Parallel()
	links := NewMemoryLinkStore(0)
	core := &recordingSessionTerminator{}
	oidcTrig := &recordingOIDCTrigger{}
	samlTrig := &recordingSAMLTrigger{}
	c := NewCoordinator(links, core, oidcTrig, nil)
	c.SetSAMLTrigger(samlTrig)

	ctx := context.Background()
	gsid := NewGlobalSID()
	if err := c.Link(ctx, gsid, ProtocolCore, "sess-1", "user-1"); err != nil {
		t.Fatalf("Link: %v", err)
	}

	if err := c.Logout(ctx, gsid); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if len(core.destroyed) != 1 || core.destroyed[0] != "sess-1" {
		t.Fatalf("core.destroyed = %v, want [sess-1]", core.destroyed)
	}
	// Every login is an OIDC login on this server: the BCL trigger fires
	// unconditionally when wired, regardless of whether SAML was involved.
	if len(oidcTrig.calls) != 1 || oidcTrig.calls[0].subject != "user-1" || oidcTrig.calls[0].sid != "sess-1" {
		t.Fatalf("oidcTrig.calls = %+v", oidcTrig.calls)
	}
	// No SAML leg was recorded ⇒ "where applicable" does not apply here.
	if len(samlTrig.calls) != 0 {
		t.Fatalf("samlTrig.calls = %+v, want none", samlTrig.calls)
	}

	// Logout cleans up: a second call sees no links.
	if err := c.Logout(ctx, gsid); !errors.Is(err, ErrUnknownGlobalSID) {
		t.Fatalf("second Logout err = %v, want ErrUnknownGlobalSID", err)
	}
}

func TestCoordinator_Logout_CoreAndSAMLLegs(t *testing.T) {
	t.Parallel()
	links := NewMemoryLinkStore(0)
	core := &recordingSessionTerminator{}
	oidcTrig := &recordingOIDCTrigger{}
	samlTrig := &recordingSAMLTrigger{}
	c := NewCoordinator(links, core, oidcTrig, nil)
	c.SetSAMLTrigger(samlTrig)

	ctx := context.Background()
	gsid := NewGlobalSID()
	_ = c.Link(ctx, gsid, ProtocolCore, "sess-1", "user-1")
	_ = c.Link(ctx, gsid, ProtocolSAML, "sess-1", "user-1")

	if err := c.Logout(ctx, gsid); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if len(core.destroyed) != 1 {
		t.Fatalf("core.destroyed = %v", core.destroyed)
	}
	if len(oidcTrig.calls) != 1 {
		t.Fatalf("oidcTrig.calls = %+v", oidcTrig.calls)
	}
	if len(samlTrig.calls) != 1 || samlTrig.calls[0].subject != "user-1" || samlTrig.calls[0].exclude != "" {
		t.Fatalf("samlTrig.calls = %+v", samlTrig.calls)
	}
}

func TestCoordinator_Logout_UnknownGlobalSID(t *testing.T) {
	t.Parallel()
	c := NewCoordinator(nil, nil, nil, nil)
	if err := c.Logout(context.Background(), "does-not-exist"); !errors.Is(err, ErrUnknownGlobalSID) {
		t.Fatalf("err = %v, want ErrUnknownGlobalSID", err)
	}
}

func TestCoordinator_Logout_EmptyGlobalSID(t *testing.T) {
	t.Parallel()
	c := NewCoordinator(nil, nil, nil, nil)
	if err := c.Logout(context.Background(), ""); !errors.Is(err, ErrEmptyGlobalSID) {
		t.Fatalf("err = %v, want ErrEmptyGlobalSID", err)
	}
	if err := c.Link(context.Background(), "", ProtocolCore, "x", "y"); !errors.Is(err, ErrEmptyGlobalSID) {
		t.Fatalf("Link empty gsid err = %v, want ErrEmptyGlobalSID", err)
	}
}

// TestCoordinator_Logout_NilLegsNeverPanics documents the fail-open posture:
// a Coordinator with no CoreSessionTerminator/OIDCLogoutTrigger/SAMLLogoutTrigger
// wired (matching a server that hasn't wired a SessionManager or the optional
// fan-out mechanisms) still Logout()s cleanly — it just has nothing to do
// beyond the bookkeeping cleanup.
func TestCoordinator_Logout_NilLegsNeverPanics(t *testing.T) {
	t.Parallel()
	c := NewCoordinator(nil, nil, nil, nil)
	ctx := context.Background()
	gsid := NewGlobalSID()
	_ = c.Link(ctx, gsid, ProtocolCore, "sess-1", "user-1")
	_ = c.Link(ctx, gsid, ProtocolSAML, "sess-1", "user-1")

	if err := c.Logout(ctx, gsid); err != nil {
		t.Fatalf("Logout: %v", err)
	}
}

// TestCoordinator_Logout_CoreDestroyErrorDoesNotBlockFanOut mirrors the rest
// of the codebase's fail-open posture: a store error destroying one leg must
// not prevent the OIDC/SAML fan-outs (or the cleanup) from running.
func TestCoordinator_Logout_CoreDestroyErrorDoesNotBlockFanOut(t *testing.T) {
	t.Parallel()
	core := &recordingSessionTerminator{err: errors.New("boom")}
	oidcTrig := &recordingOIDCTrigger{}
	c := NewCoordinator(nil, core, oidcTrig, nil)

	ctx := context.Background()
	gsid := NewGlobalSID()
	_ = c.Link(ctx, gsid, ProtocolCore, "sess-1", "user-1")

	if err := c.Logout(ctx, gsid); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if len(oidcTrig.calls) != 1 {
		t.Fatalf("oidcTrig.calls = %+v, want fan-out to still run", oidcTrig.calls)
	}
}

// bouncingOIDCTrigger simulates a FUTURE cross-protocol receiver that, upon
// observing the OIDC BCL fan-out this trigger stands in for, itself calls
// back into the SAME Coordinator.Logout for the SAME global_sid — e.g. an
// operator wiring the SAML SP-side SLO receiver (or an OIDC back-channel
// logout receiver) to drive Coordinator.Logout instead of just destroying
// its own local session, closing a cycle back into this Coordinator. c is
// wired AFTER construction (NewCoordinator needs the trigger before the
// Coordinator it points back into exists) — safe because Logout is never
// called until the test invokes it, well after both are wired.
//
// callCap is a defensive ceiling independent of the guard under test: if the
// production re-entrancy guard ever regressed, this would otherwise recurse
// until the goroutine stack overflows the process (unrecoverable, not just a
// failing test) — capping the self-inflicted recursion converts that failure
// mode into an assertable, harmless one (calls > 1).
type bouncingOIDCTrigger struct {
	c       *Coordinator
	ctx     context.Context
	gsid    GlobalSID
	calls   int
	callCap int
}

func (b *bouncingOIDCTrigger) TriggerBackchannelLogout(_ context.Context, _, _ string) {
	b.calls++
	if b.calls > b.callCap {
		return
	}
	// The bounce: re-enter Logout for the SAME global_sid, synchronously,
	// from within the fan-out Logout itself triggered.
	_ = b.c.Logout(b.ctx, b.gsid)
}

// TestCoordinator_Logout_BounceBackReentrancyDoesNotLoop is the critical
// regression test for the cross-protocol re-entrancy guard: it deliberately
// engineers a bounce-back (OIDC fan-out -> re-triggers Coordinator.Logout for
// the same global_sid, standing in for a future SAML/OIDC receiver closing
// that cycle for real) and asserts the recursion TERMINATES after exactly one
// bounced attempt, rather than looping/recursing without bound. Without
// enterPropagation's guard, the nested Logout call would find the SAME
// LinkRecords still present (DeleteAll only runs at the END of the outer
// call) and re-run the ENTIRE fan-out again, invoking this same trigger a
// second time, recursing forever.
func TestCoordinator_Logout_BounceBackReentrancyDoesNotLoop(t *testing.T) {
	t.Parallel()
	links := NewMemoryLinkStore(0)
	core := &recordingSessionTerminator{}
	ctx := context.Background()
	gsid := NewGlobalSID()

	bouncer := &bouncingOIDCTrigger{ctx: ctx, gsid: gsid, callCap: 10}
	c := NewCoordinator(links, core, bouncer, nil)
	bouncer.c = c

	_ = c.Link(ctx, gsid, ProtocolCore, "sess-1", "user-1")
	_ = c.Link(ctx, gsid, ProtocolSAML, "sess-1", "user-1")

	// Run off the test goroutine with a hard timeout: an actual infinite
	// loop (as opposed to a stack-overflowing recursion) would otherwise hang
	// the test forever instead of failing it.
	done := make(chan error, 1)
	go func() { done <- c.Logout(ctx, gsid) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("outer Logout: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Logout did not return — the re-entrancy guard failed to terminate the bounce-back")
	}

	// Exactly ONE bounce attempt happened: the outer call invoked the
	// trigger once (calls==1 recorded on entry), which synchronously called
	// Logout again — that NESTED call must be blocked at enterPropagation
	// BEFORE it reaches the trigger a second time. If the guard is missing
	// or broken, calls would hit callCap (10) instead of stopping at 1.
	if bouncer.calls != 1 {
		t.Fatalf("bouncer.calls = %d, want exactly 1 (the bounced re-entry must be blocked before invoking the trigger again)", bouncer.calls)
	}

	// The normal (non-looping) case must still be byte-identical: the core
	// leg was destroyed exactly once by the one legitimate propagation.
	if len(core.destroyed) != 1 || core.destroyed[0] != "sess-1" {
		t.Fatalf("core.destroyed = %v, want exactly [sess-1]", core.destroyed)
	}

	// The guard must not leak: once the outer call completes, its in-flight
	// marker is cleared, so a FRESH Logout for the same (now-cleaned-up)
	// gsid sees the ordinary ErrUnknownGlobalSID, never a stale
	// ErrLogoutInProgress.
	if err := c.Logout(ctx, gsid); !errors.Is(err, ErrUnknownGlobalSID) {
		t.Fatalf("post-completion Logout err = %v, want ErrUnknownGlobalSID (guard must not leak the in-flight marker)", err)
	}
}

// TestCoordinator_Logout_ConcurrentSameGSIDSecondIsNoOp proves the guard's
// thread-safety directly (independent of the recursive-bounce scenario
// above): two goroutines racing Logout for the SAME still-linked global_sid
// (e.g. a double-submitted admin action, or two replicas racing a
// cluster-wide logout event) must fan out EXACTLY ONCE between them, never
// twice — the second (whichever loses the race) gets ErrLogoutInProgress.
func TestCoordinator_Logout_ConcurrentSameGSIDSecondIsNoOp(t *testing.T) {
	t.Parallel()
	links := NewMemoryLinkStore(0)
	core := &recordingSessionTerminator{}
	oidcTrig := &blockingOIDCTrigger{entered: make(chan struct{}), release: make(chan struct{})}
	c := NewCoordinator(links, core, oidcTrig, nil)

	ctx := context.Background()
	gsid := NewGlobalSID()
	_ = c.Link(ctx, gsid, ProtocolCore, "sess-1", "user-1")

	// Start the first Logout; it blocks INSIDE the OIDC trigger call so the
	// second Logout below is guaranteed to observe gsid as still in-flight
	// (rather than racing to complete first).
	firstDone := make(chan error, 1)
	go func() { firstDone <- c.Logout(ctx, gsid) }()
	<-oidcTrig.entered

	secondErr := c.Logout(ctx, gsid)
	if !errors.Is(secondErr, ErrLogoutInProgress) {
		t.Fatalf("concurrent second Logout err = %v, want ErrLogoutInProgress", secondErr)
	}

	close(oidcTrig.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Logout: %v", err)
	}
	if len(oidcTrig.calls) != 1 {
		t.Fatalf("oidcTrig.calls = %d, want exactly 1 (the concurrent duplicate must not re-trigger the fan-out)", len(oidcTrig.calls))
	}
}

// blockingOIDCTrigger holds TriggerBackchannelLogout open until release is
// closed, signaling entered first so a concurrent caller can deterministically
// observe the in-flight window instead of racing it.
type blockingOIDCTrigger struct {
	entered chan struct{}
	release chan struct{}
	calls   []string
}

func (b *blockingOIDCTrigger) TriggerBackchannelLogout(_ context.Context, subject, _ string) {
	b.calls = append(b.calls, subject)
	close(b.entered)
	<-b.release
}
