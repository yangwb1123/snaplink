package sessionhub

import (
	"context"
	"errors"
	"testing"
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
