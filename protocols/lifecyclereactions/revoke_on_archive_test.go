package lifecyclereactions_test

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/lifecyclereactions"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// fixture wires the three real memory stores RevokeAccessOnArchive
// composes, pre-seeded with a session and refresh tokens (across two
// clients) for one user — no mocks, per AGENTS.md.
type fixture struct {
	sessions *defaultimpl.MemorySessionManager
	refresh  *defaultimpl.MemoryRefreshTokenStore
	clients  *defaultimpl.MemoryClientStore
}

func newFixture(t *testing.T, userID string) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{
		sessions: defaultimpl.NewMemorySessionManager(),
		refresh:  defaultimpl.NewMemoryRefreshTokenStore(),
		clients:  defaultimpl.NewMemoryClientStore(),
	}
	for _, cid := range []string{"c1", "c2"} {
		if err := f.clients.Add(ctx, &core.Client{ID: cid}); err != nil {
			t.Fatalf("add client %s: %v", cid, err)
		}
		tok := userID + "-" + cid + "-rt"
		err := f.refresh.Issue(ctx, tok, &oauth.RefreshToken{
			UserID:    userID,
			ClientID:  cid,
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("issue refresh token for %s: %v", cid, err)
		}
	}
	if _, err := f.sessions.Create(ctx, userID); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return f
}

func (f *fixture) refreshTokenCount(t *testing.T, userID string) int {
	t.Helper()
	n := 0
	for _, cid := range []string{"c1", "c2"} {
		count, err := f.refresh.CountForSubject(context.Background(), userID, cid)
		if err != nil {
			t.Fatalf("count refresh tokens for %s: %v", cid, err)
		}
		n += count
	}
	return n
}

func (f *fixture) sessionCount(t *testing.T, userID string) int {
	t.Helper()
	sessions, err := f.sessions.ListByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	return len(sessions)
}

func TestRevokeAccessOnArchive_RevokesSessionsAndRefreshTokens(t *testing.T) {
	const userID = "user-1"
	f := newFixture(t, userID)

	if got := f.refreshTokenCount(t, userID); got != 2 {
		t.Fatalf("precondition: refresh tokens = %d, want 2", got)
	}
	if got := f.sessionCount(t, userID); got != 1 {
		t.Fatalf("precondition: sessions = %d, want 1", got)
	}

	reaction := lifecyclereactions.RevokeAccessOnArchive(f.sessions, f.refresh, f.clients)
	if err := reaction(context.Background(), userID); err != nil {
		t.Fatalf("reaction() = %v, want nil", err)
	}

	if got := f.refreshTokenCount(t, userID); got != 0 {
		t.Fatalf("after revoke: refresh tokens = %d, want 0", got)
	}
	if got := f.sessionCount(t, userID); got != 0 {
		t.Fatalf("after revoke: sessions = %d, want 0", got)
	}
}

func TestRevokeAccessOnArchive_WiredThroughLifecycleEventBusEndToEnd(t *testing.T) {
	const userID = "user-2"
	f := newFixture(t, userID)

	bus := userlifecycle.NewLifecycleEventBus()
	bus.OnUserArchived(lifecyclereactions.RevokeAccessOnArchive(f.sessions, f.refresh, f.clients))

	rec := audit.New(audit.NewMemorySink(10))
	rec.AddSink(bus)

	// Drive the EXACT seam userlifecycle's admin handler / sweep use — no
	// direct call into the reaction, proving the bus->reaction wiring works
	// off the real EventAdminUserLifecycleChanged audit event.
	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "policy violation", "admin1", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, userID, tr)

	if got := f.refreshTokenCount(t, userID); got != 0 {
		t.Fatalf("after archive transition: refresh tokens = %d, want 0", got)
	}
	if got := f.sessionCount(t, userID); got != 0 {
		t.Fatalf("after archive transition: sessions = %d, want 0", got)
	}
}

func TestRevokeAccessOnArchive_NonArchiveTransitionDoesNotRevoke(t *testing.T) {
	const userID = "user-3"
	f := newFixture(t, userID)

	bus := userlifecycle.NewLifecycleEventBus()
	bus.OnUserArchived(lifecyclereactions.RevokeAccessOnArchive(f.sessions, f.refresh, f.clients))

	rec := audit.New(audit.NewMemorySink(10))
	rec.AddSink(bus)

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateSuspended, "", "admin1", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, userID, tr)

	if got := f.refreshTokenCount(t, userID); got != 2 {
		t.Fatalf("suspend must not revoke refresh tokens: got %d, want 2", got)
	}
	if got := f.sessionCount(t, userID); got != 1 {
		t.Fatalf("suspend must not destroy sessions: got %d, want 1", got)
	}
}

func TestRevokeAccessOnArchive_NilStoresSkipTheirLeg(t *testing.T) {
	const userID = "user-4"
	f := newFixture(t, userID)

	// Sessions-only: refresh/clients nil skips that leg without error.
	reaction := lifecyclereactions.RevokeAccessOnArchive(f.sessions, nil, nil)
	if err := reaction(context.Background(), userID); err != nil {
		t.Fatalf("reaction() = %v, want nil", err)
	}
	if got := f.sessionCount(t, userID); got != 0 {
		t.Fatalf("sessions = %d, want 0", got)
	}
	if got := f.refreshTokenCount(t, userID); got != 2 {
		t.Fatalf("refresh tokens should be untouched (nil refresh index): got %d, want 2", got)
	}
}

func TestRevokeAccessOnArchive_EmptyUserIDIsNoOp(t *testing.T) {
	f := newFixture(t, "user-5")
	reaction := lifecyclereactions.RevokeAccessOnArchive(f.sessions, f.refresh, f.clients)
	if err := reaction(context.Background(), ""); err != nil {
		t.Fatalf("reaction(\"\") = %v, want nil", err)
	}
}
