package compliance_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/compliance"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

// fixture wires the four memory stores an Eraser composes, pre-seeded
// with data for two subjects so cross-subject isolation is testable.
type fixture struct {
	users    *defaultimpl.MemoryUserProvider
	sessions *defaultimpl.MemorySessionManager
	refresh  *defaultimpl.MemoryRefreshTokenStore
	clients  *defaultimpl.MemoryClientStore
	eraser   *compliance.Eraser
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{
		users:    defaultimpl.NewMemoryUserProvider(),
		sessions: defaultimpl.NewMemorySessionManager(),
		refresh:  defaultimpl.NewMemoryRefreshTokenStore(),
		clients:  defaultimpl.NewMemoryClientStore(),
	}
	f.eraser = &compliance.Eraser{
		Users:    f.users,
		Sessions: f.sessions,
		Refresh:  f.refresh,
		Clients:  f.clients,
	}

	for _, id := range []string{"c1", "c2"} {
		if err := f.clients.Add(ctx, &core.Client{ID: id}); err != nil {
			t.Fatalf("add client %s: %v", id, err)
		}
	}
	for _, uid := range []string{"u1", "u2"} {
		if err := f.users.CreateOrUpdate(ctx, &core.User{ID: uid}); err != nil {
			t.Fatalf("create user %s: %v", uid, err)
		}
		if _, err := f.sessions.Create(ctx, uid); err != nil {
			t.Fatalf("create session %s: %v", uid, err)
		}
		// One refresh token per (user, client).
		for _, cid := range []string{"c1", "c2"} {
			tok := uid + "-" + cid + "-rt"
			err := f.refresh.Issue(ctx, tok, &oauth.RefreshToken{
				UserID:    uid,
				ClientID:  cid,
				ExpiresAt: time.Now().Add(time.Hour),
			})
			if err != nil {
				t.Fatalf("issue refresh %s: %v", tok, err)
			}
		}
	}
	return f
}

func TestEraseSubject_FullErasure(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	rep, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if rep.RefreshTokensDeleted != 2 {
		t.Errorf("RefreshTokensDeleted = %d, want 2", rep.RefreshTokensDeleted)
	}
	if rep.SessionsDestroyed != 1 {
		t.Errorf("SessionsDestroyed = %d, want 1", rep.SessionsDestroyed)
	}
	if !rep.UserDeleted {
		t.Error("UserDeleted = false, want true")
	}

	// u1 fully gone.
	if s, _ := f.sessions.ListByUser(ctx, "u1"); len(s) != 0 {
		t.Errorf("u1 still has %d sessions", len(s))
	}
	if _, err := f.users.GetByID(ctx, "u1"); err == nil {
		t.Error("u1 still retrievable after erasure")
	}
	if n, _ := f.refresh.DeleteAllForSubject(ctx, "u1", "c1"); n != 0 {
		t.Errorf("u1/c1 still has %d refresh tokens", n)
	}

	// u2 untouched (cross-subject isolation).
	if s, _ := f.sessions.ListByUser(ctx, "u2"); len(s) != 1 {
		t.Errorf("u2 sessions = %d, want 1 (collateral erasure)", len(s))
	}
	if _, err := f.users.GetByID(ctx, "u2"); err != nil {
		t.Errorf("u2 wrongly erased: %v", err)
	}
	if n, _ := f.refresh.DeleteAllForSubject(ctx, "u2", "c1"); n != 1 {
		t.Errorf("u2/c1 refresh tokens = %d, want 1", n)
	}
}

func TestEraseSubject_Idempotent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	if _, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{}); err != nil {
		t.Fatalf("first erase: %v", err)
	}
	rep, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err != nil {
		t.Fatalf("second erase: %v", err)
	}
	if rep.RefreshTokensDeleted != 0 || rep.SessionsDestroyed != 0 {
		t.Errorf("re-run deleted refresh=%d sessions=%d, want 0/0", rep.RefreshTokensDeleted, rep.SessionsDestroyed)
	}
}

func TestEraseSubject_DryRunMutatesNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	rep, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if rep.SessionsDestroyed != 1 {
		t.Errorf("dry-run SessionsDestroyed (projection) = %d, want 1", rep.SessionsDestroyed)
	}
	// Nothing actually removed.
	if s, _ := f.sessions.ListByUser(ctx, "u1"); len(s) != 1 {
		t.Errorf("dry-run destroyed sessions: %d remain, want 1", len(s))
	}
	if _, err := f.users.GetByID(ctx, "u1"); err != nil {
		t.Error("dry-run deleted the user")
	}
	if n, _ := f.refresh.DeleteAllForSubject(ctx, "u1", "c1"); n != 1 {
		t.Errorf("dry-run revoked refresh tokens: %d remain, want 1", n)
	}
}

func TestEraseSubject_SkipsUnwiredStores(t *testing.T) {
	ctx := context.Background()
	// Only a user provider wired; refresh + sessions absent.
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u1"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	e := &compliance.Eraser{Users: users}

	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if !rep.UserDeleted {
		t.Error("user not deleted")
	}
	if len(rep.Skipped) == 0 {
		t.Error("expected refresh + sessions recorded as skipped")
	}
}

func TestEraseSubject_EmptyUserID(t *testing.T) {
	f := newFixture(t)
	if _, err := f.eraser.EraseSubject(context.Background(), "", compliance.EraseOptions{}); err == nil {
		t.Fatal("expected error for empty user id")
	}
}
