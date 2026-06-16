package sso_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

// RevokeTenantRefreshTokens enumerates a tenant's clients and purges every
// refresh token bound to them, leaving other tenants untouched. It is the
// active-revocation companion to the lazy suspension check.
func TestServer_RevokeTenantRefreshTokens(t *testing.T) {
	ctx := context.Background()

	clients := defaultimpl.NewMemoryClientStore()
	for _, c := range []*sso.Client{
		{ID: "ca", TenantID: "t1"},
		{ID: "cb", TenantID: "t1"},
		{ID: "cc", TenantID: "t2"},
	} {
		if err := clients.Add(ctx, c); err != nil {
			t.Fatalf("add client %s: %v", c.ID, err)
		}
	}

	rts := defaultimpl.NewMemoryRefreshTokenStore()
	mk := func(tok, client string) {
		if err := rts.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: "u", ClientID: client, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("issue %s: %v", tok, err)
		}
	}
	mk("t1a", "ca")
	mk("t1b", "cb")
	mk("t2a", "cc")

	srv := sso.NewServer(
		sso.WithIssuer("sso-test"),
		sso.WithClientStore(clients),
		sso.WithRefreshTokenStore(rts, time.Hour),
	)

	n, err := srv.RevokeTenantRefreshTokens(ctx, "t1")
	if err != nil {
		t.Fatalf("RevokeTenantRefreshTokens: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked %d, want 2 (t1 has 2 clients, 1 token each)", n)
	}
	// A client outside the tenant keeps its token.
	if _, err := rts.Inspect(ctx, "t2a"); err != nil {
		t.Fatalf("t2 token should survive: %v", err)
	}
	// Empty tenant is a no-op (no accidental fleet-wide wipe).
	if blank, _ := srv.RevokeTenantRefreshTokens(ctx, ""); blank != 0 {
		t.Fatalf("empty tenant revoked %d, want 0", blank)
	}
}

// RevokeTenantRefreshTokens also destroys the tenant's active sessions via the
// direct SessionTenantIndex path (sessions stamped with the tenant at login),
// leaving other tenants' and untagged sessions alive.
func TestServer_RevokeTenant_DestroysSessionsByIndex(t *testing.T) {
	ctx := context.Background()
	sm := defaultimpl.NewMemorySessionManager(time.Hour)
	keepGlobex, _ := sm.CreateWithMeta(ctx, "carol", sso.SessionMeta{TenantID: "t2"})
	keepUntagged, _ := sm.Create(ctx, "dave")
	acme1, _ := sm.CreateWithMeta(ctx, "alice", sso.SessionMeta{TenantID: "t1"})
	acme2, _ := sm.CreateWithMeta(ctx, "bob", sso.SessionMeta{TenantID: "t1"})

	srv := sso.NewServer(
		sso.WithIssuer("sso-test"),
		sso.WithSessionManager(sm),
	)

	if _, err := srv.RevokeTenantRefreshTokens(ctx, "t1"); err != nil {
		t.Fatalf("RevokeTenantRefreshTokens: %v", err)
	}
	for _, id := range []string{acme1.ID, acme2.ID} {
		if _, err := sm.Get(ctx, id); err == nil {
			t.Errorf("t1 session %s should be destroyed", id)
		}
	}
	if _, err := sm.Get(ctx, keepGlobex.ID); err != nil {
		t.Errorf("t2 session destroyed: %v", err)
	}
	if _, err := sm.Get(ctx, keepUntagged.ID); err != nil {
		t.Errorf("untagged session destroyed: %v", err)
	}
}

// When sessions weren't tenant-stamped at login (e.g. a SessionManager that
// doesn't persist TenantID, or sessions predating the binding), revocation
// still works through the membership-roster fallback: the tenant's members are
// enumerated and each member's sessions destroyed.
func TestServer_RevokeTenant_DestroysSessionsByRoster(t *testing.T) {
	ctx := context.Background()
	sm := defaultimpl.NewMemorySessionManager(time.Hour)
	// Sessions created WITHOUT a tenant stamp (so the index path finds nothing).
	alice, _ := sm.Create(ctx, "alice")
	bob, _ := sm.Create(ctx, "bob")
	outsider, _ := sm.Create(ctx, "carol")

	members := defaultimpl.NewMemoryTenantUserStore()
	for _, uid := range []string{"alice", "bob"} {
		if err := members.Add(ctx, &sso.TenantMembership{
			TenantID: "t1", UserID: uid, Role: sso.TenantRoleMember, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("add member %s: %v", uid, err)
		}
	}

	srv := sso.NewServer(
		sso.WithIssuer("sso-test"),
		sso.WithSessionManager(sm),
		sso.WithTenantUserStore(members),
	)

	if _, err := srv.RevokeTenantRefreshTokens(ctx, "t1"); err != nil {
		t.Fatalf("RevokeTenantRefreshTokens: %v", err)
	}
	for _, id := range []string{alice.ID, bob.ID} {
		if _, err := sm.Get(ctx, id); err == nil {
			t.Errorf("member session %s should be destroyed via roster", id)
		}
	}
	// A user not on the roster keeps their session.
	if _, err := sm.Get(ctx, outsider.ID); err != nil {
		t.Errorf("non-member session destroyed: %v", err)
	}
}
