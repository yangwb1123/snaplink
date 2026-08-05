package sso_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// RevokeTenantRefreshTokens enumerates a tenant's clients and purges every
// refresh token bound to them, leaving other tenants untouched. It is the
// active-revocation companion to the lazy suspension check.
func TestServer_RevokeTenantRefreshTokens(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	ctx := context.Background()
	sm := defaultimpl.NewMemorySessionManager(time.Hour)
	keepGlobex, _ := sm.CreateWithMeta(ctx, "carol", sso.SessionMeta{TenantID: "t2"})
	keepUntagged, _ := sm.Create(ctx, "dave")
	acme1, _ := sm.CreateWithMeta(ctx, "alice", sso.SessionMeta{TenantID: "t1"})
	acme2, _ := sm.CreateWithMeta(ctx, "bob", sso.SessionMeta{TenantID: "t1"})

	srv := sso.NewServer(
		sso.WithIssuer("sso-test"),
		sso.WithSessionManager(sm),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()), // tenant-scoped: refresh leg is a clean no-op
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
	t.Parallel()
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
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()), // tenant-scoped: refresh leg is a no-op, not unsupported
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

type failingTenantSessionManager struct{ core.SessionManager }

func (failingTenantSessionManager) Destroy(context.Context, string) error {
	return errors.New("injected tenant session destroy failure")
}

func TestServer_RevokeTenantCredentials_ReturnsSessionFailures(t *testing.T) {
	ctx := context.Background()
	base := defaultimpl.NewMemorySessionManager(time.Hour)
	session, _ := base.Create(ctx, "alice")
	members := defaultimpl.NewMemoryTenantUserStore()
	if err := members.Add(ctx, &sso.TenantMembership{
		TenantID: "t1", UserID: "alice", Role: sso.TenantRoleMember,
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	srv := sso.NewServer(
		sso.WithIssuer("sso-test"),
		sso.WithSessionManager(failingTenantSessionManager{SessionManager: base}),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()), // tenant-scoped: refresh leg contributes no results
		sso.WithTenantUserStore(members),
	)

	report := srv.RevokeTenantCredentials(ctx, "t1")
	if report.Complete() || report.SessionsRevoked != 0 || len(report.Results) != 1 {
		t.Fatalf("report = %+v", report)
	}
	result := report.Results[0]
	if result.Kind != "session" || result.ResourceID != session.ID ||
		result.Status != "failed" || result.IdempotencyKey == "" || result.Error == "" {
		t.Fatalf("result = %+v", result)
	}
}

// basicClientStore is a minimal core.ClientStore WITHOUT the
// TenantScopedClientStore extension — the embedder-store shape that must
// now degrade explicitly instead of silently succeeding.
type basicClientStore struct {
	clients map[string]*core.Client
}

func (b *basicClientStore) Get(_ context.Context, id string) (*core.Client, error) {
	if c, ok := b.clients[id]; ok {
		return c, nil
	}
	return nil, core.ErrNoSuchClient
}
func (b *basicClientStore) ValidateSecret(context.Context, string, string) error {
	return errors.New("invalid secret")
}
func (b *basicClientStore) List(context.Context) ([]*core.Client, error) {
	out := make([]*core.Client, 0, len(b.clients))
	for _, c := range b.clients {
		out = append(out, c)
	}
	return out, nil
}
func (b *basicClientStore) Add(context.Context, *core.Client) error    { return nil }
func (b *basicClientStore) Update(context.Context, *core.Client) error { return nil }
func (b *basicClientStore) Delete(context.Context, string) error       { return nil }
func (b *basicClientStore) RotateSecret(context.Context, string) (string, error) {
	return "", nil
}

// TestServer_RevokeTenantRefreshTokens_UnsupportedStoreDegradesExplicitly
// pins the silent-no-op fix: a client store without tenant-scoped
// enumeration yields a distinguishable failure (not (0, nil)), so the admin
// hook cannot mistake "backend unsupported" for "zero tokens existed".
func TestServer_RevokeTenantRefreshTokens_UnsupportedStoreDegradesExplicitly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clients := &basicClientStore{clients: map[string]*core.Client{
		"ca": {ID: "ca", TenantID: "t1"},
	}}
	rts := defaultimpl.NewMemoryRefreshTokenStore()
	_ = rts.Issue(ctx, "tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "ca", ExpiresAt: time.Now().Add(time.Hour),
	})
	srv := sso.NewServer(
		sso.WithIssuer("sso-test"),
		sso.WithClientStore(clients),
		sso.WithRefreshTokenStore(rts, time.Hour),
	)

	report := srv.RevokeTenantCredentials(ctx, "t1")
	if len(report.Results) == 0 {
		t.Fatal("unsupported store produced zero results — silent no-op regression")
	}
	unsupported := false
	for _, r := range report.Results {
		if r.Status == "failed" && r.Kind == "refresh_tokens" {
			unsupported = true
		}
	}
	if !unsupported {
		t.Fatalf("no refresh_tokens failure result: %+v", report.Results)
	}
	// The token is untouched (nothing could be purged) — but the report says so.
	if _, err := rts.Inspect(ctx, "tok"); err != nil {
		t.Fatalf("token should survive an unsupported purge: %v", err)
	}
}
