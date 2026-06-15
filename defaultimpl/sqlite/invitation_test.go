package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	sqlitestores "github.com/snaplink/sso/defaultimpl/sqlite"
)

func newInvitationStore(t *testing.T) *sqlitestores.InvitationStore {
	t.Helper()
	dsn := "file:invite_" + t.Name() + "?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
	s, err := sqlitestores.NewInvitationStore(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteInvitationStore_IssueConsumeSingleUse(t *testing.T) {
	s := newInvitationStore(t)
	ctx := context.Background()
	if err := s.Issue(ctx, &core.Invitation{Token: "t1", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleAdmin, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "t1")
	if err != nil || got.TenantID != "acme" || got.Role != core.TenantRoleAdmin {
		t.Fatalf("consume = %+v, %v; want acme/admin", got, err)
	}
	// Single-use.
	if _, err := s.Consume(ctx, "t1"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("second consume err = %v, want ErrInvitationNotFound", err)
	}
}

func TestSQLiteInvitationStore_MissingAndExpired(t *testing.T) {
	s := newInvitationStore(t)
	ctx := context.Background()
	if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("missing err = %v, want ErrInvitationNotFound", err)
	}
	_ = s.Issue(ctx, &core.Invitation{Token: "exp", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleMember, ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.Consume(ctx, "exp"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("expired err = %v, want ErrInvitationNotFound", err)
	}
}

func TestSQLiteInvitationStore_ListByTenant(t *testing.T) {
	s := newInvitationStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.Invitation{Token: "a1", TenantID: "acme", Email: "a1@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "a2", TenantID: "acme", Email: "a2@e.com", Role: core.TenantRoleAdmin, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "g1", TenantID: "globex", Email: "g@e.com", Role: core.TenantRoleGuest, ExpiresAt: exp})

	pending, err := s.ListByTenant(ctx, "acme")
	if err != nil || len(pending) != 2 {
		t.Fatalf("ListByTenant(acme) = %d, %v; want 2", len(pending), err)
	}
	for _, inv := range pending {
		if inv.TenantID != "acme" {
			t.Errorf("cross-tenant leak: %+v", inv)
		}
	}
	if other, _ := s.ListByTenant(ctx, "unknown"); len(other) != 0 {
		t.Errorf("unknown tenant roster = %d, want 0", len(other))
	}
}

func TestSQLiteInvitationStore_CrossTenantIsolation(t *testing.T) {
	s := newInvitationStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.Invitation{Token: "a1", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "g1", TenantID: "globex", Email: "g@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})

	// Consuming one tenant's invite must not touch the other's roster.
	if _, err := s.Consume(ctx, "a1"); err != nil {
		t.Fatalf("consume a1: %v", err)
	}
	if globex, _ := s.ListByTenant(ctx, "globex"); len(globex) != 1 {
		t.Errorf("globex roster wrongly affected: %d, want 1", len(globex))
	}
}
