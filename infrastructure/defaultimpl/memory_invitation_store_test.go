package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryInvitationStore_IssueConsumeSingleUse(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryInvitationStore()
	ctx := context.Background()
	if err := s.Issue(ctx, &core.Invitation{Token: "t1", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleMember, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "t1")
	if err != nil || got.TenantID != "acme" || got.Role != core.TenantRoleMember {
		t.Fatalf("consume = %+v, %v; want acme/member", got, err)
	}
	// Single-use.
	if _, err := s.Consume(ctx, "t1"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("second consume err = %v, want ErrInvitationNotFound", err)
	}
}

func TestMemoryInvitationStore_MissingAndExpired(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryInvitationStore()
	ctx := context.Background()
	if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("missing err = %v, want ErrInvitationNotFound", err)
	}
	_ = s.Issue(ctx, &core.Invitation{Token: "exp", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleMember, ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.Consume(ctx, "exp"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("expired err = %v, want ErrInvitationNotFound", err)
	}
}

func TestMemoryInvitationStore_ListByTenantPending(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryInvitationStore()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.Invitation{Token: "a1", TenantID: "acme", Email: "a1@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "a2", TenantID: "acme", Email: "a2@e.com", Role: core.TenantRoleAdmin, ExpiresAt: exp})
	// Expired invite must NOT appear in the pending roster.
	_ = s.Issue(ctx, &core.Invitation{Token: "old", TenantID: "acme", Email: "old@e.com", Role: core.TenantRoleMember, ExpiresAt: time.Now().Add(-time.Second)})

	pending, err := s.ListByTenant(ctx, "acme")
	if err != nil || len(pending) != 2 {
		t.Fatalf("ListByTenant(acme) = %d, %v; want 2 pending", len(pending), err)
	}
	for _, inv := range pending {
		if inv.TenantID != "acme" {
			t.Errorf("cross-tenant leak: %+v", inv)
		}
	}
}

func TestMemoryInvitationStore_CrossTenantIsolation(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryInvitationStore()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.Invitation{Token: "a1", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "g1", TenantID: "globex", Email: "g@e.com", Role: core.TenantRoleGuest, ExpiresAt: exp})

	acme, _ := s.ListByTenant(ctx, "acme")
	if len(acme) != 1 || acme[0].TenantID != "acme" {
		t.Fatalf("acme roster = %+v, want 1 acme invite", acme)
	}
	if other, _ := s.ListByTenant(ctx, "unknown"); len(other) != 0 {
		t.Errorf("unknown tenant roster = %d, want 0", len(other))
	}
	// Consuming one tenant's invite must not affect the other's.
	if _, err := s.Consume(ctx, "a1"); err != nil {
		t.Fatalf("consume a1: %v", err)
	}
	if globex, _ := s.ListByTenant(ctx, "globex"); len(globex) != 1 {
		t.Errorf("globex roster wrongly affected: %d, want 1", len(globex))
	}
}

func TestMemoryInvitationStore_RevokeByTenantEmail(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryInvitationStore()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	// Two live tokens for the same recipient (re-send) + another recipient + another tenant.
	_ = s.Issue(ctx, &core.Invitation{Token: "r1", TenantID: "acme", Email: "gone@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "r2", TenantID: "acme", Email: "gone@e.com", Role: core.TenantRoleAdmin, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "k1", TenantID: "acme", Email: "keep@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "g1", TenantID: "globex", Email: "gone@e.com", Role: core.TenantRoleGuest, ExpiresAt: exp})

	if err := s.Revoke(ctx, "acme", "gone@e.com"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// EVERY token for the recipient is dead — a revoked invite can never be accepted.
	if _, err := s.Consume(ctx, "r1"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("r1 after revoke err = %v, want ErrInvitationNotFound", err)
	}
	if _, err := s.Consume(ctx, "r2"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("r2 after revoke err = %v, want ErrInvitationNotFound", err)
	}
	if acme, _ := s.ListByTenant(ctx, "acme"); len(acme) != 1 || acme[0].Email != "keep@e.com" {
		t.Errorf("acme roster after revoke = %+v, want only keep@e.com", acme)
	}
	if globex, _ := s.ListByTenant(ctx, "globex"); len(globex) != 1 {
		t.Errorf("globex roster wrongly affected: %d, want 1", len(globex))
	}
	// Idempotent: nothing pending is a no-op, not an error (no pending-invite oracle).
	if err := s.Revoke(ctx, "acme", "gone@e.com"); err != nil {
		t.Errorf("repeat Revoke err = %v, want nil", err)
	}
}
