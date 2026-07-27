package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryTenantUserStore_AddGetRemove(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()

	if err := s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u1", Role: core.TenantRoleMember, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, err := s.Get(ctx, "acme", "u1")
	if err != nil || got.Role != core.TenantRoleMember {
		t.Fatalf("get = %+v, %v; want role member", got, err)
	}

	if err := s.Remove(ctx, "acme", "u1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := s.Get(ctx, "acme", "u1"); !errors.Is(err, core.ErrNoMembership) {
		t.Errorf("get after remove err = %v, want ErrNoMembership", err)
	}
	// Remove is idempotent.
	if err := s.Remove(ctx, "acme", "u1"); err != nil {
		t.Errorf("idempotent remove err = %v, want nil", err)
	}
}

func TestMemoryTenantUserStore_GetMiss(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryTenantUserStore()
	if _, err := s.Get(context.Background(), "nope", "nobody"); !errors.Is(err, core.ErrNoMembership) {
		t.Errorf("get miss err = %v, want ErrNoMembership", err)
	}
}

func TestMemoryTenantUserStore_AddUpsertsRole(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()

	_ = s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u1", Role: core.TenantRoleMember, CreatedAt: time.Now()})
	_ = s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u1", Role: core.TenantRoleAdmin, CreatedAt: time.Now()})

	got, err := s.Get(ctx, "acme", "u1")
	if err != nil || got.Role != core.TenantRoleAdmin {
		t.Fatalf("get = %+v, %v; want role admin (upsert)", got, err)
	}
	// Upsert must not create a duplicate edge.
	roster, _ := s.ListByTenant(ctx, "acme")
	if len(roster) != 1 {
		t.Errorf("roster len = %d, want 1 (upsert, not duplicate)", len(roster))
	}
}

func TestMemoryTenantUserStore_ListByTenant(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	now := time.Now()

	_ = s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u1", Role: core.TenantRoleAdmin, CreatedAt: now})
	_ = s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u2", Role: core.TenantRoleMember, CreatedAt: now})
	_ = s.Add(ctx, &core.TenantMembership{TenantID: "globex", UserID: "u1", Role: core.TenantRoleGuest, CreatedAt: now})

	roster, err := s.ListByTenant(ctx, "acme")
	if err != nil || len(roster) != 2 {
		t.Fatalf("ListByTenant(acme) = %d, %v; want 2", len(roster), err)
	}
	for _, m := range roster {
		if m.TenantID != "acme" {
			t.Errorf("cross-tenant leak: %+v", m)
		}
	}
	if other, _ := s.ListByTenant(ctx, "unknown"); len(other) != 0 {
		t.Errorf("unknown tenant roster = %d, want 0", len(other))
	}
}

func TestMemoryTenantUserStore_ListByUser(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	now := time.Now()

	_ = s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u1", Role: core.TenantRoleAdmin, CreatedAt: now})
	_ = s.Add(ctx, &core.TenantMembership{TenantID: "globex", UserID: "u1", Role: core.TenantRoleGuest, CreatedAt: now})
	_ = s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u2", Role: core.TenantRoleMember, CreatedAt: now})

	orgs, err := s.ListByUser(ctx, "u1")
	if err != nil || len(orgs) != 2 {
		t.Fatalf("ListByUser(u1) = %d, %v; want 2", len(orgs), err)
	}
	for _, m := range orgs {
		if m.UserID != "u1" {
			t.Errorf("wrong user in u1 orgs: %+v", m)
		}
	}
	if other, _ := s.ListByUser(ctx, "ghost"); len(other) != 0 {
		t.Errorf("ghost orgs = %d, want 0", len(other))
	}
}

func TestMemoryTenantUserStore_CrossTenantIsolation(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	now := time.Now()

	_ = s.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u1", Role: core.TenantRoleAdmin, CreatedAt: now})
	_ = s.Add(ctx, &core.TenantMembership{TenantID: "globex", UserID: "u1", Role: core.TenantRoleMember, CreatedAt: now})

	// Removing from one tenant must not touch the same user's other-tenant edge.
	if err := s.Remove(ctx, "acme", "u1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := s.Get(ctx, "acme", "u1"); !errors.Is(err, core.ErrNoMembership) {
		t.Errorf("acme edge survived: %v", err)
	}
	if got, err := s.Get(ctx, "globex", "u1"); err != nil || got.Role != core.TenantRoleMember {
		t.Errorf("globex edge wrongly affected: %+v, %v", got, err)
	}
}
