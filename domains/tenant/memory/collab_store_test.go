package memory

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/tenant"
)

func TestExternalUserStore_AddGetRemove(t *testing.T) {
	ctx := context.Background()
	s := NewExternalUserStore()

	if _, err := s.Get(ctx, "guest", "u1"); err != tenant.ErrNoGuestRecord {
		t.Fatalf("Get on empty store: err=%v want ErrNoGuestRecord", err)
	}

	rec := &tenant.GuestRecord{
		GuestTenantID:     "guest",
		HomeTenantID:      "home",
		ExternalSubjectID: "u1",
		Roles:             []string{"read"},
	}
	if err := s.Add(ctx, rec); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := s.Get(ctx, "guest", "u1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HomeTenantID != "home" || len(got.Roles) != 1 || got.Roles[0] != "read" {
		t.Errorf("Get returned %+v", got)
	}

	// Mutating the returned pointer must not corrupt the store (defensive copy).
	got.HomeTenantID = "tampered"
	got2, _ := s.Get(ctx, "guest", "u1")
	if got2.HomeTenantID != "home" {
		t.Errorf("store was mutated via returned pointer: %+v", got2)
	}

	if err := s.Remove(ctx, "guest", "u1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := s.Get(ctx, "guest", "u1"); err != tenant.ErrNoGuestRecord {
		t.Fatalf("Get after Remove: err=%v want ErrNoGuestRecord", err)
	}
	// Idempotent.
	if err := s.Remove(ctx, "guest", "u1"); err != nil {
		t.Fatalf("Remove (already gone) should be nil, got %v", err)
	}
}

func TestExternalUserStore_AddUpserts(t *testing.T) {
	ctx := context.Background()
	s := NewExternalUserStore()
	_ = s.Add(ctx, &tenant.GuestRecord{GuestTenantID: "g", HomeTenantID: "h", ExternalSubjectID: "u1", Roles: []string{"read"}})
	_ = s.Add(ctx, &tenant.GuestRecord{GuestTenantID: "g", HomeTenantID: "h", ExternalSubjectID: "u1", Roles: []string{"read", "write"}})

	all, err := s.ListByGuestTenant(ctx, "g")
	if err != nil {
		t.Fatalf("ListByGuestTenant: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected upsert to keep exactly 1 record, got %d", len(all))
	}
	if len(all[0].Roles) != 2 {
		t.Errorf("expected updated roles, got %v", all[0].Roles)
	}
}

func TestExternalUserStore_AddRejectsInvalid(t *testing.T) {
	ctx := context.Background()
	s := NewExternalUserStore()
	if err := s.Add(ctx, &tenant.GuestRecord{GuestTenantID: "g", ExternalSubjectID: "u1"}); err == nil {
		t.Fatal("expected validation error for missing home_tenant_id")
	}
}

func TestExternalUserStore_ListByGuestTenantIsolatesTenants(t *testing.T) {
	ctx := context.Background()
	s := NewExternalUserStore()
	_ = s.Add(ctx, &tenant.GuestRecord{GuestTenantID: "g1", HomeTenantID: "h", ExternalSubjectID: "u1"})
	_ = s.Add(ctx, &tenant.GuestRecord{GuestTenantID: "g2", HomeTenantID: "h", ExternalSubjectID: "u2"})

	g1, _ := s.ListByGuestTenant(ctx, "g1")
	if len(g1) != 1 || g1[0].ExternalSubjectID != "u1" {
		t.Errorf("g1 roster leaked or missing: %+v", g1)
	}
}

func TestCollaborationStore_PutIsTrustedRemove(t *testing.T) {
	ctx := context.Background()
	s := NewCollaborationStore()

	// Fail-closed default: no row ⇒ not trusted.
	trusted, err := s.IsTrusted(ctx, "guest", "home")
	if err != nil || trusted {
		t.Fatalf("IsTrusted on empty store: trusted=%v err=%v (want false, nil)", trusted, err)
	}

	if err := s.Put(ctx, &tenant.TenantCollaboration{GuestTenantID: "guest", HomeTenantID: "home"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	trusted, err = s.IsTrusted(ctx, "guest", "home")
	if err != nil || !trusted {
		t.Fatalf("IsTrusted after Put: trusted=%v err=%v (want true, nil)", trusted, err)
	}
	// Trust is directional: home does NOT automatically trust guest back.
	reverse, _ := s.IsTrusted(ctx, "home", "guest")
	if reverse {
		t.Error("trust must not be symmetric")
	}

	if err := s.Remove(ctx, "guest", "home"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	trusted, _ = s.IsTrusted(ctx, "guest", "home")
	if trusted {
		t.Error("expected no trust after Remove")
	}
}

func TestCollaborationStore_PutRejectsInvalid(t *testing.T) {
	ctx := context.Background()
	s := NewCollaborationStore()
	if err := s.Put(ctx, &tenant.TenantCollaboration{GuestTenantID: "acme", HomeTenantID: "acme"}); err == nil {
		t.Fatal("expected validation error for guest==home tenant")
	}
}

func TestCollaborationStore_ListByGuestTenant(t *testing.T) {
	ctx := context.Background()
	s := NewCollaborationStore()
	_ = s.Put(ctx, &tenant.TenantCollaboration{GuestTenantID: "guest", HomeTenantID: "home1"})
	_ = s.Put(ctx, &tenant.TenantCollaboration{GuestTenantID: "guest", HomeTenantID: "home2"})
	_ = s.Put(ctx, &tenant.TenantCollaboration{GuestTenantID: "other", HomeTenantID: "home1"})

	list, err := s.ListByGuestTenant(ctx, "guest")
	if err != nil {
		t.Fatalf("ListByGuestTenant: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 trust rows for guest tenant, got %d", len(list))
	}
}

var (
	_ tenant.ExternalUserStore  = (*ExternalUserStore)(nil)
	_ tenant.CollaborationStore = (*CollaborationStore)(nil)
)
