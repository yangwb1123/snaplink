package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/migrate"
	"github.com/snaplink/sso/tenant"
)

// TestMigration_StampsBaselineAndKeepsCascade proves the tenant backend
// records schema version 1 and that the ON DELETE CASCADE foreign key
// survives running through the migration runner (deleting a tenant
// removes its domains).
func TestMigration_StampsBaselineAndKeepsCascade(t *testing.T) {
	ctx := context.Background()
	s, err := New("file:" + filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if v, _ := migrate.CurrentVersion(ctx, s.db, "tenant"); v != 1 {
		t.Errorf("version = %d, want 1", v)
	}

	if err := s.PutTenant(ctx, &tenant.Tenant{ID: "t1", Slug: "t1", Name: "T1", Status: tenant.StatusActive}); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	if err := s.PutDomain(ctx, &tenant.Domain{Hostname: "t1.example.com", TenantID: "t1"}); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}
	if err := s.DeleteTenant(ctx, "t1"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	// CASCADE: the domain must be gone with its tenant.
	if _, err := s.GetDomain(ctx, "t1.example.com"); err == nil {
		t.Error("domain survived tenant delete — ON DELETE CASCADE not in effect after migration")
	}
}
