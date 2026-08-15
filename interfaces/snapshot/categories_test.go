package snapshot_test

import (
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/snapshot"
)

func TestAllCategories_StableContents(t *testing.T) {
	t.Parallel()
	got := snapshot.AllCategories()
	want := []snapshot.ResourceCategory{
		snapshot.CategoryTenants,
		snapshot.CategoryTenantDomains,
		snapshot.CategoryConnections,
		snapshot.CategoryClients,
		snapshot.CategoryUsers,
		snapshot.CategoryPairwise,
		snapshot.CategoryRoles,
		snapshot.CategoryAssignments,
		snapshot.CategoryMenus,
		snapshot.CategoryNetPolicy,
		// v3 credential-portability categories are appended at the END so
		// the v1/v2 category order stays byte-identical.
		snapshot.CategoryWebAuthn,
		snapshot.CategoryTotpSeeds,
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, c := range want {
		if got[i] != c {
			t.Errorf("AllCategories[%d] = %q, want %q", i, got[i], c)
		}
	}
}

func TestAllCategories_NotShared(t *testing.T) {
	t.Parallel()
	// Each call must return an independent slice so callers can mutate
	// it (filter, append) without affecting subsequent callers.
	a := snapshot.AllCategories()
	b := snapshot.AllCategories()
	if len(a) == 0 {
		t.Fatal("AllCategories returned empty slice")
	}
	a[0] = "MUTATED"
	if b[0] == "MUTATED" {
		t.Error("AllCategories returns a shared backing array; mutating one slice corrupted another")
	}
}

func TestSnapshot_Validate_AcceptsCurrentSchema(t *testing.T) {
	t.Parallel()
	s := &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SourceNamespace: "test",
	}
	if err := s.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestSnapshot_Validate_RejectsUnknownSchema(t *testing.T) {
	t.Parallel()
	s := &snapshot.Snapshot{
		SchemaVersion:   "999",
		SourceNamespace: "test",
	}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected error on unknown schema version")
	}
	if !errors.Is(err, snapshot.ErrUnknownSchemaVersion) {
		t.Errorf("err = %v, want wrapped ErrUnknownSchemaVersion", err)
	}
}

func TestSnapshot_Validate_RequiresSourceNamespace(t *testing.T) {
	t.Parallel()
	s := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion,
		// no SourceNamespace
	}
	if err := s.Validate(); err == nil {
		t.Error("expected error on empty source_namespace")
	}
}

func TestIsValidSchemaVersion(t *testing.T) {
	t.Parallel()
	if !snapshot.IsValidSchemaVersion(snapshot.SchemaVersion) {
		t.Errorf("current SchemaVersion %q rejected by IsValidSchemaVersion", snapshot.SchemaVersion)
	}
	// v1 and v2 artifacts remain readable by v3 builds.
	if !snapshot.IsValidSchemaVersion("1") {
		t.Error("schema v1 must remain readable")
	}
	if !snapshot.IsValidSchemaVersion("2") {
		t.Error("schema v2 must remain readable during the v3 migration")
	}
	for _, bogus := range []string{"", "0", "4", "v1", "1.0"} {
		if snapshot.IsValidSchemaVersion(bogus) {
			t.Errorf("IsValidSchemaVersion(%q) returned true; only v1, v2 and %q are supported", bogus, snapshot.SchemaVersion)
		}
	}
}
