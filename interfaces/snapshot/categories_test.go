package snapshot_test

import (
	"errors"
	"testing"

	"github.com/snaplink/sso/interfaces/snapshot"
)

func TestAllCategories_StableContents(t *testing.T) {
	t.Parallel()
	got := snapshot.AllCategories()
	want := []snapshot.ResourceCategory{
		snapshot.CategoryClients,
		snapshot.CategoryUsers,
		snapshot.CategoryRoles,
		snapshot.CategoryAssignments,
		snapshot.CategoryMenus,
		snapshot.CategoryNetPolicy,
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
	for _, bogus := range []string{"", "0", "2", "v1", "1.0"} {
		if snapshot.IsValidSchemaVersion(bogus) {
			t.Errorf("IsValidSchemaVersion(%q) returned true; only %q is currently supported", bogus, snapshot.SchemaVersion)
		}
	}
}
