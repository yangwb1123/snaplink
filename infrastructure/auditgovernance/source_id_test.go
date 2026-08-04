package auditgovernance

import (
	"strings"
	"testing"
)

func TestTenantSourceIDIsStableDistinctAndOpaque(t *testing.T) {
	first, err := TenantSourceID("snaplink-commerce", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	repeated, _ := TenantSourceID("snaplink-commerce", "tenant-a")
	second, _ := TenantSourceID("snaplink-commerce", "tenant-b")
	if first != repeated || first == second {
		t.Fatalf("source IDs are not stable and distinct: %q %q %q", first, repeated, second)
	}
	if strings.Contains(first, "tenant-a") || !strings.HasPrefix(first, "snaplink-commerce.") {
		t.Fatalf("source ID is not opaque or namespaced: %q", first)
	}
}

func TestTenantSourceIDRejectsAmbiguousInputs(t *testing.T) {
	for _, input := range []struct{ prefix, tenant string }{
		{"", "tenant-a"}, {"bad prefix", "tenant-a"}, {".bad", "tenant-a"},
		{"bad.", "tenant-a"}, {strings.Repeat("a", maxSourcePrefixBytes+1), "tenant-a"},
		{"billing", ""}, {"billing", " tenant-a"},
	} {
		if _, err := TenantSourceID(input.prefix, input.tenant); err == nil {
			t.Fatalf("TenantSourceID(%q, %q) succeeded", input.prefix, input.tenant)
		}
	}
}
