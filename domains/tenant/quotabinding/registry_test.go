package quotabinding_test

import (
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant/quotabinding"
)

func TestRegistryAllowsOneOAuthClientAcrossTenantSources(t *testing.T) {
	registry, err := quotabinding.NewRegistry([]quotabinding.Source{
		source("binding-a", "tenant-a", "billing:tenant-a"),
		source("binding-b", "tenant-b", "billing:tenant-b"),
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	for sourceSystem, expected := range map[string]string{
		"billing:tenant-a": "tenant-a", "billing:tenant-b": "tenant-b",
	} {
		if tenantID, ok := registry.Resolve("billing-relay", sourceSystem); !ok || tenantID != expected {
			t.Fatalf("Resolve(%q) = %q, %v", sourceSystem, tenantID, ok)
		}
	}
}

func TestRegistryRejectsCrossTenantSourceAndCompositeDuplicates(t *testing.T) {
	first := source("binding-a", "tenant-a", "billing:tenant")
	second := source("binding-b", "tenant-b", "billing:tenant")
	if _, err := quotabinding.NewRegistry([]quotabinding.Source{first, second}); !errors.Is(err, quotabinding.ErrConflict) {
		t.Fatalf("cross-tenant source error = %v", err)
	}
	second.TenantID, second.SourceSystem = "tenant-a", first.SourceSystem
	second.Enabled = false
	if _, err := quotabinding.NewRegistry([]quotabinding.Source{first, second}); !errors.Is(err, quotabinding.ErrConflict) {
		t.Fatalf("duplicate composite error = %v", err)
	}
}

func TestRegistryDesiredStateIsMonotonicAndRejectsEquivocation(t *testing.T) {
	first := source("binding-a", "tenant-a", "billing:tenant-a")
	registry, err := quotabinding.NewRegistry([]quotabinding.Source{first})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	disabled := first
	disabled.Enabled, disabled.Revision = false, 2
	if applied, err := registry.ApplyDesired([]quotabinding.Source{disabled}); err != nil || !applied {
		t.Fatalf("disable = %v, %v", applied, err)
	}
	if _, ok := registry.Resolve(first.ClientID, first.SourceSystem); ok {
		t.Fatal("disabled source still resolves")
	}
	if err := registry.Ready(t.Context()); !errors.Is(err, quotabinding.ErrNoEnabledSource) {
		t.Fatalf("Ready() error = %v", err)
	}
	if applied, err := registry.ApplyDesired([]quotabinding.Source{first}); !errors.Is(err, quotabinding.ErrStale) || applied {
		t.Fatalf("stale desired state = %v, %v", applied, err)
	}
	if err := registry.Ready(t.Context()); !errors.Is(err, quotabinding.ErrStale) {
		t.Fatalf("Ready() after stale state = %v", err)
	}
	equivocation := disabled
	equivocation.Enabled = true
	if _, err := registry.ApplyDesired([]quotabinding.Source{equivocation}); !errors.Is(err, quotabinding.ErrConflict) {
		t.Fatalf("same-revision equivocation error = %v", err)
	}
	if err := registry.Ready(t.Context()); !errors.Is(err, quotabinding.ErrConflict) {
		t.Fatalf("Ready() after equivocation = %v", err)
	}
	if applied, err := registry.ApplyDesired([]quotabinding.Source{disabled}); err != nil || applied {
		t.Fatalf("exact desired state = %v, %v", applied, err)
	}
	if err := registry.Ready(t.Context()); !errors.Is(err, quotabinding.ErrNoEnabledSource) {
		t.Fatalf("exact state did not clear desired error: %v", err)
	}
	reenabled := disabled
	reenabled.Enabled, reenabled.Revision = true, 3
	if applied, err := registry.ApplyDesired([]quotabinding.Source{reenabled}); err != nil || !applied {
		t.Fatalf("reenable = %v, %v", applied, err)
	}
	if err := registry.Ready(t.Context()); err != nil {
		t.Fatalf("Ready() after re-enable: %v", err)
	}
}

func TestRegistryRejectsStaleBatchAtomically(t *testing.T) {
	first := source("binding-a", "tenant-a", "billing:tenant-a")
	first.Revision = 2
	registry, err := quotabinding.NewRegistry([]quotabinding.Source{first})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	stale := first
	stale.Revision = 1
	added := source("binding-b", "tenant-b", "billing:tenant-b")
	if applied, err := registry.ApplyDesired([]quotabinding.Source{added, stale}); !errors.Is(err, quotabinding.ErrStale) || applied {
		t.Fatalf("ApplyDesired() = %v, %v", applied, err)
	}
	if _, ok := registry.Resolve(added.ClientID, added.SourceSystem); ok {
		t.Fatal("new source from rejected batch became live")
	}
	if tenantID, ok := registry.Resolve(first.ClientID, first.SourceSystem); !ok || tenantID != first.TenantID {
		t.Fatalf("existing source changed = %q, %v", tenantID, ok)
	}
}

func source(id, tenantID, sourceSystem string) quotabinding.Source {
	return quotabinding.Source{
		ID: id, ClientID: "billing-relay", TenantID: tenantID,
		SourceSystem: sourceSystem, Enabled: true, Revision: 1,
	}
}
