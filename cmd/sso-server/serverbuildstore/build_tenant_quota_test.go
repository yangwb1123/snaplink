package serverbuildstore

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestBuildTenantQuotaRuntimeDisabledAndUnknown(t *testing.T) {
	if rt, err := BuildTenantQuotaRuntime(t.Context(), config.TenantResourceQuotaConfig{}, nil, "", nil); err != nil || rt != nil {
		t.Fatalf("disabled: runtime=%v err=%v, want nil nil", rt, err)
	}
	if _, err := BuildTenantQuotaRuntime(t.Context(), config.TenantResourceQuotaConfig{Backend: "carrier-pigeon"}, nil, "", nil); err == nil {
		t.Fatal("unknown backend should fail")
	}
	if _, err := BuildTenantQuotaRuntime(t.Context(), config.TenantResourceQuotaConfig{Backend: "postgres"}, nil, "", nil); err == nil {
		t.Fatal("postgres without shared pool should fail")
	}
}

func TestReconcileTenantClientUsageSeedsAbsoluteCount(t *testing.T) {
	rt, err := BuildTenantQuotaRuntime(t.Context(), config.TenantResourceQuotaConfig{
		Backend: "memory", Limits: []config.TenantQuotaSeedConfig{{TenantID: "acme", MaxClients: 1}},
	}, nil, "", memorystoreidentity.NewMemoryClientStore())
	if err != nil {
		t.Fatal(err)
	}
	clients := memorystoreidentity.NewMemoryClientStore()
	for _, client := range []*core.Client{
		{ID: "acme-1", TenantID: "acme"}, {ID: "acme-2", TenantID: "acme"},
		{ID: "other-1", TenantID: "other"},
	} {
		if err := clients.Add(t.Context(), client); err != nil {
			t.Fatal(err)
		}
	}
	seeds := []config.TenantQuotaSeedConfig{{TenantID: "acme"}}
	if err := ReconcileTenantClientUsage(t.Context(), rt.Store, clients, seeds); err != nil {
		t.Fatal(err)
	}
	usage, err := rt.Store.GetUsage(t.Context(), "acme")
	if err != nil || usage.Clients != 2 {
		t.Fatalf("reconciled usage = %+v, %v", usage, err)
	}
	resources := rt.Store.(core.TenantQuotaResourceStore)
	if _, err := resources.ReleaseResource(t.Context(), "acme", core.ResourceClients, "acme-1"); err != nil {
		t.Fatal(err)
	}
	usage, _ = rt.Store.GetUsage(t.Context(), "acme")
	if usage.Clients != 1 {
		t.Fatalf("usage after legacy resource release = %+v", usage)
	}
}

func TestBuildTenantQuotaRuntimeMemorySeedsAndStops(t *testing.T) {
	cfg := config.TenantResourceQuotaConfig{
		Backend:         "memory",
		CleanupInterval: time.Millisecond,
		Limits: []config.TenantQuotaSeedConfig{{
			TenantID: "acme", MaxClients: 3, MaxUsers: 20, MaxSessions: 30, MaxTokenRate: 4,
		}},
	}
	rt, err := BuildTenantQuotaRuntime(t.Context(), cfg, nil, "", memorystoreidentity.NewMemoryClientStore())
	if err != nil {
		t.Fatalf("BuildTenantQuotaRuntime: %v", err)
	}
	quota, err := rt.Store.GetQuota(t.Context(), "acme")
	if err != nil {
		t.Fatalf("GetQuota: %v", err)
	}
	want := core.TenantQuota{MaxClients: 3, MaxUsers: 20, MaxSessions: 30, MaxTokenRate: 4}
	if *quota != want {
		t.Fatalf("quota = %+v, want %+v", *quota, want)
	}
	rt.Start(testLogger())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if !rt.Stop(ctx) {
		t.Fatal("cleanup loop did not stop")
	}
}
