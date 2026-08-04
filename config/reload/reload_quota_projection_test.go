package reload

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/tenant/quotabinding"
)

func TestReloadAppliesQuotaProjectionSourcesAsOneDesiredState(t *testing.T) {
	initial := quotaProjectionReloadConfig(quotaReloadSource("binding-a", "tenant-a", 1, true))
	next := quotaProjectionReloadConfig(
		quotaReloadSource("binding-a", "tenant-a", 1, true),
		quotaReloadSource("binding-b", "tenant-b", 1, true),
	)
	registry, err := quotabinding.NewRegistry(initial.Tenant.ResourceQuota.ProjectionIngress.Sources)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	reloader := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	reloader.SetTenantQuotaProjectionSourcesHook(func(sources []config.TenantQuotaProjectionSourceConfig) error {
		_, applyErr := registry.ApplyDesired(sources)
		return applyErr
	})
	result, err := reloader.Reload(t.Context())
	if err != nil || len(result.Applied) != 1 || len(result.Ignored) != 0 {
		t.Fatalf("Reload() = %+v, %v", result, err)
	}
	if tenantID, ok := registry.Resolve("billing-relay", "billing:tenant-b"); !ok || tenantID != "tenant-b" {
		t.Fatalf("new binding = %q, %v", tenantID, ok)
	}
}

func TestReloadRejectsQuotaProjectionSameRevisionEquivocation(t *testing.T) {
	first := quotaReloadSource("binding-a", "tenant-a", 1, true)
	initial := quotaProjectionReloadConfig(first)
	equivocation := first
	equivocation.Enabled = false
	next := quotaProjectionReloadConfig(equivocation)
	desired := next
	registry, _ := quotabinding.NewRegistry([]quotabinding.Source{first})
	reloader := New(initial, func(context.Context) (*config.Config, error) { return desired, nil }, nil)
	reloader.SetTenantQuotaProjectionSourcesHook(func(sources []config.TenantQuotaProjectionSourceConfig) error {
		_, applyErr := registry.ApplyDesired(sources)
		return applyErr
	})
	result, err := reloader.Reload(t.Context())
	if !errors.Is(err, quotabinding.ErrConflict) || len(result.Applied) != 0 ||
		!containsPath(result.Ignored, tenantQuotaProjectionSourcesPrefix) {
		t.Fatalf("Reload() = %+v, %v", result, err)
	}
	if err := registry.Ready(t.Context()); !errors.Is(err, quotabinding.ErrConflict) {
		t.Fatalf("Ready() after rejection = %v", err)
	}
	if _, ok := registry.Resolve(first.ClientID, first.SourceSystem); !ok {
		t.Fatal("equivocating reload changed live registry")
	}
	current := reloader.Current().Tenant.ResourceQuota.ProjectionIngress.Sources
	if len(current) != 1 || !current[0].Enabled {
		t.Fatalf("tracked config changed after rejection: %+v", current)
	}
	desired = initial
	result, err = reloader.Reload(t.Context())
	if err != nil || result.Changed() {
		t.Fatalf("exact recovery Reload() = %+v, %v", result, err)
	}
	if err := registry.Ready(t.Context()); err != nil {
		t.Fatalf("Ready() after exact recovery = %v", err)
	}
}

func TestReloadQuotaProjectionHookCanRejectOperationally(t *testing.T) {
	initial := quotaProjectionReloadConfig(quotaReloadSource("binding-a", "tenant-a", 1, true))
	next := quotaProjectionReloadConfig(quotaReloadSource("binding-a", "tenant-a", 2, false))
	reloader := New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	reloader.SetTenantQuotaProjectionSourcesHook(func([]config.TenantQuotaProjectionSourceConfig) error {
		return errors.New("control plane rejected")
	})
	result, err := reloader.Reload(t.Context())
	if err == nil || !containsPath(result.Ignored, tenantQuotaProjectionSourcesPrefix) {
		t.Fatalf("Reload() = %+v, %v", result, err)
	}
}

func TestReloadRejectsStaleQuotaProjectionWithoutAdvancingCurrent(t *testing.T) {
	current := quotaReloadSource("binding-a", "tenant-a", 2, true)
	stale := current
	stale.Revision = 1
	initial := quotaProjectionReloadConfig(current)
	desired := quotaProjectionReloadConfig(stale)
	registry, _ := quotabinding.NewRegistry([]quotabinding.Source{current})
	reloader := New(initial, func(context.Context) (*config.Config, error) { return desired, nil }, nil)
	reloader.SetTenantQuotaProjectionSourcesHook(func(sources []config.TenantQuotaProjectionSourceConfig) error {
		_, applyErr := registry.ApplyDesired(sources)
		return applyErr
	})
	result, err := reloader.Reload(t.Context())
	if !errors.Is(err, quotabinding.ErrStale) ||
		!containsPath(result.Ignored, tenantQuotaProjectionSourcesPrefix) {
		t.Fatalf("Reload() = %+v, %v", result, err)
	}
	tracked := reloader.Current().Tenant.ResourceQuota.ProjectionIngress.Sources
	if len(tracked) != 1 || tracked[0].Revision != 2 {
		t.Fatalf("tracked sources = %+v", tracked)
	}
	if err := registry.Ready(t.Context()); !errors.Is(err, quotabinding.ErrStale) {
		t.Fatalf("Ready() = %v", err)
	}
}

func TestReloadQuotaProjectionFailurePreventsOtherLiveChanges(t *testing.T) {
	current := quotaReloadSource("binding-a", "tenant-a", 2, true)
	stale := current
	stale.Revision = 1
	initial := quotaProjectionReloadConfig(current)
	initial.Logging.Level = "info"
	desired := quotaProjectionReloadConfig(stale)
	desired.Logging.Level = "debug"
	registry, _ := quotabinding.NewRegistry([]quotabinding.Source{current})
	logChanges := 0
	reloader := New(initial, func(context.Context) (*config.Config, error) { return desired, nil }, func(string) {
		logChanges++
	})
	reloader.SetTenantQuotaProjectionSourcesHook(func(sources []config.TenantQuotaProjectionSourceConfig) error {
		_, applyErr := registry.ApplyDesired(sources)
		return applyErr
	})
	if _, err := reloader.Reload(t.Context()); !errors.Is(err, quotabinding.ErrStale) {
		t.Fatalf("Reload() error = %v", err)
	}
	if logChanges != 0 || reloader.Current().Logging.Level != "info" {
		t.Fatalf("partial live apply: calls=%d level=%q", logChanges, reloader.Current().Logging.Level)
	}
}

func quotaProjectionReloadConfig(sources ...quotabinding.Source) *config.Config {
	value := baseConfig()
	value.Tenant.ResourceQuota = config.TenantResourceQuotaConfig{
		Backend: "memory",
		ProjectionIngress: config.TenantQuotaProjectionIngressConfig{
			Enabled: true, Audience: "snaplink-sso", Sources: sources,
		},
	}
	return value
}

func quotaReloadSource(id, tenantID string, revision uint64, enabled bool) quotabinding.Source {
	return quotabinding.Source{
		ID: id, ClientID: "billing-relay", TenantID: tenantID,
		SourceSystem: "billing:" + tenantID, Enabled: enabled, Revision: revision,
	}
}
