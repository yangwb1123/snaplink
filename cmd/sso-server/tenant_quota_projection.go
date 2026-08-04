package main

import (
	"fmt"
	"net/http"

	"github.com/yangwb1123/snaplink/config"
	configreload "github.com/yangwb1123/snaplink/config/reload"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// mountTenantQuotaProjectionHandler mounts the route only when explicitly
// enabled at boot. Its registry remains live for safe source-only SIGHUP
// desired-state updates; backend, audience, and route enablement stay cold.
func mountTenantQuotaProjectionHandler(
	cfg *config.Config, a *app, logger spi.Logger,
) error {
	ingress := cfg.Tenant.ResourceQuota.ProjectionIngress
	if !ingress.Enabled {
		return nil
	}
	registry, err := sso.NewTenantQuotaProjectionSourceRegistry(ingress.Sources)
	if err != nil {
		return fmt.Errorf("tenant quota projection bindings: %w", err)
	}
	handler, err := sso.NewTenantQuotaProjectionHandlerWithRegistry(
		a.server, ingress.Audience, registry,
	)
	if err != nil {
		return fmt.Errorf("tenant quota projection handler: %w", err)
	}
	if err := a.server.Handle(http.MethodPut, core.PathTenantQuotaProjection, handler); err != nil {
		return fmt.Errorf("mount tenant quota projection: %w", err)
	}
	a.server.AddReadyCheck("tenant-quota-projection-bindings", registry.Ready)
	a.tenantQuotaProjectionSources = registry
	logger.Info("tenant quota projection ingress mounted", "path", core.PathTenantQuotaProjection)
	return nil
}

func wireTenantQuotaProjectionReload(
	reloader *configreload.Reloader, registry *sso.TenantQuotaProjectionSourceRegistry,
) {
	if reloader == nil || registry == nil {
		return
	}
	reloader.SetTenantQuotaProjectionSourcesHook(func(
		sources []config.TenantQuotaProjectionSourceConfig,
	) error {
		_, err := registry.ApplyDesired(sources)
		return err
	})
}
