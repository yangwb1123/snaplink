package reload

import (
	"fmt"

	"github.com/yangwb1123/snaplink/config"
)

// SetTenantQuotaProjectionSourcesHook wires the bounded SIGHUP control plane
// for source desired state. Route enablement, audience, and backend remain
// cold-start boundaries; only versioned source records are live-reloadable.
func (r *Reloader) SetTenantQuotaProjectionSourcesHook(
	fn func([]config.TenantQuotaProjectionSourceConfig) error,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setTenantQuotaProjectionSources = fn
}

func (r *Reloader) applyTenantQuotaProjectionSources(
	newCfg *config.Config, changed bool,
) (string, error) {
	if r.setTenantQuotaProjectionSources == nil {
		return "", nil
	}
	sources := newCfg.Tenant.ResourceQuota.ProjectionIngress.Sources
	if err := r.setTenantQuotaProjectionSources(sources); err != nil {
		return "", err
	}
	r.current.Tenant.ResourceQuota.ProjectionIngress.Sources = append(
		[]config.TenantQuotaProjectionSourceConfig(nil), sources...,
	)
	if !changed {
		return "", nil
	}
	return "tenant.resource_quota.projection_ingress.sources: desired state applied", nil
}

func (r *Reloader) reconcileTenantQuotaProjectionSources(
	result Result, newCfg *config.Config, changed bool,
) (Result, error) {
	if !changed && r.setTenantQuotaProjectionSources == nil {
		return result, nil
	}
	applied, err := r.applyTenantQuotaProjectionSources(newCfg, changed)
	if err != nil {
		if changed {
			result.Ignored = append(result.Ignored, tenantQuotaProjectionSourcesPrefix)
		}
		return result, fmt.Errorf("config reload: quota projection sources: %w", err)
	}
	if applied != "" {
		result.Applied = append(result.Applied, applied)
	} else if changed && r.setTenantQuotaProjectionSources == nil {
		result.Ignored = append(result.Ignored, tenantQuotaProjectionSourcesPrefix)
	}
	return result, nil
}
