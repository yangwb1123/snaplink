package sso

import (
	"net/http"

	"golang.org/x/time/rate"

	"github.com/snaplink/sso/shared/core"
)

// checkQuotaBeforeCreate checks if the tenant has capacity to create a
// resource. Returns handled=true when the response is already written
// (quota exceeded or store error).
func (s *Server) checkQuotaBeforeCreate(ctx HandlerContext, tenantID string, resource core.ResourceType) bool {
	if s.tenantQuotaStore == nil || tenantID == "" {
		return false
	}
	if err := s.tenantQuotaStore.IncrementUsage(ctx.Request().Context(), tenantID, resource, 1); err != nil {
		if err == core.ErrQuotaExceeded {
			s.logger.Error("tenant quota exceeded", "tenant_id", tenantID, "resource", resource)
			ctx.JSON(http.StatusForbidden, errorBody(core.ErrQuotaExceededCode))
			return true
		}
		s.logger.Error("quota check failed", "tenant_id", tenantID, "resource", resource, "error", err)
		// Fail-open on store errors — don't block resource creation.
		return false
	}
	return false
}

// CheckClientCreateQuota is the oauth.RegisterDeps seam that makes the tenant
// client-create quota LIVE on the DCR /register path. It charges one unit of
// core.ResourceClients against the tenant; returns true when a 403
// quota_exceeded was already written (the caller must stop). Skips (false) when
// no quota store is wired or the client is tenant-less, and fails OPEN on a
// non-quota store error — matching the createSession session-quota precedent.
func (s *Server) CheckClientCreateQuota(ctx HandlerContext, tenantID string) bool {
	return s.checkQuotaBeforeCreate(ctx, tenantID, core.ResourceClients)
}

// rateLimiterEntry pairs a token bucket limiter with the grant type it
// gates. Stored in grantRateLimiters by grant type URN.
type rateLimiterEntry struct {
	limiter *rate.Limiter
}
