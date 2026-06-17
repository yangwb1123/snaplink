package sso

import (
	"github.com/snaplink/sso/metrics"
)

// tenantMetricsEnabled reports whether the opt-in per-tenant metrics are
// armed: an operator-supplied allowlist AND a metrics registry with the
// vectors registered. When false every tenant-metric call below is a no-op
// (byte-identical off, §5).
func (s *Server) tenantMetricsEnabled() bool {
	return len(s.tenantMetricsAllowlist) > 0 &&
		s.metrics != nil && s.metrics.LoginAttemptsByTenantTotal != nil
}

// tenantLabel resolves clientID to a BOUNDED tenant label value. It looks up
// the client's TenantID and returns it ONLY when it is on the operator
// allowlist; every other tenant — and every untenanted / unknown client —
// folds into the single metrics.TenantLabelOther bucket. This caps the
// tenant label cardinality at len(allowlist)+1, the same discipline the MFA
// metric uses by restricting its label to SupportedMethods() (§5).
//
// Called ONLY when tenantMetricsEnabled() (the opt-in path), so the
// ClientStore.Get it issues never runs on a default build.
func (s *Server) tenantLabel(ctx HandlerContext, clientID string) string {
	if clientID == "" {
		return metrics.TenantLabelOther
	}
	c, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || c == nil || c.TenantID == "" {
		return metrics.TenantLabelOther
	}
	if _, ok := s.tenantMetricsAllowlist[c.TenantID]; ok {
		return c.TenantID
	}
	return metrics.TenantLabelOther
}

// recordTenantLoginAttempt bumps the per-tenant login counter (outcome ∈
// {success, failure}) when the opt-in metrics are armed; otherwise no-op.
func (s *Server) recordTenantLoginAttempt(ctx HandlerContext, clientID, outcome string) {
	if !s.tenantMetricsEnabled() {
		return
	}
	s.metrics.LoginAttemptsByTenantTotal.WithLabelValues(s.tenantLabel(ctx, clientID), outcome).Inc()
}

// recordTenantTokenIssued bumps the per-tenant token-issue counter
// (by strategy) when the opt-in metrics are armed; otherwise no-op.
func (s *Server) recordTenantTokenIssued(ctx HandlerContext, clientID, strategy string) {
	if !s.tenantMetricsEnabled() {
		return
	}
	s.metrics.TokensIssuedByTenantTotal.WithLabelValues(s.tenantLabel(ctx, clientID), strategy).Inc()
}
