// Code generated. Server field accessors for tenant, compliance, and data stores.
package sso

import (
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/compliance"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/core"
)

func (s *Server) ConnectionStore() connections.Store           { return s.connectionStore }
func (s *Server) ConsentStore() core.ConsentStore              { return s.consentStore }
func (s *Server) TenantUserStore() core.TenantUserStore        { return s.tenantUserStore }
func (s *Server) UserProviderAccessor() core.UserProvider      { return s.userProvider }
func (s *Server) DeviceSecretStore() core.DeviceSecretStore    { return s.deviceSecretStore }
func (s *Server) CrossReplicaRevocationEnabled() bool          { return s.crossReplicaRevocation }
func (s *Server) InvalidationBus() cluster.Bus                 { return s.invalidationBus }
func (s *Server) DataExporter() *compliance.Exporter           { return s.dataExporter }
func (s *Server) AccountEraser() *compliance.Eraser            { return s.accountEraser }

// Tenant metrics accessors.
func (s *Server) RecordTenantLoginAttempt(ctx HandlerContext, clientID, outcome string) {
	s.recordTenantLoginAttempt(ctx, clientID, outcome)
}
func (s *Server) RecordTenantTokenIssued(ctx HandlerContext, clientID, strategy string) {
	s.recordTenantTokenIssued(ctx, clientID, strategy)
}
func (s *Server) TenantMetricsEnabled() bool                   { return s.tenantMetricsEnabled() }
func (s *Server) TenantLabel(ctx HandlerContext, clientID string) string {
	return s.tenantLabel(ctx, clientID)
}
func (s *Server) TenantMetricsAllowlist() map[string]struct{}  { return s.tenantMetricsAllowlist }
