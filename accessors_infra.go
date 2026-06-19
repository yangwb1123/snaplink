// Code generated. Server field accessors for infrastructure components.
package sso

import (
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/spi"
)

func (s *Server) Auditor() *audit.Recorder                     { return s.auditor }
func (s *Server) Permissions() permissions.Provider            { return s.permissions }
func (s *Server) EmbedPermissions() bool                       { return s.embedPermissions }
func (s *Server) NetStore() netpolicy.Store                    { return s.netStore }
func (s *Server) NetClassifier() *netpolicy.Classifier         { return s.netClassifier }
func (s *Server) Metrics() *metrics.Metrics                    { return s.metrics }
func (s *Server) SrvLogger() spi.Logger                        { return s.logger }
func (s *Server) Issuer() string                               { return s.issuer }
func (s *Server) SessionMgr() core.SessionManager              { return s.sessionMgr }
func (s *Server) ClientStoreAccessor() core.ClientStore        { return s.clientStore }
func (s *Server) TokenIssuers() map[string]core.TokenIssuer    { return s.tokenIssuers }
func (s *Server) LogoutTokenIssuer() LogoutTokenIssuer         { return s.logoutTokenIssuer }
func (s *Server) LogoutNotifier() LogoutNotifier               { return s.logoutNotifier }
