package sso

import (
	"github.com/snaplink/sso/protocols/oauth/oauthspi"
	"github.com/snaplink/sso/shared/core"
)

// CIBAPushNotifier exposes the optional CIBA push delivery notifier. Folded
// into this file (rather than its own accessors_push.go) to keep
// interfaces/sso at its frozen directory_fanout_test.go file-count ceiling.
func (s *Server) CIBAPushNotifier() oauthspi.CIBAPushNotifier { return s.cibaPushNotifier }

// PathAdminSessionsLinked re-exports core.PathAdminSessionsLinked (cross-
// protocol session-hub admin query), folded in here for the same file-
// budget reason as CIBAPushNotifier above.
const PathAdminSessionsLinked = core.PathAdminSessionsLinked

// seedFeatureGateLiveFlags seeds every *Live atomic.Bool (sso_wiring.go) from
// the resolved s.featureGates BEFORE Mount() reads them via the matching
// *GateOn method — split out of NewServer (sso.go) to keep that function
// under the maintainability line budget.
func (s *Server) seedFeatureGateLiveFlags() {
	s.adminAPILive.Store(gateOn(s.featureGates.AdminAPI))
	s.webSPALive.Store(gateOn(s.featureGates.WebSPA))
	s.oidcLive.Store(gateOn(s.featureGates.OIDC))
	s.cibaLive.Store(gateOn(s.featureGates.CIBA))
	s.caepLive.Store(gateOn(s.featureGates.CAEP))
	s.federationLive.Store(gateOn(s.featureGates.Federation))
	s.selfServiceLive.Store(gateOn(s.featureGates.SelfService))
}

// SetOIDCGateEnabled flips the LIVE feature_gates.oidc value read by
// oidcGateOn (server_routes.go) — the config/reload SIGHUP hook
// (SetOIDCGateHook) calls this. Always returns true: mountOIDCUserEndpoints
// always registers /userinfo and /end_session behind a core.GatedRouter now
// (server_userinfo.go), unconditionally of any store, so there is always an
// already-mounted route for this flag to affect.
func (s *Server) SetOIDCGateEnabled(enabled bool) bool {
	s.oidcLive.Store(enabled)
	return true
}

// SetCIBAGateEnabled flips the LIVE feature_gates.ciba value read by
// cibaGateOn. Always returns true: mountCIBAEndpoint always registers
// POST /backchannel-authentication behind a core.GatedRouter now
// (server_routes.go), regardless of whether a CIBA store is wired (the
// handler itself 501s without one — see mountCIBAEndpoint's doc).
func (s *Server) SetCIBAGateEnabled(enabled bool) bool {
	s.cibaLive.Store(enabled)
	return true
}

// SetCAEPGateEnabled flips the LIVE feature_gates.caep value read by
// caepGateOn. Returns false when no CAEP receiver was ever wired
// (WithCAEPReceiver): with no mounted route for this flag to affect,
// flipping it has no observable effect, so the caller (config/reload)
// should report the change as Ignored rather than Applied — mirroring
// SetWebSPAGateEnabled's "nothing to flip" contract.
func (s *Server) SetCAEPGateEnabled(enabled bool) bool {
	s.caepLive.Store(enabled)
	return s.caepReceiver != nil
}

// SetFederationGateEnabled flips the LIVE feature_gates.federation value
// read by federationGateOn. Returns false when NONE of the federation
// sub-features (RFC 9728 protected-resource metadata, OpenID Federation
// entity configuration, B2B home-realm discovery) were ever wired: with no
// mounted route in the group for this flag to affect, flipping it has no
// observable effect, so the caller should report the change as Ignored
// rather than Applied.
func (s *Server) SetFederationGateEnabled(enabled bool) bool {
	s.federationLive.Store(enabled)
	return s.protectedResourceMetadata != nil || s.federationEntity != nil || s.connectionStore != nil
}

// SetSelfServiceGateEnabled flips the LIVE feature_gates.self_service value
// read by selfServiceGateOn. Always returns true: mountSelfServiceProfile
// always registers GET /me/permissions, /me/menus, and /me/roles behind a
// core.GatedRouter now (server_me.go), unconditionally of any backing
// store, so there is always an already-mounted route for this flag to
// affect.
func (s *Server) SetSelfServiceGateEnabled(enabled bool) bool {
	s.selfServiceLive.Store(enabled)
	return true
}
