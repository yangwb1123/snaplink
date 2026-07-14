package sso

import (
	"context"
	"errors"
	"time"

	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/protocols/oauth"
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

// cibaDeliveryModes builds the backchannel_token_delivery_modes_supported
// discovery advertisement for applyCIBABackchannel (server_discovery_config.go
// — extracted here to stay under that file's maintainability line budget).
// Poll is always available; ping/push are appended when their respective
// notifier is wired.
func (s *Server) cibaDeliveryModes() []string {
	modes := []string{"poll"}
	if s.cibaPingNotifier != nil {
		modes = append(modes, "ping")
	}
	if s.cibaPushNotifier != nil {
		modes = append(modes, "push")
	}
	return modes
}

// cibaPushDeliveryTimeout bounds the detached CIBA push-delivery goroutine
// (deliverCIBAPush). Generous relative to cibaPingDeliveryTimeout
// (server_invalidation.go): push does strictly more work under the same
// kind of bound — claiming the request AND minting a full token set BEFORE
// the HTTP POST, which itself retries internally (see
// oauth.NewCIBAPushNotifier's own backoff budget) — so issuance latency
// plus the notifier's retries both need to fit inside it.
const cibaPushDeliveryTimeout = 20 * time.Second

// dispatchCIBANotification is ResolveBackchannelAuthRequest's out-of-band
// delivery seam (server_invalidation.go), extracted here to stay under that
// file's maintainability line budget. Push takes precedence over ping when
// both are wired AND the resolution is an approval: push is a strict
// upgrade (it delivers the actual token, saving the client a round trip),
// and firing both risks a confusing ping-telling-the-client-to-poll once
// push has already claimed + consumed the request (deliverCIBAPush). A
// denied resolution has no token to push, so ping (if wired) still fires
// for it — the client's poll surfaces access_denied either way.
func (s *Server) dispatchCIBANotification(authReqID, clientID, notificationToken string, approved bool) {
	switch {
	case approved && s.cibaPushNotifier != nil:
		go s.deliverCIBAPush(authReqID)
	case s.cibaPingNotifier != nil:
		go s.deliverCIBAPing(clientID, authReqID, notificationToken)
	}
}

// deliverCIBAPush supervises a single detached CIBA push delivery (CIBA
// Core §10.3): the body of the goroutine dispatchCIBANotification spawns
// for an APPROVED request when a CIBAPushNotifier is wired. Unlike
// deliverCIBAPing (which only pokes the client to come poll), a
// push-registered client never polls /token at all, so this mints the
// token set itself — claiming the request via ConsumeIfApproved, the SAME
// single-use claim the /token poll path uses (protocols/oauth's
// oracle-safe pattern), so a concurrent client poll (a push-registered
// client MAY still poll as a fallback) races safely: whichever side wins
// the claim mints exactly once; the loser sees ErrCIBARequestNotFound,
// which for THIS goroutine is a silent no-op (not a delivery failure — the
// poll already served the client).
//
// Hardening mirrors deliverCIBAPing: a bounded context (a hanging notifier
// or slow issuer can't leak this goroutine forever) and recover() (a
// panicking custom notifier is contained, not fatal to the process).
// Best-effort by contract: a failed push is dead-lettered (when the wired
// notifier carries a CIBAPushDeadLetterStore) and logged, never surfaced —
// there is no caller left to return an error to.
func (s *Server) deliverCIBAPush(authReqID string) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("ciba push delivery panicked", "auth_req_id", authReqID, "panic", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), cibaPushDeliveryTimeout)
	defer cancel()

	r, err := s.cibaStore.ConsumeIfApproved(ctx, authReqID)
	if err != nil {
		if !errors.Is(err, oauth.ErrCIBARequestNotFound) {
			s.logger.Error("ciba push: claim failed", "auth_req_id", authReqID, "error", err)
		}
		return
	}
	client, err := s.clientStore.Get(ctx, r.ClientID)
	if err != nil || client == nil {
		s.logger.Error("ciba push: client lookup failed", "auth_req_id", authReqID, "client_id", r.ClientID, "error", err)
		return
	}

	payload, ok := tokengrant.MintCIBATokensForPush(s, newBackgroundHandlerContext(ctx), client, r, time.Now())
	if !ok {
		return // buildCIBATokenResponse already logged the specific issuance failure.
	}
	if err := s.cibaPushNotifier.NotifyPush(ctx, client.ID, authReqID, r.ClientNotificationToken, payload); err != nil {
		s.logger.Error("ciba push delivery failed", "auth_req_id", authReqID, "client_id", client.ID, "error", err)
	}
}
