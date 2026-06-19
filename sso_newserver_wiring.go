package sso

import (
	"github.com/snaplink/sso/federation"
)

// applyFederationAutoRegistration decorates the wired ClientStore so an
// authorization-endpoint Get MISS for a valid HTTPS federation entity ID
// resolves the RP's trust chain on-the-fly and derives a policy-constrained
// client. Called post-options (order between WithClientStore /
// WithFederationEntity / WithFederationAutoRegistration is irrelevant) and ONLY
// when all three preconditions hold: the opt-in flag, a wired ClientStore, and a
// federation resolver with configured trust anchors (Resolver().Enabled()).
// Absent any one, no decoration occurs and every s.clientStore.Get is
// byte-identical to a non-federation build (the decorator is never even
// constructed). The decorator forwards every other method to the wrapped store;
// only Get adds the on-miss federation fallback, and a pre-registered client
// always wins.
func (s *Server) applyFederationAutoRegistration() {
	if !(s.federationAutoRegister && s.clientStore != nil &&
		s.federationEntity != nil && s.federationEntity.Resolver().Enabled()) {
		return
	}
	// Source the abuse-resistance knobs (negative-cache TTL + size, the
	// resolution concurrency cap) from the SAME federation Config the
	// resolver was built from. Zero/unset values pass through as the SDK
	// defaults (the With* options no-op on a non-positive arg). These bound
	// the UNAUTHENTICATED resolution-on-authz surface (a fake-but-HTTPS
	// client_id flood); see federation/doc.go for the operator rate-limit +
	// egress-policy that complete the defense.
	fedCfg := s.federationEntity.Config()
	s.clientStore = federation.NewRegistrationClientStore(
		s.clientStore,
		s.federationEntity.Resolver(),
		federation.WithRegistrationLogger(func(msg string, args ...any) {
			// A federation resolution/mapping miss is an EXPECTED,
			// oracle-safe outcome (an unknown client_id that resembles an
			// entity ID but doesn't validate), not a server error — log at
			// Info for operator visibility without alerting noise.
			s.logger.Info(msg, args...)
		}),
		federation.WithRegistrationNegativeCacheTTL(fedCfg.ResolutionNegativeCacheTTL),
		federation.WithRegistrationNegativeCacheMaxSize(fedCfg.ResolutionNegativeCacheMaxSize),
		federation.WithRegistrationMaxConcurrency(fedCfg.MaxConcurrentResolutions),
		// §7 trust-mark requirement (slice 4b): an EXTRA admission gate
		// sourced from the SAME federation Config. Empty
		// RequiredTrustMarkTypes ⇒ inert (byte-identical to the slice-3
		// path); when set, an auto-registering RP must carry a valid
		// configured-issuer-signed mark of each required type.
		federation.WithRegistrationTrustMarks(fedCfg),
	)
}

// applyClientStoreCache decorates the wired ClientStore with the opt-in
// per-login metadata cache (WithClientStoreCache). Called LAST (after the
// federation registration decorator) so the cache is the OUTERMOST layer: a Get
// hit short-circuits before the inner federation/operator store, and the cache
// transparently caches the federation decorator's on-miss derived clients too.
// Called post-options so order between WithClientStore / WithClientStoreCache /
// WithFederationAutoRegistration is irrelevant. Only when a positive TTL was
// requested AND a ClientStore is wired; otherwise no wrapper is constructed and
// every s.clientStore.Get is byte-identical to a non-caching build.
// ValidateSecret bypasses the cache (§2).
func (s *Server) applyClientStoreCache() {
	if !(s.clientStoreCacheTTL > 0 && s.clientStore != nil) {
		return
	}
	var onOutcome func(string)
	if s.metrics != nil {
		onOutcome = s.metrics.ObserveClientStoreCache
	}
	s.clientStoreCacheRef = newClientStoreCache(s.clientStore, s.clientStoreCacheTTL, onOutcome)
	s.clientStore = s.clientStoreCacheRef
}
