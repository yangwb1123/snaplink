package sso

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/domains/tokenusage"
	"github.com/snaplink/sso/interfaces/sso/servercache"
	"github.com/snaplink/sso/internal/auth/consent"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/sse"
	"github.com/snaplink/sso/shared/spi"
)

// Server is the core SSO orchestrator. Its ~60 fields are grouped into
// anonymously-embedded sub-structs (sso_wiring.go, server_federation.go,
// sso_protocol.go, sso_selfservice.go) by concern, so no single file holds
// the whole god-struct. Embedding is anonymous, so every s.<field> access and
// every With* option keeps working unchanged via Go field promotion — the
// struct's public shape and behavior are identical.
type Server struct {
	wiringState
	federationMeshState
	clusterState
	protocolState
	cacheState
	selfServiceState
}

// Option configures the Server.
type Option func(*Server)

// ReadyCheck is a named health-check function for /readyz.
type ReadyCheck func(ctx context.Context) error

type namedReadyCheck struct {
	Name    string
	Check   ReadyCheck
	Timeout time.Duration // 0 -> use the aggregate deadline
}

func NewServer(opts ...Option) *Server {
	// Fields are assigned (not set via a composite literal) because the Server
	// struct's fields live in anonymously-embedded sub-structs (sso_*.go); a
	// keyed literal can't name promoted fields, but assignment through the outer
	// selector can. End state is identical to the previous literal.
	s := &Server{}
	s.authenticators = make(map[string]Authenticator)
	s.tokenIssuers = make(map[string]TokenIssuer)
	s.tenantTokenStrategies = make(map[string]string)
	s.issuer = DefaultIssuer
	s.logger = spi.NopLogger{}
	s.discoveryCacheTTL = defaultDiscoveryCacheTTL
	s.discoveryDocCacheTTL = DefaultDiscoveryDocCacheTTL
	s.authzPolicyBundleCacheTTL = DefaultAuthzPolicyBundleCacheTTL
	s.jwksCacheTTL = defaultJWKSCacheTTL
	s.consentChallenges = consent.NewChallengeStore()
	s.panicRecovery = true
	for _, opt := range opts {
		opt(s)
	}
	s.startedAt = time.Now()
	s.applyAuditSinkTaps()
	s.applyConfigAuditWiring()
	s.applyMetricsWiring()
	// OpenID Federation 1.0 automatic client registration (slice 3) then the
	// opt-in per-login ClientStore metadata cache. Order between these two
	// ClientStore decorators is load-bearing: the cache MUST wrap the
	// federation decorator (OUTERMOST) so a Get hit short-circuits before the
	// inner federation/operator store. See each helper's doc for the
	// byte-identical preconditions when a precondition does not hold.
	s.applyFederationAutoRegistration()
	s.applyClientStoreCache()
	// Attack-surface visibility: emit the metric snapshot + (if any gate is
	// off) the audit event + log line for FeatureGates. Last, so it reflects
	// the fully-resolved config regardless of option order.
	s.recordFeatureGateStartup()
	return s
}

// applyAuditSinkTaps fans the audit recorder's sink out to every opt-in
// consumer of the audit pipeline (CAEP/SSF transmitter, realtime admin event
// stream). Called post-options (order between WithAuditRecorder and
// WithCAEPTransmitter / WithSSEBroker doesn't matter) so both taps see every
// event uniformly. Each tap is independently opt-in: when its half is
// unwired, or no recorder is wired at all, that branch is skipped entirely —
// a build using neither feature is byte-identical.
func (s *Server) applyAuditSinkTaps() {
	if s.auditor == nil {
		return
	}
	if s.caepTransmitter != nil {
		s.auditor.AddSink(s.caepTransmitter)
	}
	if s.sseBroker != nil {
		s.auditor.AddSink(sse.NewSink(s.sseBroker))
	}
}

// applyMetricsWiring registers the opt-in per-tenant metric vectors and arms
// the token-usage recorder's Prometheus hooks, both post-options so wiring
// order between the relevant With* calls is irrelevant. Each block's own
// byte-identical-when-unwired precondition keeps a build that uses neither
// feature identical to a pre-feature build.
func (s *Server) applyMetricsWiring() {
	// Per-tenant metrics (§5): register the opt-in vectors when BOTH a
	// tenant allowlist AND a metrics registry are wired. EnableTenantMetrics
	// is idempotent. Without both, the vectors stay nil and nothing is
	// registered or emitted (byte-identical).
	if len(s.tenantMetricsAllowlist) > 0 && s.metrics != nil {
		s.metrics.EnableTenantMetrics()
	}
	// Token-usage hooks: armed only when BOTH a Recorder
	// (WithTokenUsageRecorder) AND a metrics registry (WithMetrics) are
	// wired. Without a recorder there is nothing to hook; without metrics the
	// recorder still records to its store, just with no hooks fired.
	if s.tokenUsageRecorder == nil || s.metrics == nil {
		return
	}
	s.metrics.EnableTokenUsageMetrics()
	s.tokenUsageRecorder.SetHooks(tokenusage.Hooks{
		Recorded: s.metrics.ObserveTokenUsageEvent,
		Dropped:  s.metrics.ObserveTokenUsageDropped,
		Tracked:  s.metrics.SetTokenUsageTrackedBuckets,
	})
}

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
	if !s.federationAutoRegister || s.clientStore == nil ||
		s.federationEntity == nil || !s.federationEntity.Resolver().Enabled() {
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
	if s.clientStoreCacheTTL <= 0 || s.clientStore == nil {
		return
	}
	var onOutcome func(string)
	if s.metrics != nil {
		onOutcome = s.metrics.ObserveClientStoreCache
	}
	s.clientStoreCacheRef = servercache.NewClientStoreCache(s.clientStore, s.clientStoreCacheTTL, onOutcome)
	s.clientStore = s.clientStoreCacheRef
}

// gateState pairs a gate's wire name with its resolved on/off value, for
// recordFeatureGateStartup — the single place that fans a gate's boolean out
// to the metric + audit + log surfaces.
type gateState struct {
	name string
	on   bool
}

func (s *Server) allGateStates() []gateState {
	return []gateState{
		{"oidc", s.oidcGateOn()},
		{"ciba", s.cibaGateOn()},
		{"caep", s.caepGateOn()},
		{"federation", s.federationGateOn()},
		{"self_service", s.selfServiceGateOn()},
		{"admin_api", s.adminAPIGateOn()},
		{"web_spa", s.webSPAGateOn()},
	}
}

// recordFeatureGateStartup logs, audits, and records a metric for every gate
// an operator explicitly disabled. Called once from NewServer, after every
// option (including WithFeatureGates) has run. Disabling a protocol surface
// is a deliberate attack-surface change, so it gets the same visibility as
// any other security-relevant configuration — but a build that never
// touches FeatureGates (every gate on) emits nothing new here beyond the
// (all-1) metric snapshot, keeping the common case's audit trail
// byte-identical to a pre-gate server.
func (s *Server) recordFeatureGateStartup() {
	states := s.allGateStates()
	var disabled []string
	for _, g := range states {
		s.metrics.SetFeatureGateEnabled(g.name, g.on)
		if !g.on {
			disabled = append(disabled, g.name)
		}
	}
	if len(disabled) == 0 {
		return
	}
	sort.Strings(disabled)
	joined := strings.Join(disabled, ",")
	s.logger.Info("sso: protocol surfaces disabled via feature_gates", "disabled", joined)
	e := &audit.Event{
		Type:      audit.EventFeatureGatesDisabled,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now(),
		Reason:    joined,
	}
	audit.SetMeta(e, "disabled_gates", joined)
	s.auditor.Record(context.Background(), e)
}
