package sso

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/federation"
	"github.com/yangwb1123/snaplink/domains/metering"
	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/domains/tokenanomaly"
	"github.com/yangwb1123/snaplink/domains/tokenpolicy"
	"github.com/yangwb1123/snaplink/interfaces/admin"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/interfaces/sso/servercache"
	"github.com/yangwb1123/snaplink/internal/auth/consent"
	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/sessionhub"
	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/spi"
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
	threatState
	tokenExchangeChainState
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
	s.loginTransactionStore = login.NewMemoryTransactionStore()
	s.panicRecovery = true
	// Conservative built-in default — see clientRegistrationRateLimiter's doc
	// (sso_protocol.go) for why this one is seeded here rather than left nil
	// like every other rate limiter, which options only ever tighten or
	// disable (WithClientRegistrationRateLimit(nil)), never turn on cold.
	s.clientRegistrationRateLimiter = ratelimit.NewMemoryLimiter(
		defaultClientRegistrationRatePerSec, defaultClientRegistrationRateBurst)
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
	// Cross-protocol session hub (platform/lifecycle/sessionhub): constructed post-options
	// so it captures whatever SessionManager WithSessionManager wired. Always
	// on (unlike the other apply* helpers here) — see applySessionHub.
	s.applySessionHub()
	s.seedFeatureGateLiveFlags()
	// Attack-surface visibility: emit the metric snapshot + (if any gate is
	// off) the audit event + log line for FeatureGates. Last, so it reflects
	// the fully-resolved config regardless of option order.
	s.recordFeatureGateStartup()
	return s
}

// applySessionHub constructs the Cross-protocol Session Hub coordinator
// (always — this is bookkeeping infrastructure, not an opt-in feature, so
// there is no "byte-identical when unwired" precondition to gate on). It
// wires:
//   - a fresh bounded in-memory LinkStore (no operator seam yet; add one
//     alongside a future WithSessionHubLinkStore if a shared backend is
//     needed for a multi-replica deployment);
//   - CoreSessionTerminator = s.sessionMgr, whatever WithSessionManager set
//     (nil is fine — Coordinator.Logout then just skips that leg, exactly
//     like every other nil-SPI fail-open in this server);
//   - OIDCLogoutTrigger = s itself, via TriggerBackchannelLogout (accessors.go).
//
// The SAML leg is deliberately NOT wired here: the concrete SAML IdP handlers
// (infrastructure/saml, a separate Go module) are built FROM this
// already-constructed Server (they need IssuerForClient/SessionMgr), so
// wiring them requires infrastructure/saml's Deps.SessionHub to call
// s.sessionHub.SetSAMLTrigger(...) AFTER both exist — see that package.
func (s *Server) applySessionHub() {
	s.sessionHub = sessionhub.NewCoordinator(
		sessionhub.NewMemoryLinkStore(0),
		s.sessionMgr,
		s,
		s.logger,
	)
}

// applyAuditSinkTaps fans the audit recorder's sink out to every opt-in
// consumer of the audit pipeline (CAEP/SSF transmitter, realtime admin event
// stream, the generic webhook egress engine, the outbound SCIM provisioning
// push). Called post-options (order between WithAuditRecorder and
// WithCAEPTransmitter / WithSSEBroker / WithWebhookEngine / WithSCIMProvisioner
// doesn't matter) so every tap sees every event uniformly. Each tap is
// independently opt-in: when its half is unwired, or no recorder is wired at
// all, that branch is skipped entirely — a build using none of these
// features is byte-identical.
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
	if s.webhookEngine != nil {
		s.auditor.AddSink(s.webhookEngine)
	}
	if s.scimProvisionSink != nil {
		s.auditor.AddSink(s.scimProvisionSink)
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
	// Token-policy counters (§5): registered when BOTH a policy store
	// (WithTokenPolicy) AND a metrics registry are wired. Placed before the
	// token-usage early-return below so a policy-only deployment (no usage
	// recorder) still gets its counters. Idempotent + byte-identical off.
	if s.tokenPolicyStore != nil && s.metrics != nil {
		s.metrics.EnableTokenPolicyMetrics()
	}
	// Token-anomaly findings counter (§5): armed when BOTH a detector
	// (WithTokenAnomalyDetector) AND a metrics registry are wired. Placed
	// before the token-usage early-return so a detector-only deployment still
	// gets its counter. Idempotent + byte-identical off. The hook fires only
	// on the off-path Analyze sweep, never the request path.
	if s.tokenAnomalyDetector != nil && s.metrics != nil {
		s.metrics.EnableTokenAnomalyMetrics()
		s.tokenAnomalyDetector.SetFindingHook(s.metrics.ObserveTokenAnomalyFinding)
	}
	// Token-usage hooks: armed only when BOTH a Recorder
	// (WithTokenUsageRecorder) AND a metrics registry (WithMetrics) are
	// wired. Without a recorder there is nothing to hook; without metrics the
	// recorder still records to its store, just with no hooks fired.
	if s.tokenUsageRecorder == nil || s.metrics == nil {
		return
	}
	s.metrics.EnableTokenUsageMetrics()
	s.tokenUsageRecorder.SetHooks(metering.Hooks{
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

// handleAdminTokenUsage serves GET /api/v1/admin/tokens/usage — the
// aggregated token-usage telemetry read API. Admin-gated (admin:read) by
// the /api/v1/admin/ prefix; only mounted when a Recorder is wired, so
// s.tokenUsageRecorder is always non-nil here.
func (s *Server) handleAdminTokenUsage(ctx HandlerContext) {
	metering.HandleAdminUsage(s.tokenUsageRecorder.UsageStore(), s.logger, ctx)
}

// handleAdminTokenPolicies serves GET /api/v1/admin/token-policies — the
// read-only token-policy governance view. Admin-gated (admin:read) by the
// /api/v1/admin/ prefix; only mounted when WithTokenPolicy is wired, so
// s.tokenPolicyStore is always non-nil here. Governance metadata only — the
// policy set holds no secret material.
func (s *Server) handleAdminTokenPolicies(ctx HandlerContext) {
	tokenpolicy.HandleAdminPolicies(s.tokenPolicyStore, s.logger, ctx)
}

// handleAdminTokenPortfolio serves GET /api/v1/admin/tokens/portfolio —
// aggregated token-portfolio overview (Phase 3 of token governance). Admin-
// gated (admin:read) by the /api/v1/admin/ prefix; only mounted when a
// Recorder is wired, so s.tokenUsageRecorder is always non-nil here.
func (s *Server) handleAdminTokenPortfolio(ctx HandlerContext) {
	metering.HandleAdminPortfolio(s.tokenUsageRecorder.UsageStore(), s.logger, ctx)
}

// handleAdminTokenSubject serves GET /api/v1/admin/tokens/subjects/:subject —
// the per-subject active-token count, read through the existing
// RefreshTokenSubjectCounter. Governance data only. Admin-gated (admin:read).
func (s *Server) handleAdminTokenSubject(ctx HandlerContext) {
	admin.HandleSubjectTokens(s.refreshTokenStore, s.logger, ctx)
}

// handleAdminTokenExpiring serves GET /api/v1/admin/tokens/expiring — the
// refresh-token expiry calendar (capacity planning / pre-expiry notification),
// read through the existing RefreshTokenExpiryLister. Governance data only
// (a thumbprint, never a token value). Admin-gated (admin:read).
func (s *Server) handleAdminTokenExpiring(ctx HandlerContext) {
	admin.HandleTokenExpiring(s.refreshTokenStore, s.logger, ctx)
}

// handleAdminTokenSuspicious serves GET /api/v1/admin/tokens/suspicious — the
// off-path-detected token-behavior anomalies (governance/reporting only; a
// finding never feeds an auth decision). Admin-gated (admin:read); only mounted
// when a detector is wired, so s.tokenAnomalyDetector is always non-nil here.
func (s *Server) handleAdminTokenSuspicious(ctx HandlerContext) {
	tokenanomaly.HandleAdminSuspicious(s.tokenAnomalyDetector.Findings(), s.logger, ctx)
}

// handleAdminBulkRevoke serves POST /api/v1/admin/tokens/bulk-revoke — the
// admin bulk-revoke workflow (admin:write). Reuses the existing refresh-token
// revocation SPIs with revocation-storm caps. no-store headers because it
// mutates token state.
func (s *Server) handleAdminBulkRevoke(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	admin.HandleBulkRevoke(s.refreshTokenStore, s.auditor, s.logger, ctx)
}

// RunTokenAnomalyDetection wakes every interval and runs one off-path
// TokenAnomalyDetector.Analyze sweep — turning the accumulated per-thumbprint
// observations + per-client rate buckets into governance findings on the
// suspicious-token list + the findings metric. Same shutdown contract as
// RunBreakGlassSweeper: it exits on ctx cancellation, a sweep error is logged
// but never tears down the loop, and it is the OPERATOR's responsibility to
// start it in a goroutine (NOT started automatically by NewServer/Mount, so
// embedding the SDK in tests or short-lived processes never leaks it).
//
//	go srv.RunTokenAnomalyDetection(ctx, time.Minute)
//
// DETECTION / REPORTING ONLY — never feeds an auth decision. No-op when no
// TokenAnomalyDetector is wired or interval <= 0.
func (s *Server) RunTokenAnomalyDetection(ctx context.Context, interval time.Duration) {
	if s.tokenAnomalyDetector == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.tokenAnomalyDetector.Analyze(ctx); err != nil {
				s.logger.Error("token anomaly analyze failed", "error", err)
			}
		}
	}
}

// applyIntrospectionSigningMetadata advertises RFC 9701 §7
// introspection_signing_alg_values_supported — ONLY when a dedicated
// introspection signer is wired (WithIntrospectionSigning); omitted
// entirely otherwise, so an unmodified deployment's discovery doc is
// byte-identical to a build without this feature. Relocated from
// server_helpers.go (which was at the line budget).
func (s *Server) applyIntrospectionSigningMetadata(cfg *oidc.ProviderMetadata, ctx context.Context) {
	if s.introspectionSigner == nil {
		return
	}
	cfg.IntrospectionSigningAlgValuesSupported = s.introspectionSigningAlgValues(ctx)
}

// introspectionSigningAlgValues derives the alg(s) the wired introspection
// signer actually produces. Prefers the published JWKS (authoritative —
// covers a signer mid-rotation with two live algs, though the shipped
// issuers never mix algs on one instance) and falls back to the signer's
// own Alg() method (the same fallback shape userinfoSignerProducesAlg
// uses) for a signer that opts out of JWKS discovery entirely (e.g. a
// KMS-backed IntrospectionSigner with no local public key to publish).
func (s *Server) introspectionSigningAlgValues(ctx context.Context) []string {
	if jp := s.IntrospectionSigningKeys(); jp != nil {
		if keys, err := jp.JWKS(ctx); err == nil {
			seen := map[string]struct{}{}
			for _, k := range keys {
				if k.Alg != "" {
					seen[k.Alg] = struct{}{}
				}
			}
			if len(seen) > 0 {
				out := make([]string, 0, len(seen))
				for a := range seen {
					out = append(out, a)
				}
				sort.Strings(out)
				return out
			}
		}
	}
	if ar, ok := s.introspectionSigner.(interface{ Alg() string }); ok {
		if alg := ar.Alg(); alg != "" {
			return []string{alg}
		}
	}
	return nil
}

// handleAdminListThreatPolicies serves GET /api/v1/admin/threat-policies —
// lists every configured Active ITDR threat policy. Admin-gated (admin:read);
// only mounted when s.threatPolicyStore is non-nil.
func (s *Server) handleAdminListThreatPolicies(ctx HandlerContext) {
	threataction.HandleAdminListPolicies(s.threatPolicyStore, s.logger, ctx)
}

// handleAdminGetThreatPolicy serves GET /api/v1/admin/threat-policies/:name —
// returns a single Active ITDR threat policy by name. Admin-gated (admin:read).
func (s *Server) handleAdminGetThreatPolicy(ctx HandlerContext) {
	threataction.HandleAdminGetPolicy(s.threatPolicyStore, s.logger, ctx)
}

// handleAdminPutThreatPolicy serves PUT /api/v1/admin/threat-policies/:name —
// creates or updates an Active ITDR threat policy. Admin-gated (admin:write).
func (s *Server) handleAdminPutThreatPolicy(ctx HandlerContext) {
	threataction.HandleAdminPutPolicy(s.threatPolicyStore, s.logger, ctx)
}

// handleAdminDeleteThreatPolicy serves DELETE /api/v1/admin/threat-policies/:name —
// deletes an Active ITDR threat policy. Admin-gated (admin:write).
func (s *Server) handleAdminDeleteThreatPolicy(ctx HandlerContext) {
	threataction.HandleAdminDeletePolicy(s.threatPolicyStore, s.logger, ctx)
}
