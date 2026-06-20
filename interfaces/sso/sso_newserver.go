package sso

import (
	"context"
	"time"

	"github.com/snaplink/sso/internal/auth/consent"
	"github.com/snaplink/sso/shared/spi"
)

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
	s.consentChallenges = consent.NewChallengeStore()
	for _, opt := range opts {
		opt(s)
	}
	// Tap the audit pipeline for the CAEP/SSF transmitter, if wired. Done
	// here (after every option ran, so order between WithAuditRecorder and
	// WithCAEPTransmitter doesn't matter) by fanning the recorder's sink
	// out to the transmitter. When the transmitter is unwired this branch
	// is skipped entirely, so a build without it is byte-identical.
	if s.caepTransmitter != nil && s.auditor != nil {
		s.auditor.AddSink(s.caepTransmitter)
	}
	// Per-tenant metrics (§5): register the opt-in vectors when BOTH a
	// tenant allowlist AND a metrics registry are wired. Done post-options
	// (order between WithMetrics and WithTenantMetricsAllowlist is
	// irrelevant); EnableTenantMetrics is idempotent. Without both, the
	// vectors stay nil and nothing is registered or emitted (byte-identical).
	if len(s.tenantMetricsAllowlist) > 0 && s.metrics != nil {
		s.metrics.EnableTenantMetrics()
	}
	// OpenID Federation 1.0 automatic client registration (slice 3) then the
	// opt-in per-login ClientStore metadata cache. Order between these two
	// ClientStore decorators is load-bearing: the cache MUST wrap the
	// federation decorator (OUTERMOST) so a Get hit short-circuits before the
	// inner federation/operator store. See each helper's doc for the
	// byte-identical preconditions when a precondition does not hold.
	s.applyFederationAutoRegistration()
	s.applyClientStoreCache()
	return s
}
