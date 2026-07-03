package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// New returns a Metrics bound to a fresh isolated Registry. This is
// the right shape for cmd/sso-server: the binary owns its own metric
// namespace and exposes it via /metrics.
//
// Includes the standard process + Go runtime collectors (goroutines,
// gc pause, file descriptors, etc.) which every prometheus deployment
// expects to see.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return NewWithRegistry(reg)
}

// NewWithRegistry binds the metric vectors to an existing Registerer.
// Use when embedding the SSO server into a larger app whose metrics
// already live on a shared registry (the embedding app supplies the
// process/Go runtime collectors itself).
//
// Caller is responsible for serving the registry via promhttp. The
// SSO server's /metrics endpoint only fires when sso.WithMetrics
// receives a *Metrics whose Registry is the one we constructed.
func NewWithRegistry(reg *prometheus.Registry) *Metrics {
	factory := promauto.With(reg)
	m := &Metrics{Registry: reg}

	// Grouped registration keeps each helper under the per-function
	// complexity/length budgets; ordering is preserved across helpers,
	// and every metric name/help/label/bucket is defined exactly once.
	registerHTTPMetrics(factory, m)
	registerLoginMetrics(factory, m)
	registerSignupFunnelMetrics(factory, m)
	registerMFACredentialMetrics(factory, m)
	registerRetentionMetrics(factory, m)
	registerAnomalyMetrics(factory, m)
	registerSigningOpMetrics(factory, m)
	registerSigningKeyMetrics(factory, m)
	registerClusterHealthMetrics(factory, m)
	registerCAEPMetrics(factory, m)
	registerRefreshRevocationMetrics(factory, m)
	registerFeatureGateMetrics(factory, m)

	return m
}

func registerHTTPMetrics(factory promauto.Factory, m *Metrics) {
	m.HTTPRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameHTTPRequestsTotal,
			Help: "Total HTTP requests served by the SSO router, by method and status class (2xx/3xx/4xx/5xx).",
		},
		[]string{LabelMethod, LabelStatusClass},
	)

	m.HTTPRequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    NameHTTPRequestDuration,
			Help:    "HTTP request latency in seconds, by method. Default buckets cover the typical auth-flow latency range (millis to seconds).",
			Buckets: prometheus.DefBuckets,
		},
		[]string{LabelMethod},
	)
}

func registerLoginMetrics(factory promauto.Factory, m *Metrics) {
	m.LoginAttemptsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameLoginAttemptsTotal,
			Help: "Login attempts at /auth/login, by authenticator provider and outcome (success/failure).",
		},
		[]string{LabelProvider, LabelOutcome},
	)

	m.TokensIssuedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameTokensIssuedTotal,
			Help: "Tokens issued on successful login, by token strategy (jwt/session).",
		},
		[]string{LabelStrategy},
	)

	m.RiskDecisionsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameRiskDecisionsTotal,
			Help: "RiskScorer decisions, by decision value (allow/deny/require_mfa). Zero traffic when no scorer is configured.",
		},
		[]string{LabelDecision},
	)

	m.ClientStoreCacheTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameClientStoreCacheTotal,
			Help: "Per-login ClientStore metadata cache lookups, by outcome (hit/miss). Zero traffic when WithClientStoreCache isn't wired. ValidateSecret bypasses the cache and is not counted here.",
		},
		[]string{LabelOutcome},
	)

	m.LoginDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    NameLoginDuration,
			Help:    "End-to-end /auth/login latency by authenticator provider + outcome (success/failure). Distinct from sso_http_request_duration_seconds so operators can detect a slow authenticator (TOTPStore lookup, OIDC federation roundtrip) without conflating it with /token + /userinfo latency.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{LabelProvider, LabelOutcome},
	)
}

func registerSignupFunnelMetrics(factory promauto.Factory, m *Metrics) {
	m.SignupStartedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSignupStartedTotal,
			Help: "Self-service signup flows initiated at /auth/register, by outcome (success/failure). Operators graph started→verified→completed to find the drop-off step.",
		},
		[]string{LabelOutcome},
	)
	m.SignupVerifiedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSignupVerifiedTotal,
			Help: "Email verifications completed for self-service signup, by outcome (success/failure). Zero traffic when signup verification is not enabled.",
		},
		[]string{LabelOutcome},
	)
	m.SignupCompletedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSignupCompletedTotal,
			Help: "Self-service signup funnels that reached the first-login milestone, by outcome (success/failure). A completed funnel = registered + verified (if required) + first successful login.",
		},
		[]string{LabelOutcome},
	)
	m.PasswordResetRequestedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NamePasswordResetRequestedTotal,
			Help: "Password reset flows initiated at /auth/forgot-password, by outcome (success/failure). Operators graph requested→completed to measure the email-delivery + user-action conversion rate.",
		},
		[]string{LabelOutcome},
	)
	m.PasswordResetCompletedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NamePasswordResetCompletedTotal,
			Help: "Password reset flows completed at /auth/reset-password, by outcome (success/failure). A completed reset sets a new credential; operators alert on a rising failure rate (broken link / expired token).",
		},
		[]string{LabelOutcome},
	)
}

func registerMFACredentialMetrics(factory promauto.Factory, m *Metrics) {
	m.MFAChallengesTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameMFAChallengesTotal,
			Help: "MFA challenges issued at /auth/login when RiskScorer returns DecisionRequireMFA. Labeled by mfa_method (the FIRST method in the supported set, since the user picks one downstream). Zero traffic when MFA orchestration isn't wired.",
		},
		[]string{LabelMFAMethod},
	)

	m.MFACompletionsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameMFACompletionsTotal,
			Help: "MFA verification outcomes at /auth/mfa, by mfa_method (totp/webauthn/push/...) and outcome (success/failure). Operators alert on a rising failure rate.",
		},
		[]string{LabelMFAMethod, LabelOutcome},
	)

	m.WebAuthnRegistrationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameWebAuthnRegistrationsTotal,
			Help: "WebAuthn registration ceremony completions at /webauthn/registration/finish, by outcome (success/failure). Begin observability comes from sso_http_requests_total on /webauthn/registration/begin.",
		},
		[]string{LabelOutcome},
	)

	m.WebAuthnAssertionsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameWebAuthnAssertionsTotal,
			Help: "WebAuthn login assertion completions at /webauthn/login/finish, by outcome (success/failure). Operators alert on a rising failure rate as a credential-stuffing signal.",
		},
		[]string{LabelOutcome},
	)

	m.CredentialHealthSignalsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameCredentialHealthSignals,
			Help: "Non-blocking login-time credential-health signals, by signal (weak/compromised). Emitted after a successful login when a PasswordHealthChecker flags the credential. Zero traffic when no checker is wired.",
		},
		[]string{LabelSignal},
	)

	m.MFACompletionDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    NameMFACompletionDuration,
			Help:    "End-to-end /auth/mfa latency by outcome (success/failure). The Push factor's polling loop dominates this — operators alerting on push-flow stalls graph p95 of {mfa_method=push}.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{LabelOutcome},
	)
}

func registerRetentionMetrics(factory promauto.Factory, m *Metrics) {
	m.RetentionPrunedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameRetentionPrunedTotal,
			Help: "Rows deleted by background retention loops, by subsystem (audit/snapshot/push_approvals). Sum is total prunes since start; rate is throughput. Zero traffic when no retention loop is configured.",
		},
		[]string{LabelSubsystem},
	)

	m.RetentionPruneErrorTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameRetentionPruneErrTotal,
			Help: "Retention prune calls that returned an error, by subsystem. Operators alert on a rising error rate relative to retention_pruned_total — sustained errors with no successes means retention is silently failing.",
		},
		[]string{LabelSubsystem},
	)
}

func registerAnomalyMetrics(factory promauto.Factory, m *Metrics) {
	m.AnomaliesDetectedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameAnomaliesDetectedTotal,
			Help: "Anomalies surfaced by behavioral detectors (off the request hot path). Labels: anomaly_type (impossible_travel/velocity_burst/new_device/new_country/brute_force_shadow), severity (info/warn/critical). Operators alerting on credential stuffing graph rate(critical) per 5min.",
		},
		[]string{LabelAnomalyType, LabelSeverity},
	)

	m.AnomalyDispatchedTotal = factory.NewCounter(
		prometheus.CounterOpts{
			Name: NameAnomalyDispatchedTotal,
			Help: "Login events OFFERED to the AsyncAnomalyRunner dispatcher (the offered-load denominator). No labels. Divide sso_anomaly_dispatch_drops_total by this to get the drop RATE (drops/offered) rather than only an absolute drop count. Zero traffic when no AnomalyRunner is wired.",
		},
	)

	m.AnomalyDispatchDropsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameAnomalyDispatchDropsTotal,
			Help: "Login events dropped by the AsyncAnomalyRunner bounded queue. Non-zero = login traffic outpaces detector capacity; raise queue size or worker count, or accept reduced anomaly coverage during bursts. reason ∈ {queue_full, ctx_canceled}.",
		},
		[]string{LabelDropReason},
	)

	m.AnomalyInspectErrorsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameAnomalyInspectErrorsTotal,
			Help: "Detector.Inspect calls that returned an error (DB timeout, store unreachable). Surfaces the silently-broken-detector failure mode — operators alert on any non-zero rate per detector.",
		},
		[]string{LabelDetector},
	)
}

func registerSigningOpMetrics(factory promauto.Factory, m *Metrics) {
	m.SigningKeyRotationsTotal = factory.NewCounter(
		prometheus.CounterOpts{
			Name: NameSigningKeyRotationsTotal,
			Help: "Automatic signing-key rotations performed. Alert if it stops advancing while rotation is enabled (loop wedged) — RPs would keep verifying against an aging key.",
		},
	)

	m.FAPIViolationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameFAPIViolationsTotal,
			Help: "FAPI 2.0 baseline rule violations. Labels: rule (the 5 fapi:* ids — bounded), mode (inspection | enforce). The inspection-mode ramp-up dashboard: graph rate(...) by rule to see which RPs / requests fail which rule before flipping to enforce. Zero when the FAPI profile is off.",
		},
		[]string{LabelFAPIRule, LabelFAPIMode},
	)

	m.SigningOperationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSigningOperationsTotal,
			Help: "External (KMS/HSM) signing operations. Labels: alg (eddsa/es256/rs256/ps256), outcome (success/error). A rising error rate signals KMS outage or throttling; token issuance fails closed when signing errors. Zero when no external signer is wired.",
		},
		[]string{LabelAlg, LabelOutcome},
	)

	m.SigningDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    NameSigningDuration,
			Help:    "External (KMS/HSM) signing round-trip latency in seconds, labeled by alg. DefBuckets (.005s-10s) cover the typical 5-50ms KMS RTT plus tail; alert on a p99 that threatens token-issuance latency.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{LabelAlg},
	)

	m.SigningBackendUp = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: NameSigningBackendUp,
			Help: "External (KMS/HSM) signing backend health: 1 if the last signing operation succeeded, 0 after a failure. Labeled by alg. Alert on 0 — it fires before /readyz drains the replica. Never set when no external signer is wired.",
		},
		[]string{LabelAlg},
	)
}

func registerSigningKeyMetrics(factory promauto.Factory, m *Metrics) {
	m.SigningKeyAdoptionErrorsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSigningKeyAdoptionErrorsTotal,
			Help: "Peer signing-key adoptions that failed in the leaderless aggregation loop, by reason (decode/adopt). decode = malformed/off-curve/weak peer JWK; adopt = decoded but every matching-alg issuer rejected it (e.g. kid collision). Fail-open (key skipped); a rising rate surfaces a peer publishing bad keys before it manifests as unknown-kid validation failures. Zero when no signing-key registry is wired.",
		},
		[]string{LabelReason},
	)

	m.CIBAPingTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameCIBAPingTotal,
			Help: "CIBA ping-delivery attempts from the detached post-resolution notifier goroutine, by outcome (success/error). An error (notifier returned an error or panicked) degrades the client to poll; alert on a rising error series with no successes (notification endpoint wedged/unreachable). Zero traffic when no CIBAPingNotifier is wired.",
		},
		[]string{LabelOutcome},
	)

	m.SigningKeyAggregationUp = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: NameSigningKeyAggregationUp,
			Help: "Leaderless signing-key aggregation subscription health: 1 while this replica is subscribed and adopting peers' keys, 0 while degraded (registry Subscribe channel closed, loop retrying). Degraded means the replica stops adopting peers' newly-rotated keys while local signing still succeeds — alert on 0. Never set when no signing-key registry is wired.",
		},
	)

	m.SigningKeyCutoverTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSigningKeyCutoverTotal,
			Help: "Deadline-coordinated signing-key rotation cutovers this replica enacted on a received cross-replica rotation Event, by outcome (deferred/extended/adopted_only/noop). The feature defers a demoted kid's retirement to a cluster-coordinated deadline so a rolling deploy can't strand a token under an early-retired kid (unknown-kid 401). A rising noop series means peers send garbage/superseded Events (fail-safe absorbs them). Zero when coordinated rotation isn't armed.",
		},
		[]string{LabelOutcome},
	)
}

func registerClusterHealthMetrics(factory promauto.Factory, m *Metrics) {
	m.InvalidationBusUp = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: NameInvalidationBusUp,
			Help: "Cross-replica invalidation-bus subscription health: 1 while this replica is subscribed and applying invalidations, 0 while degraded (bus Subscribe channel closed under a live context, loop retrying). Degraded means the replica stops applying cross-replica invalidations (tenant suspension, client-cache, coordinated key rotation, token revocation) until it resubscribes — alert on 0. Never set when no invalidation bus is wired.",
		},
	)

	m.InvalidationBusReconnectsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameInvalidationBusReconnectsTotal,
			Help: "Cross-replica invalidation-bus subscription transitions, by reason (degraded/reconnected). degraded = the Subscribe channel closed under a live context and the loop flipped degraded (missing invalidations); reconnected = a degraded loop resubscribed and resumed. Alert on a rising degraded series without matching reconnected ticks (bus backend flapping/down). Zero traffic when no invalidation bus is wired.",
		},
		[]string{LabelReason},
	)

	m.NetPolicyClassifierUp = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: NameNetPolicyClassifierUp,
			Help: "Network-policy Classifier Watch subscription health: 1 while this replica is subscribed and applying policy updates, 0 while degraded (Store.Watch channel closed under a live context, loop retrying). Degraded means the Classifier keeps serving its last snapshot (fail-open) but stops picking up policy edits until it resubscribes — alert on 0. Never set when no network-policy store is wired.",
		},
	)

	m.NetPolicyClassifierReconnectsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameNetPolicyClassifierReconnectsTotal,
			Help: "Network-policy Classifier Watch subscription transitions, by reason (degraded/reconnected). degraded = the Watch channel closed under a live context and the loop flipped degraded (serving a frozen snapshot); reconnected = a degraded loop resubscribed, re-listed, and resumed. Alert on a rising degraded series without matching reconnected ticks (policy backend flapping/down). Zero traffic when no network-policy store is wired.",
		},
		[]string{LabelReason},
	)
}

func registerCAEPMetrics(factory promauto.Factory, m *Metrics) {
	m.CAEPSetsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameCAEPSetsTotal,
			Help: "OpenID Shared Signals (CAEP/RISC) Security Event Token push attempts from the detached transmitter goroutine, by outcome (success/failed/dropped). A failed/dropped SET means an affected RP missed a real-time revocation signal; alert on a rising failed/dropped series. Zero traffic when no CAEP transmitter is wired.",
		},
		[]string{LabelOutcome},
	)

	m.SSFSetsReceivedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSSFSetsReceivedTotal,
			Help: "Inbound OpenID Shared Signals (CAEP/SSF) Security Event Tokens processed by the receiver, by outcome (revoked/noop/rejected). `rejected` is a SET that failed validation (bad signature/untrusted iss/wrong aud/expired/replayed/malformed) — a rising series can mean a misconfigured upstream or a forged/replayed-SET probe; `revoked` drove a local revocation; `noop` mapped to no local subject or only unknown events. Zero traffic when no CAEP receiver is wired.",
		},
		[]string{LabelOutcome},
	)
}

func registerRefreshRevocationMetrics(factory promauto.Factory, m *Metrics) {
	m.RefreshRotationVelocityExceededTotal = factory.NewCounter(
		prometheus.CounterOpts{
			Name: NameRefreshRotationVelocityExceededTotal,
			Help: "Refresh-token families revoked by the per-family rotation-velocity cap (a family rotated faster than the configured per-window limit). No labels (a familyID/user/client label would be unbounded). The wire response stays the generic invalid_grant, so this counter plus the refresh_rotation_velocity_exceeded audit event are the only operator visibility. Zero traffic when no rotation limiter is wired.",
		},
	)

	m.TokenRevocationsPropagatedTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameTokenRevocationsPropagatedTotal,
			Help: "Cross-replica access-token revocation propagation events, by direction (published/adopted). published = this replica broadcast a token-revoked Event after a local /token/revoke; adopted = this replica added a peer-published revoked token to its own in-process deny-set. No token/jti label (bounded cardinality). Purely additive + best-effort. Zero traffic when cross-replica revocation isn't armed.",
		},
		[]string{LabelDirection},
	)
}

func registerFeatureGateMetrics(factory promauto.Factory, m *Metrics) {
	m.FeatureGateEnabled = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: NameFeatureGateEnabled,
			Help: "Whether a protocol surface's routes are mounted (1) or explicitly disabled via feature_gates (0). Set once at boot per feature (bounded cardinality — the fixed gate set), never on the request path.",
		},
		[]string{LabelFeature},
	)
}

// EnableTenantMetrics lazily constructs + registers the two opt-in
// per-tenant counters (LoginAttemptsByTenantTotal + TokensIssuedByTenantTotal)
// on this Metrics' Registry. It is called by the Server ONLY when an
// operator supplies a bounded tenant allowlist (sso.WithTenantMetricsAllowlist)
// — so without that option the vectors stay nil and the metrics are never
// registered or emitted (zero series, byte-identical off, §5).
//
// Idempotent: a second call is a no-op (the vectors are already built).
// Bounded cardinality is the CALLER's responsibility — the Server maps any
// tenant outside the allowlist to TenantLabelOther before touching the
// label, capping the tenant dimension at len(allowlist)+1.
func (m *Metrics) EnableTenantMetrics() {
	if m == nil || m.LoginAttemptsByTenantTotal != nil {
		return
	}
	factory := promauto.With(m.Registry)
	m.LoginAttemptsByTenantTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameLoginAttemptsByTenantTotal,
			Help: "Login attempts at /auth/login broken down by tenant + outcome (success/failure). OPT-IN + cardinality-gated: the tenant label is restricted to an operator-supplied allowlist, with every other tenant folded into the single tenant=\"other\" bucket. Zero traffic (and no series) when no allowlist is wired.",
		},
		[]string{LabelTenant, LabelOutcome},
	)
	m.TokensIssuedByTenantTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameTokensIssuedByTenantTotal,
			Help: "Tokens issued broken down by tenant + token strategy (jwt/session). OPT-IN + cardinality-gated: the tenant label is restricted to an operator-supplied allowlist, with every other tenant folded into the single tenant=\"other\" bucket. Zero traffic (and no series) when no allowlist is wired.",
		},
		[]string{LabelTenant, LabelStrategy},
	)
}

// ObserveClientStoreCache bumps the per-login ClientStore cache counter for
// outcome ("hit" or "miss"). Nil-safe so the decorator can call it
// unconditionally whether or not metrics are wired. outcome is a bounded
// 2-value dimension (§5) — never a per-client label.
func (m *Metrics) ObserveClientStoreCache(outcome string) {
	if m == nil || m.ClientStoreCacheTotal == nil {
		return
	}
	m.ClientStoreCacheTotal.WithLabelValues(outcome).Inc()
}

// Signup funnel observation helpers. Nil-safe so callers can fire them
// unconditionally; each is a no-op when the corresponding counter was
// never registered (signup/password-reset not enabled).

func (m *Metrics) ObserveSignupStarted(outcome string) {
	if m == nil || m.SignupStartedTotal == nil {
		return
	}
	m.SignupStartedTotal.WithLabelValues(outcome).Inc()
}

func (m *Metrics) ObserveSignupVerified(outcome string) {
	if m == nil || m.SignupVerifiedTotal == nil {
		return
	}
	m.SignupVerifiedTotal.WithLabelValues(outcome).Inc()
}

func (m *Metrics) ObserveSignupCompleted(outcome string) {
	if m == nil || m.SignupCompletedTotal == nil {
		return
	}
	m.SignupCompletedTotal.WithLabelValues(outcome).Inc()
}

func (m *Metrics) ObservePasswordResetRequested(outcome string) {
	if m == nil || m.PasswordResetRequestedTotal == nil {
		return
	}
	m.PasswordResetRequestedTotal.WithLabelValues(outcome).Inc()
}

func (m *Metrics) ObservePasswordResetCompleted(outcome string) {
	if m == nil || m.PasswordResetCompletedTotal == nil {
		return
	}
	m.PasswordResetCompletedTotal.WithLabelValues(outcome).Inc()
}
