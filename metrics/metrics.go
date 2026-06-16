// Package metrics holds the Prometheus metric vectors the SSO server
// emits, plus the HTTP middleware that records request count + latency.
//
// Design choices that affect operators:
//
//   - All metric names are prefixed `sso_` so they don't collide with
//     metrics an embedding application emits on the same registry.
//
//   - Label cardinality is bounded by design — we use `status_class`
//     (2xx / 4xx / 5xx) rather than raw status code, `method` rather
//     than path, `provider` (authenticator name) rather than user id.
//     Operators who want per-endpoint breakdowns should derive them
//     from traces, not from labels.
//
//   - The Registry is held INSIDE the Metrics struct so operators who
//     embed the SSO server in a larger app can share a registry via
//     NewWithRegistry. Default New() returns a fresh isolated one
//     (the right thing for cmd/sso-server).
//
// Wire with sso.WithMetrics(metrics.New()) — when the option is
// omitted, the server skips instrumentation entirely (zero overhead).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics groups every collector the SSO server publishes. Construct
// once at server boot, pass into [sso.WithMetrics].
type Metrics struct {
	// Registry is the prometheus.Registerer the metrics are bound to.
	// Exposed so /metrics can serve from it and tests can scrape it
	// directly.
	Registry *prometheus.Registry

	// HTTP layer.
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	// Auth flow.
	LoginAttemptsTotal *prometheus.CounterVec // labels: provider, outcome
	TokensIssuedTotal  *prometheus.CounterVec // labels: strategy

	// Per-tenant login + issuance breakdowns. OPT-IN and CARDINALITY-
	// GATED: emitted ONLY through an operator-supplied bounded allowlist
	// (sso.WithTenantMetricsAllowlist). Every tenant NOT on the allowlist
	// maps to the single LabelTenant=TenantLabelOther bucket, so the tenant
	// label cardinality is len(allowlist)+1 — never the unbounded SaaS-
	// tenant set (§5). Both vectors are nil when no allowlist is wired (the
	// metrics are not registered or emitted — byte-identical off); this
	// mirrors the MFA-method restriction to SupportedMethods() before the
	// label reaches the registry.
	LoginAttemptsByTenantTotal *prometheus.CounterVec // labels: tenant, outcome
	TokensIssuedByTenantTotal  *prometheus.CounterVec // labels: tenant, strategy

	// Risk scoring (zero traffic when no RiskScorer wired).
	RiskDecisionsTotal *prometheus.CounterVec // labels: decision

	// Per-login ClientStore cache (zero traffic when WithClientStoreCache
	// isn't wired). Bounded {outcome} ∈ {hit, miss} — NO per-client_id label.
	ClientStoreCacheTotal *prometheus.CounterVec // labels: outcome

	// MFA orchestration (zero traffic when no MFAProvider wired).
	// MFAChallengesTotal counts every challenge issued at
	// /auth/login when the risk scorer returns DecisionRequireMFA;
	// MFACompletionsTotal counts /auth/mfa outcomes by mfa_method
	// + outcome (success/failure). Bounded cardinality: methods are
	// the wire-stable strings totp/webauthn/push/etc, not per-user.
	MFAChallengesTotal  *prometheus.CounterVec // labels: mfa_method
	MFACompletionsTotal *prometheus.CounterVec // labels: mfa_method, outcome

	// Retention scheduler observability. Single counter pair shared
	// across the three subsystems (audit, snapshot, push_approvals)
	// so operators can graph "what got pruned recently" with a
	// single PromQL query. Bounded subsystem cardinality (3 known
	// values). Operators alert on the errors series rising relative
	// to the pruned series — sustained errors with no successes
	// means retention is silently failing.
	RetentionPrunedTotal     *prometheus.CounterVec // labels: subsystem
	RetentionPruneErrorTotal *prometheus.CounterVec // labels: subsystem

	// WebAuthn ceremony completion. Incremented at the Finish phase
	// (cryptographic verification step) only — Begin observability
	// is derivable from sso_http_requests_total on the begin paths.
	// outcome ∈ {success, failure} (bounded cardinality).
	WebAuthnRegistrationsTotal *prometheus.CounterVec // labels: outcome
	WebAuthnAssertionsTotal    *prometheus.CounterVec // labels: outcome

	// CredentialHealthSignalsTotal counts non-blocking login-time
	// credential-health signals, by signal ∈ {weak, compromised}
	// (bounded). Emitted alongside the password_weak / password_compromised
	// audit events after a successful login. Zero traffic when no
	// PasswordHealthChecker is wired. Operators graph the rate to size a
	// "users on weak credentials" remediation campaign.
	CredentialHealthSignalsTotal *prometheus.CounterVec // labels: signal

	// Login + MFA latency histograms. Distinct from the generic HTTP
	// duration so operators can graph login-specific latency
	// (authenticator round-trips, password verification, risk scorer
	// time) without conflating it with /token / /userinfo / /metrics
	// noise. Labels: provider (login only) / outcome (login + mfa).
	LoginDuration         *prometheus.HistogramVec // labels: provider, outcome
	MFACompletionDuration *prometheus.HistogramVec // labels: outcome

	// Anomaly detection (zero traffic when no AnomalyRunner wired).
	// AnomaliesDetectedTotal counts each Anomaly surfaced by a
	// detector, labeled by type + severity. AnomalyDispatchedTotal
	// counts every event OFFERED to the dispatcher (the offered-load
	// denominator) — no labels (bounded cardinality); pair it with
	// AnomalyDispatchDropsTotal to derive a drop RATE (drops/offered)
	// rather than only an absolute drop count. AnomalyDispatchDropsTotal
	// counts events dropped by the bounded-queue dispatcher (load-
	// shedding metric — non-zero = login traffic outpaces detector
	// capacity). AnomalyInspectErrorsTotal counts per-detector
	// failures (DB timeout, store unreachable) — surfaces the
	// "anomaly detection silently broken" failure mode.
	AnomaliesDetectedTotal    *prometheus.CounterVec // labels: anomaly_type, severity
	AnomalyDispatchedTotal    prometheus.Counter     // no labels
	AnomalyDispatchDropsTotal *prometheus.CounterVec // labels: reason
	AnomalyInspectErrorsTotal *prometheus.CounterVec // labels: detector

	// SigningKeyRotationsTotal counts automatic signing-key rotations.
	// No labels — rotation is a single global, low-frequency event;
	// operators alert if it stops advancing (rotation loop wedged) or
	// jumps unexpectedly. Zero when rotation is disabled.
	SigningKeyRotationsTotal prometheus.Counter

	// FAPIViolationsTotal counts FAPI 2.0 baseline rule violations.
	// Labels: rule (the 5 fapi:* ids — bounded), mode (inspection |
	// enforce). The inspection-mode ramp-up dashboard: graph
	// rate(...) by rule to see which RPs / requests fail which rule
	// before flipping to enforce. Zero when the FAPI profile is off.
	FAPIViolationsTotal *prometheus.CounterVec

	// SigningOperationsTotal + SigningDuration instrument the JWT
	// signing seam when backed by an EXTERNAL signer (KMS/HSM). Labels:
	// alg (bounded: eddsa/es256/rs256/ps256), outcome (success/error).
	// In-process signing is microsecond-scale and not instrumented; the
	// point of these is the KMS/HSM network round-trip — operators
	// alert on a rising error rate (KMS outage / throttling) or a p99
	// duration that threatens token-issuance latency. Zero when no
	// external signer is wired.
	SigningOperationsTotal *prometheus.CounterVec   // labels: alg, outcome
	SigningDuration        *prometheus.HistogramVec // labels: alg

	// SigningBackendUp is 1 while the external signer's last operation
	// succeeded, 0 after a failure — a directly alertable gauge that
	// fires BEFORE /readyz drains the replica (the readyz probe tolerates
	// stale failures; this gauge reflects the last raw outcome). Labels:
	// alg. Never set when no external signer is wired.
	SigningBackendUp *prometheus.GaugeVec // labels: alg

	// SigningKeyAdoptionErrorsTotal counts peer signing-key adoptions that
	// failed in the leaderless aggregation loop, by reason ∈ {decode, adopt}
	// (bounded). decode = a peer JWK was malformed/off-curve/weak; adopt = it
	// decoded but every matching-alg issuer rejected AdoptVerifyKey. Both are
	// fail-open (the key is skipped, the loop continues), so the only signal an
	// operator gets WITHOUT this metric is a log line — a rising rate here
	// surfaces a peer publishing bad keys (or a kid collision) before it
	// manifests as unexplained "unknown kid" validation failures. Zero traffic
	// when no signing-key registry is wired.
	SigningKeyAdoptionErrorsTotal *prometheus.CounterVec // labels: reason

	// CIBAPingTotal counts CIBA ping-delivery attempts fired from the
	// detached notifier goroutine after a backchannel request resolves, by
	// outcome ∈ {success, error} (bounded). A ping failure (the notifier
	// returned an error OR panicked) degrades the client to poll, so it is
	// non-fatal — but operators have no other visibility into a wedged or
	// unreachable notification endpoint. Alert on a rising error series:
	// sustained errors with no successes means ping delivery is broken and
	// clients are silently falling back to poll. Zero traffic when no
	// CIBAPingNotifier is wired.
	CIBAPingTotal *prometheus.CounterVec // labels: outcome

	// SigningKeyAggregationUp is 1 while this replica's peer-key subscription
	// is healthy, 0 while it is degraded (the registry's Subscribe channel
	// closed and the loop is between resubscribe attempts). A degraded
	// subscription means the replica STOPS adopting peers' newly-rotated keys
	// while local signing keeps succeeding — peers' tokens later fail with
	// "unknown kid" yet nothing else flags it. This gauge (plus the matching
	// readiness check) is the direct alert. No labels — aggregation health is a
	// single per-replica condition. Never set when no registry is wired.
	SigningKeyAggregationUp prometheus.Gauge

	// SigningKeyCutoverTotal counts deadline-coordinated signing-key rotation
	// cutovers this replica ENACTED on receiving a cross-replica
	// KindSigningKeyRotation Event, by outcome ∈ {deferred, extended,
	// adopted_only, noop} (bounded). The feature defers a demoted kid's
	// retirement to a cluster-coordinated deadline so a rolling deploy can't
	// strand a token under an early-retired kid ("unknown kid" 401). A healthy
	// rotation shows a deferred (or adopted_only) tick on each peer; a rising
	// noop series means peers are sending garbage/superseded Events (the
	// fail-safe absorbs them — the local grace fallback still retires). No kid /
	// replica label (§5 bounded cardinality). Zero traffic when coordinated
	// rotation isn't armed (WithCoordinatedKeyRotation + a bus).
	SigningKeyCutoverTotal *prometheus.CounterVec // labels: outcome

	// InvalidationBusUp is 1 while this replica's cross-replica invalidation-bus
	// subscription is healthy, 0 while it is degraded (the bus Subscribe channel
	// closed while the run context was still live and the loop is between
	// resubscribe attempts). A degraded subscription means the replica STOPS
	// applying cross-replica invalidations — a just-suspended tenant, edited
	// client, or revoked token keeps being honored locally until its own TTL/exp
	// — while /readyz would otherwise stay green. This gauge (plus the matching
	// readiness check) is the direct alert. No labels — bus health is a single
	// per-replica condition. Never set when no invalidation bus is wired.
	InvalidationBusUp prometheus.Gauge

	// InvalidationBusReconnectsTotal counts cross-replica invalidation-bus
	// subscription transitions, by reason ∈ {degraded, reconnected} (bounded).
	// degraded = the Subscribe channel closed under a live context and the loop
	// flipped degraded; reconnected = a degraded loop resubscribed and resumed.
	// A rising degraded series (especially without matching reconnected ticks)
	// means the bus backend is flapping or down and this replica is missing
	// cross-replica invalidations. No per-event/per-kind label (§5 bounded
	// cardinality). Zero traffic when no invalidation bus is wired.
	InvalidationBusReconnectsTotal *prometheus.CounterVec // labels: reason

	// NetPolicyClassifierUp is 1 while this replica's network-policy Classifier
	// is subscribed to Store.Watch and applying updates, 0 while it is degraded
	// (the Watch channel closed under a live context and the loop is between
	// resubscribe attempts). A degraded Classifier keeps SERVING its last
	// snapshot (fail-open — Classify never blocks or errors) but STOPS picking up
	// policy edits, so a just-added/removed network class is not reflected here
	// until it resubscribes — while /readyz would otherwise stay green. This
	// gauge (plus the matching readiness check) is the direct alert. No labels —
	// classifier health is a single per-replica condition. Never set when no
	// network-policy store is wired.
	NetPolicyClassifierUp prometheus.Gauge

	// NetPolicyClassifierReconnectsTotal counts network-policy Classifier Watch
	// subscription transitions, by reason ∈ {degraded, reconnected} (bounded).
	// degraded = the Watch channel closed under a live context and the loop
	// flipped degraded; reconnected = a degraded loop resubscribed, re-listed,
	// and resumed. A rising degraded series (especially without matching
	// reconnected ticks) means the policy backend is flapping or down and this
	// replica is serving a frozen policy snapshot. No per-policy label (§5
	// bounded cardinality). Zero traffic when no network-policy store is wired.
	NetPolicyClassifierReconnectsTotal *prometheus.CounterVec // labels: reason

	// CAEPSetsTotal counts OpenID Shared Signals (CAEP/RISC) Security
	// Event Token push attempts from the detached transmitter goroutine, by
	// outcome ∈ {success, failed, dropped} (bounded). A failed/dropped SET
	// means an affected RP did NOT receive a real-time revocation signal and
	// will only converge on its own token TTL — alert on a rising
	// failed/dropped series to catch a wedged or misconfigured receiver
	// before it widens the cross-RP revocation window. Zero traffic when no
	// CAEP transmitter is wired.
	CAEPSetsTotal *prometheus.CounterVec // labels: outcome

	// SSFSetsReceivedTotal counts INBOUND OpenID Shared Signals (CAEP/SSF)
	// Security Event Tokens processed by the receiver, by outcome ∈
	// {revoked, noop, rejected} (bounded). `rejected` is a SET that failed
	// validation (bad signature / untrusted iss / wrong aud / expired /
	// replayed / malformed) — a rising rejected series can mean a
	// misconfigured upstream OR a forged/replayed-SET probing attempt;
	// `revoked` is a validated SET that drove a local revocation; `noop` is
	// a valid SET that mapped to no local subject or carried only unknown
	// events. Zero traffic when no CAEP receiver is wired.
	SSFSetsReceivedTotal *prometheus.CounterVec // labels: outcome

	// RefreshRotationVelocityExceededTotal counts refresh-token families
	// killed by the per-family rotation-VELOCITY cap (the store implements
	// oauth.RefreshTokenRotationLimiter and a family exceeded the configured
	// per-window rotation count). No labels — a velocity breach is a single
	// global security condition, and a familyID/user/client label would be
	// unbounded (§5). Each increment is one family that rotated too fast and
	// was revoked; the wire response stays the generic invalid_grant, so this
	// counter (plus the refresh_rotation_velocity_exceeded audit event) is the
	// only operator visibility. Zero traffic when no rotation limiter is wired.
	RefreshRotationVelocityExceededTotal prometheus.Counter

	// TokenRevocationsPropagatedTotal counts cross-replica access-token
	// revocation propagation events, by direction ∈ {published, adopted}
	// (bounded). `published` = this replica broadcast a KindTokenRevoked Event
	// after a local /token/revoke; `adopted` = this replica added a
	// peer-published revoked token to its own in-process deny-set. No token/jti
	// label (§5 bounded cardinality). The propagation is purely additive
	// (revocation only ever ADDS to a deny-set) and best-effort, so this counter
	// is the operator's visibility into whether revocations are converging
	// across replicas. Zero traffic when WithCrossReplicaRevocation isn't armed
	// (or no bus is wired).
	TokenRevocationsPropagatedTotal *prometheus.CounterVec // labels: direction
}

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

	return &Metrics{
		Registry: reg,

		HTTPRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameHTTPRequestsTotal,
				Help: "Total HTTP requests served by the SSO router, by method and status class (2xx/3xx/4xx/5xx).",
			},
			[]string{LabelMethod, LabelStatusClass},
		),

		HTTPRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: NameHTTPRequestDuration,
				Help: "HTTP request latency in seconds, by method. Default buckets cover the typical auth-flow latency range (millis to seconds).",
				// DefBuckets cover .005s through 10s — appropriate for auth flows.
				Buckets: prometheus.DefBuckets,
			},
			[]string{LabelMethod},
		),

		LoginAttemptsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameLoginAttemptsTotal,
				Help: "Login attempts at /auth/login, by authenticator provider and outcome (success/failure).",
			},
			[]string{LabelProvider, LabelOutcome},
		),

		TokensIssuedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameTokensIssuedTotal,
				Help: "Tokens issued on successful login, by token strategy (jwt/session).",
			},
			[]string{LabelStrategy},
		),

		RiskDecisionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameRiskDecisionsTotal,
				Help: "RiskScorer decisions, by decision value (allow/deny/require_mfa). Zero traffic when no scorer is configured.",
			},
			[]string{LabelDecision},
		),

		ClientStoreCacheTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameClientStoreCacheTotal,
				Help: "Per-login ClientStore metadata cache lookups, by outcome (hit/miss). Zero traffic when WithClientStoreCache isn't wired. ValidateSecret bypasses the cache and is not counted here.",
			},
			[]string{LabelOutcome},
		),

		MFAChallengesTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameMFAChallengesTotal,
				Help: "MFA challenges issued at /auth/login when RiskScorer returns DecisionRequireMFA. Labeled by mfa_method (the FIRST method in the supported set, since the user picks one downstream). Zero traffic when MFA orchestration isn't wired.",
			},
			[]string{LabelMFAMethod},
		),

		MFACompletionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameMFACompletionsTotal,
				Help: "MFA verification outcomes at /auth/mfa, by mfa_method (totp/webauthn/push/...) and outcome (success/failure). Operators alert on a rising failure rate.",
			},
			[]string{LabelMFAMethod, LabelOutcome},
		),

		RetentionPrunedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameRetentionPrunedTotal,
				Help: "Rows deleted by background retention loops, by subsystem (audit/snapshot/push_approvals). Sum is total prunes since start; rate is throughput. Zero traffic when no retention loop is configured.",
			},
			[]string{LabelSubsystem},
		),

		RetentionPruneErrorTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameRetentionPruneErrTotal,
				Help: "Retention prune calls that returned an error, by subsystem. Operators alert on a rising error rate relative to retention_pruned_total — sustained errors with no successes means retention is silently failing.",
			},
			[]string{LabelSubsystem},
		),

		WebAuthnRegistrationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameWebAuthnRegistrationsTotal,
				Help: "WebAuthn registration ceremony completions at /webauthn/registration/finish, by outcome (success/failure). Begin observability comes from sso_http_requests_total on /webauthn/registration/begin.",
			},
			[]string{LabelOutcome},
		),

		WebAuthnAssertionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameWebAuthnAssertionsTotal,
				Help: "WebAuthn login assertion completions at /webauthn/login/finish, by outcome (success/failure). Operators alert on a rising failure rate as a credential-stuffing signal.",
			},
			[]string{LabelOutcome},
		),

		CredentialHealthSignalsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameCredentialHealthSignals,
				Help: "Non-blocking login-time credential-health signals, by signal (weak/compromised). Emitted after a successful login when a PasswordHealthChecker flags the credential. Zero traffic when no checker is wired.",
			},
			[]string{LabelSignal},
		),

		LoginDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    NameLoginDuration,
				Help:    "End-to-end /auth/login latency by authenticator provider + outcome (success/failure). Distinct from sso_http_request_duration_seconds so operators can detect a slow authenticator (TOTPStore lookup, OIDC federation roundtrip) without conflating it with /token + /userinfo latency.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{LabelProvider, LabelOutcome},
		),

		MFACompletionDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    NameMFACompletionDuration,
				Help:    "End-to-end /auth/mfa latency by outcome (success/failure). The Push factor's polling loop dominates this — operators alerting on push-flow stalls graph p95 of {mfa_method=push}.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{LabelOutcome},
		),

		AnomaliesDetectedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameAnomaliesDetectedTotal,
				Help: "Anomalies surfaced by behavioral detectors (off the request hot path). Labels: anomaly_type (impossible_travel/velocity_burst/new_device/new_country/brute_force_shadow), severity (info/warn/critical). Operators alerting on credential stuffing graph rate(critical) per 5min.",
			},
			[]string{LabelAnomalyType, LabelSeverity},
		),

		AnomalyDispatchedTotal: factory.NewCounter(
			prometheus.CounterOpts{
				Name: NameAnomalyDispatchedTotal,
				Help: "Login events OFFERED to the AsyncAnomalyRunner dispatcher (the offered-load denominator). No labels. Divide sso_anomaly_dispatch_drops_total by this to get the drop RATE (drops/offered) rather than only an absolute drop count. Zero traffic when no AnomalyRunner is wired.",
			},
		),

		AnomalyDispatchDropsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameAnomalyDispatchDropsTotal,
				Help: "Login events dropped by the AsyncAnomalyRunner bounded queue. Non-zero = login traffic outpaces detector capacity; raise queue size or worker count, or accept reduced anomaly coverage during bursts. reason ∈ {queue_full, ctx_canceled}.",
			},
			[]string{LabelDropReason},
		),

		AnomalyInspectErrorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameAnomalyInspectErrorsTotal,
				Help: "Detector.Inspect calls that returned an error (DB timeout, store unreachable). Surfaces the silently-broken-detector failure mode — operators alert on any non-zero rate per detector.",
			},
			[]string{LabelDetector},
		),

		SigningKeyRotationsTotal: factory.NewCounter(
			prometheus.CounterOpts{
				Name: NameSigningKeyRotationsTotal,
				Help: "Automatic signing-key rotations performed. Alert if it stops advancing while rotation is enabled (loop wedged) — RPs would keep verifying against an aging key.",
			},
		),

		FAPIViolationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameFAPIViolationsTotal,
				Help: "FAPI 2.0 baseline rule violations. Labels: rule (fapi:par_required/signed_request/pkce_s256/no_implicit/sender_constrained), mode (inspection/enforce). In inspection mode, graph rate() by rule to find non-compliant RPs before flipping to enforce.",
			},
			[]string{LabelFAPIRule, LabelFAPIMode},
		),

		SigningOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameSigningOperationsTotal,
				Help: "External (KMS/HSM) signing operations. Labels: alg (eddsa/es256/rs256/ps256), outcome (success/error). A rising error rate signals KMS outage or throttling; token issuance fails closed when signing errors. Zero when no external signer is wired.",
			},
			[]string{LabelAlg, LabelOutcome},
		),

		SigningDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    NameSigningDuration,
				Help:    "External (KMS/HSM) signing round-trip latency in seconds, labeled by alg. DefBuckets (.005s-10s) cover the typical 5-50ms KMS RTT plus tail; alert on a p99 that threatens token-issuance latency.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{LabelAlg},
		),

		SigningBackendUp: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: NameSigningBackendUp,
				Help: "External (KMS/HSM) signing backend health: 1 if the last signing operation succeeded, 0 after a failure. Labeled by alg. Alert on 0 — it fires before /readyz drains the replica. Never set when no external signer is wired.",
			},
			[]string{LabelAlg},
		),

		SigningKeyAdoptionErrorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameSigningKeyAdoptionErrorsTotal,
				Help: "Peer signing-key adoptions that failed in the leaderless aggregation loop, by reason (decode/adopt). decode = malformed/off-curve/weak peer JWK; adopt = decoded but every matching-alg issuer rejected it (e.g. kid collision). Fail-open (key skipped); a rising rate surfaces a peer publishing bad keys before it manifests as unknown-kid validation failures. Zero when no signing-key registry is wired.",
			},
			[]string{LabelReason},
		),

		CIBAPingTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameCIBAPingTotal,
				Help: "CIBA ping-delivery attempts from the detached post-resolution notifier goroutine, by outcome (success/error). An error (notifier returned an error or panicked) degrades the client to poll; alert on a rising error series with no successes (notification endpoint wedged/unreachable). Zero traffic when no CIBAPingNotifier is wired.",
			},
			[]string{LabelOutcome},
		),

		SigningKeyAggregationUp: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: NameSigningKeyAggregationUp,
				Help: "Leaderless signing-key aggregation subscription health: 1 while this replica is subscribed and adopting peers' keys, 0 while degraded (registry Subscribe channel closed, loop retrying). Degraded means the replica stops adopting peers' newly-rotated keys while local signing still succeeds — alert on 0. Never set when no signing-key registry is wired.",
			},
		),

		SigningKeyCutoverTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameSigningKeyCutoverTotal,
				Help: "Deadline-coordinated signing-key rotation cutovers this replica enacted on a received cross-replica rotation Event, by outcome (deferred/extended/adopted_only/noop). The feature defers a demoted kid's retirement to a cluster-coordinated deadline so a rolling deploy can't strand a token under an early-retired kid (unknown-kid 401). A rising noop series means peers send garbage/superseded Events (fail-safe absorbs them). Zero when coordinated rotation isn't armed.",
			},
			[]string{LabelOutcome},
		),

		InvalidationBusUp: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: NameInvalidationBusUp,
				Help: "Cross-replica invalidation-bus subscription health: 1 while this replica is subscribed and applying invalidations, 0 while degraded (bus Subscribe channel closed under a live context, loop retrying). Degraded means the replica stops applying cross-replica invalidations (tenant suspension, client-cache, coordinated key rotation, token revocation) until it resubscribes — alert on 0. Never set when no invalidation bus is wired.",
			},
		),

		InvalidationBusReconnectsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameInvalidationBusReconnectsTotal,
				Help: "Cross-replica invalidation-bus subscription transitions, by reason (degraded/reconnected). degraded = the Subscribe channel closed under a live context and the loop flipped degraded (missing invalidations); reconnected = a degraded loop resubscribed and resumed. Alert on a rising degraded series without matching reconnected ticks (bus backend flapping/down). Zero traffic when no invalidation bus is wired.",
			},
			[]string{LabelReason},
		),

		NetPolicyClassifierUp: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: NameNetPolicyClassifierUp,
				Help: "Network-policy Classifier Watch subscription health: 1 while this replica is subscribed and applying policy updates, 0 while degraded (Store.Watch channel closed under a live context, loop retrying). Degraded means the Classifier keeps serving its last snapshot (fail-open) but stops picking up policy edits until it resubscribes — alert on 0. Never set when no network-policy store is wired.",
			},
		),

		NetPolicyClassifierReconnectsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameNetPolicyClassifierReconnectsTotal,
				Help: "Network-policy Classifier Watch subscription transitions, by reason (degraded/reconnected). degraded = the Watch channel closed under a live context and the loop flipped degraded (serving a frozen snapshot); reconnected = a degraded loop resubscribed, re-listed, and resumed. Alert on a rising degraded series without matching reconnected ticks (policy backend flapping/down). Zero traffic when no network-policy store is wired.",
			},
			[]string{LabelReason},
		),

		CAEPSetsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameCAEPSetsTotal,
				Help: "OpenID Shared Signals (CAEP/RISC) Security Event Token push attempts from the detached transmitter goroutine, by outcome (success/failed/dropped). A failed/dropped SET means an affected RP missed a real-time revocation signal; alert on a rising failed/dropped series. Zero traffic when no CAEP transmitter is wired.",
			},
			[]string{LabelOutcome},
		),

		SSFSetsReceivedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameSSFSetsReceivedTotal,
				Help: "Inbound OpenID Shared Signals (CAEP/SSF) Security Event Tokens processed by the receiver, by outcome (revoked/noop/rejected). `rejected` is a SET that failed validation (bad signature/untrusted iss/wrong aud/expired/replayed/malformed) — a rising series can mean a misconfigured upstream or a forged/replayed-SET probe; `revoked` drove a local revocation; `noop` mapped to no local subject or only unknown events. Zero traffic when no CAEP receiver is wired.",
			},
			[]string{LabelOutcome},
		),

		RefreshRotationVelocityExceededTotal: factory.NewCounter(
			prometheus.CounterOpts{
				Name: NameRefreshRotationVelocityExceededTotal,
				Help: "Refresh-token families revoked by the per-family rotation-velocity cap (a family rotated faster than the configured per-window limit). No labels (a familyID/user/client label would be unbounded). The wire response stays the generic invalid_grant, so this counter plus the refresh_rotation_velocity_exceeded audit event are the only operator visibility. Zero traffic when no rotation limiter is wired.",
			},
		),

		TokenRevocationsPropagatedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameTokenRevocationsPropagatedTotal,
				Help: "Cross-replica access-token revocation propagation events, by direction (published/adopted). published = this replica broadcast a token-revoked Event after a local /token/revoke; adopted = this replica added a peer-published revoked token to its own in-process deny-set. No token/jti label (bounded cardinality). Purely additive + best-effort. Zero traffic when cross-replica revocation isn't armed.",
			},
			[]string{LabelDirection},
		),
	}
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
