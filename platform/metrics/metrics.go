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

import "github.com/prometheus/client_golang/prometheus"

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

	// Zero-trust conditional-access decisions (zero traffic when
	// WithConditionalAccess isn't wired). Bounded {action} ∈ {allow, deny,
	// require_step_up} — the resolved CAP verdict, never a per-policy or
	// per-subject label (§5).
	ConditionalAccessDecisionsTotal *prometheus.CounterVec // labels: action

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

	// Token-usage telemetry (zero traffic when no TokenUsageRecorder is
	// wired). OPT-IN via EnableTokenUsageMetrics — without both a recorder
	// AND a metrics registry the vectors stay nil and nothing is registered
	// or emitted (byte-identical off, mirrors EnableTenantMetrics).
	// EventsTotal counts events successfully aggregated, by kind
	// (access/refresh/id) + endpoint (token/introspect/userinfo) — both
	// bounded (§5); no client/subject label. DroppedTotal counts events
	// shed by the recorder's bounded queue (load-shedding — non-zero means
	// issuance traffic outpaces the drain). TrackedBuckets gauges the
	// store's current bucket cardinality so operators see a bounded store
	// approach its eviction cap before history silently rolls off.
	TokenUsageEventsTotal    *prometheus.CounterVec // labels: kind, endpoint
	TokenUsageDroppedTotal   prometheus.Counter     // no labels
	TokenUsageTrackedBuckets prometheus.Gauge       // no labels

	// Signup funnel — self-service registration conversion pipeline.
	// outcome ∈ {success, failure} (bounded). Zero traffic when signup
	// is not enabled.
	SignupStartedTotal          *prometheus.CounterVec // labels: outcome
	SignupVerifiedTotal         *prometheus.CounterVec // labels: outcome
	SignupCompletedTotal        *prometheus.CounterVec // labels: outcome
	PasswordResetRequestedTotal *prometheus.CounterVec // labels: outcome
	PasswordResetCompletedTotal *prometheus.CounterVec // labels: outcome

	// FeatureGateEnabled is a startup-set gauge — 1 while a protocol
	// surface's routes are mounted, 0 while it was explicitly disabled via
	// feature_gates. Labeled by feature (bounded: the fixed gate set).
	// Attack-surface changes are security-relevant, so operators can graph
	// "which surfaces are exposed on this replica" without diffing config
	// files across a fleet. Set once per gate at NewServer() time — gates
	// are not runtime-mutable, so this never changes after boot.
	FeatureGateEnabled *prometheus.GaugeVec // labels: feature

	// Credential-rotation framework (platform/rotation Scheduler). Zero
	// traffic when no Scheduler is running. See credential_rotation.go for
	// the label/outcome vocabulary and the nil-safe observe helpers.
	CredentialRotationsTotal *prometheus.CounterVec // labels: credential_type, outcome
	CredentialAgeSeconds     *prometheus.GaugeVec   // labels: credential_type

	// ConfigDriftDetectedTotal counts cross-replica configuration-drift
	// detections (platform/configaudit.DriftDetector): this replica's
	// running-config digest disagreed with a peer's broadcast digest. No
	// labels — a per-peer-replica-id label would be unbounded (§5) and the
	// paired config_drift_detected audit event already carries the peer id
	// for investigation. Report-only: a rising count means SOME replica's
	// effective config has diverged, never a blocked request. Zero traffic
	// when drift detection isn't armed (WithConfigDriftDetection).
	ConfigDriftDetectedTotal prometheus.Counter

	// Token-policy engine (opt-in via WithTokenPolicy + WithMetrics). Zero
	// traffic when no policy store is wired — OPT-IN via
	// EnableTokenPolicyMetrics, so without both a store AND metrics the
	// vectors stay nil and nothing is registered or emitted (byte-identical
	// off, §5). EvaluationsTotal counts every policy gate evaluation by
	// decision (allow/deny); DenialsTotal breaks the deny subset down by
	// reason (the closed tokenpolicy.DenyReason set) — both bounded, no
	// client/subject/scope label. See token_policy.go (folded into
	// metrics_token.go) for the observe helpers.
	TokenPolicyEvaluationsTotal *prometheus.CounterVec // labels: decision
	TokenPolicyDenialsTotal     *prometheus.CounterVec // labels: reason
	// TokenPolicyRenewRequiredTotal counts access-token introspections reported
	// inactive because the token passed its require_renew fraction of TTL — a
	// governance signal (force-refresh), NOT an issuance denial, so it is its
	// own unlabeled counter rather than a DenyReason on DenialsTotal.
	TokenPolicyRenewRequiredTotal prometheus.Counter

	// Disaster-recovery degraded-service posture (zero traffic when no
	// DegradationManager is wired). DegradationMode is a state gauge: the active
	// mode's series reads 1 and every other mode reads 0, so operators alert on
	// `sso_degradation_mode{mode="normal"} == 0` (the replica left normal
	// service). DegradedRejectionsTotal counts requests the gate refused, by
	// mode + method (both bounded) — a rising series is the direct measure of
	// how much traffic the current posture is shedding.
	DegradationMode         *prometheus.GaugeVec   // labels: mode
	DegradedRejectionsTotal *prometheus.CounterVec // labels: mode, method
}

// SetFeatureGateEnabled records the boot-time state of one FeatureGates
// surface. Nil-safe so the Server can call it unconditionally whether or
// not metrics are wired.
func (m *Metrics) SetFeatureGateEnabled(feature string, enabled bool) {
	if m == nil || m.FeatureGateEnabled == nil {
		return
	}
	v := 0.0
	if enabled {
		v = 1
	}
	m.FeatureGateEnabled.WithLabelValues(feature).Set(v)
}

// ObserveConditionalAccessDecision bumps the zero-trust CAP decision counter for
// the resolved action ("allow" / "deny" / "require_step_up"). Nil-safe so the
// server can fire it unconditionally whether or not metrics or the CAP engine
// are wired. action is a bounded 3-value dimension (§5) — never a per-policy or
// per-subject label.
func (m *Metrics) ObserveConditionalAccessDecision(action string) {
	if m == nil || m.ConditionalAccessDecisionsTotal == nil {
		return
	}
	m.ConditionalAccessDecisionsTotal.WithLabelValues(action).Inc()
}
