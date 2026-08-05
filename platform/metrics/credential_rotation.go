package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Credential-rotation metric names (platform/rotation Scheduler). Kept in a
// dedicated file — like audit_async.go — rather than folded into consts.go /
// metrics_ctor.go, both of which are near the per-file line budget.
const (
	NameCredentialRotationsTotal = "sso_credential_rotations_total"
	NameCredentialAgeSeconds     = "sso_credential_age_seconds"
)

// LabelCredentialType is the bounded credential-class dimension: the
// corecredential.CredentialType vocabulary is closed (one constant per
// subsystem that registers a rotator), so this never grows unbounded.
const LabelCredentialType = "credential_type"

// Outcome label values for a rotation ATTEMPT, bounded to two (§5). Distinct
// from the generic LabelOutcome/"success"|"failure" string literals used
// elsewhere so platform/rotation can reference them as named constants rather
// than duplicating the literal.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Client-secret expiry warning metrics (platform/lifecycle/rotation
// client_secret_scan.go). The consumer is the operations team: a client
// secret that expires is a sudden-death production outage for machine
// identities, so the scanner emits one counter per warning window
// (30/14/7 days) instead of only the final day.
const (
	NameClientSecretsExpiringTotal = "sso_client_secrets_expiring_total"
	LabelWindow                    = "window"
)

func registerCredentialRotationMetrics(factory promauto.Factory, m *Metrics) {
	m.CredentialRotationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameCredentialRotationsTotal,
			Help: "Credential rotation attempts driven by the platform/rotation Scheduler, by credential_type and outcome (success/failure). A rotation failure is NOT fatal — the previous credential keeps serving and the scheduler retries with backoff — so alert on a SUSTAINED failure rate (repeated failures for one credential_type), not a single blip. Zero traffic when no rotation.Scheduler is running.",
		},
		[]string{LabelCredentialType, LabelOutcome},
	)

	m.ClientSecretsExpiringTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameClientSecretsExpiringTotal,
			Help: "Clients whose secret_expires_at landed inside an expiry warning window, by window. Emitted once per client per window per day by the client-secret expiry scanner; alert on ANY sustained positive rate — every increment is a machine identity at risk of sudden-death expiry. Zero traffic when the scanner is not wired.",
		},
		[]string{LabelWindow},
	)

	m.CredentialAgeSeconds = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: NameCredentialAgeSeconds,
			Help: "Age in seconds of the ACTIVE version of each credential type registered with the platform/rotation Scheduler, refreshed every scheduler tick. Alert on an age that has grown well past the credential's configured rotation interval — it means the scheduler is wedged or repeatedly failing to rotate that class. Zero traffic when no rotation.Scheduler is running.",
		},
		[]string{LabelCredentialType},
	)
}

// ObserveClientSecretExpiring bumps the warning counter for window.
// Nil-safe so the scanner can call it unconditionally.
func (m *Metrics) ObserveClientSecretExpiring(window string) {
	if m == nil || m.ClientSecretsExpiringTotal == nil {
		return
	}
	m.ClientSecretsExpiringTotal.WithLabelValues(window).Inc()
}

// ObserveCredentialRotation bumps the rotation-attempt counter for credType +
// outcome (OutcomeSuccess/OutcomeFailure). Nil-safe so the scheduler can call
// it unconditionally whether or not metrics are wired.
func (m *Metrics) ObserveCredentialRotation(credType, outcome string) {
	if m == nil || m.CredentialRotationsTotal == nil {
		return
	}
	m.CredentialRotationsTotal.WithLabelValues(credType, outcome).Inc()
}

// SetCredentialAge publishes the active version's current age for credType.
// Nil-safe; called once per scheduler tick for every registered class.
func (m *Metrics) SetCredentialAge(credType string, seconds float64) {
	if m == nil || m.CredentialAgeSeconds == nil {
		return
	}
	m.CredentialAgeSeconds.WithLabelValues(credType).Set(seconds)
}

// registerSigningKeyHygieneMetrics registers the peer-adopted-verify-key
// prune counter + verify-set-size gauge (interfaces/sso PruneVerifyKeys) and
// the per-issuer signing-usage counter. Kept here — beside the credential
// rotation metrics it complements — rather than in metrics_ctor.go, which is
// near its per-file line budget.
func registerSigningKeyHygieneMetrics(factory promauto.Factory, m *Metrics) {
	m.SigningKeyPrunedTotal = factory.NewCounter(
		prometheus.CounterOpts{
			Name: NameSigningKeyPrunedTotal,
			Help: "Peer-adopted verify-only signing keys removed by a PruneVerifyKeys hygiene sweep because their announcing replica hadn't been reconciled within the retention window. A safety net for a missed/lost peer-removal event, distinct from the per-announcement set-diff reconciliation that already runs on every registry update. Zero traffic when no signing-key registry is wired.",
		},
	)

	m.SigningVerifyKeysTotal = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: NameSigningVerifyKeySetSize,
			Help: "Current size of the peer-adopted verify-only key set (the leaderless signing-key aggregation's memory footprint), refreshed on every adopt/drop/prune. Zero/unset when no signing-key registry is wired.",
		},
	)

	m.SigningUsageTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameSigningUsageTotal,
			Help: "In-process JWT signing operations by alg + kid. Distinct from sso_signing_operations_total (external KMS/HSM round-trips only); watch usage shift from an old kid to a new one right after a RotateKey call as evidence the cutover took effect. Zero traffic unless an issuer's WithXMetrics option wires this in.",
		},
		[]string{LabelAlg, LabelKid},
	)
}

// ObserveSigningKeyPruned adds n to the signing-key prune counter. Nil-safe;
// n == 0 is a no-op (no-op sweeps don't need to touch the series).
func (m *Metrics) ObserveSigningKeyPruned(n int) {
	if m == nil || m.SigningKeyPrunedTotal == nil || n <= 0 {
		return
	}
	m.SigningKeyPrunedTotal.Add(float64(n))
}

// SetSigningVerifyKeys publishes the peer-adopted verify-set's current size.
// Nil-safe; called after every adopt/drop/prune that changes it.
func (m *Metrics) SetSigningVerifyKeys(n int) {
	if m == nil || m.SigningVerifyKeysTotal == nil {
		return
	}
	m.SigningVerifyKeysTotal.Set(float64(n))
}

// ObserveSigningUsage bumps the per-(alg,kid) signing-usage counter. Nil-safe
// so an issuer can call it unconditionally whether or not WithXMetrics wired
// a Metrics in.
func (m *Metrics) ObserveSigningUsage(alg, kid string) {
	if m == nil || m.SigningUsageTotal == nil {
		return
	}
	m.SigningUsageTotal.WithLabelValues(alg, kid).Inc()
}
