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

func registerCredentialRotationMetrics(factory promauto.Factory, m *Metrics) {
	m.CredentialRotationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameCredentialRotationsTotal,
			Help: "Credential rotation attempts driven by the platform/rotation Scheduler, by credential_type and outcome (success/failure). A rotation failure is NOT fatal — the previous credential keeps serving and the scheduler retries with backoff — so alert on a SUSTAINED failure rate (repeated failures for one credential_type), not a single blip. Zero traffic when no rotation.Scheduler is running.",
		},
		[]string{LabelCredentialType, LabelOutcome},
	)

	m.CredentialAgeSeconds = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: NameCredentialAgeSeconds,
			Help: "Age in seconds of the ACTIVE version of each credential type registered with the platform/rotation Scheduler, refreshed every scheduler tick. Alert on an age that has grown well past the credential's configured rotation interval — it means the scheduler is wedged or repeatedly failing to rotate that class. Zero traffic when no rotation.Scheduler is running.",
		},
		[]string{LabelCredentialType},
	)
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
