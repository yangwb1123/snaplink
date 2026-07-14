package clienttrust

import (
	"context"
	"time"

	"github.com/snaplink/sso/shared/trust"
)

// Reference tuning + scores for ClientTrustScorer. Exported where a caller
// plausibly wants to reference the same default the zero-value scorer uses
// (mirrors shared/trust's DefaultBehaviorHistoryLimit / DefaultIPReputationWindow
// naming convention).
const (
	// ColdStartScore is returned for a client with NO recorded activity at
	// all — neutral, never 0.0 (which would read as "actively distrusted").
	ColdStartScore = 0.5

	// DefaultWindow bounds how far back Summarize looks for the rule
	// counters below.
	DefaultWindow = 30 * 24 * time.Hour

	// DefaultFailureRateThreshold: an auth failure rate at or above this
	// (over DefaultFailureMinSample+ attempts) penalizes the score.
	DefaultFailureRateThreshold = 0.5
	// DefaultFailureMinSample is the minimum (success+failure) sample size
	// before the failure rate is considered meaningful — a single failed
	// attempt out of one must not look like a 100% failure rate.
	DefaultFailureMinSample = 5
	// DefaultRotationFrequencyThreshold: this many (or more) secret
	// rotations inside the window is unusually frequent for legitimate
	// operator/scheduled rotation cadences.
	DefaultRotationFrequencyThreshold = 3
	// DefaultScopeAnomalyThreshold: this many (or more) flagged scope
	// anomalies inside the window penalizes the score.
	DefaultScopeAnomalyThreshold = 1

	// Rule penalty weights. Sum (1.0) is the worst-case raw penalty before
	// decay/clamping — a client tripping every rule scores 0.0 pre-decay.
	failureRatePenalty       = 0.4
	rotationFrequencyPenalty = 0.3
	scopeAnomalyPenalty      = 0.3
)

// ClientTrustScorer implements trust.TrustScorer for OAuth clients: Score
// consults a ClientActivityStore for a rule-based verdict (failure-rate,
// rotation-frequency, scope-anomaly counters) and reuses shared/trust's
// DecayValue so an old strike recovers toward a clean score over time
// instead of haunting the client forever.
//
// It implements the SAME trust.TrustScorer interface the user/session
// scorers (behavior/ip_reputation/geo/device_posture) do, rather than
// inventing a parallel scoring interface: trust.TrustSignals already
// carries ClientID and Time — exactly what this scorer needs — so the
// interfaces are naturally compatible, and a future composite could combine
// client- and user-level signals without a redesign. Compare
// shared/trust.BehaviorScorer/IPReputationScorer, which ignore most
// TrustSignals fields too; this scorer ignores RemoteIP/Geo/UserID/AMR/ACR/
// DeviceHints and reads only ClientID + Time.
type ClientTrustScorer struct {
	Activity ClientActivityStore

	// Window bounds how far back Summarize looks. Zero uses DefaultWindow.
	Window time.Duration

	// Decay is the recovery curve applied to the raw rule penalty, anchored
	// at the most recent negative event (ClientActivitySummary.
	// LastNegativeAt) — the FRESHER the last strike, the LESS decay has
	// happened (full penalty); the OLDER it is, the more the penalty has
	// decayed (recovering score) even when the historical strike count is
	// high. The zero value (trust.DecayConfig{}) disables decay — the raw
	// penalty applies unchanged, matching the feature-off contract every
	// other DecayConfig consumer follows.
	Decay trust.DecayConfig

	// FailureRateThreshold / FailureMinSample / RotationFrequencyThreshold /
	// ScopeAnomalyThreshold override the package Default* constants. Zero
	// (or, for the float, <= 0) uses the default.
	FailureRateThreshold       float64
	FailureMinSample           int
	RotationFrequencyThreshold int
	ScopeAnomalyThreshold      int
}

// Name implements trust.TrustScorer.
func (s *ClientTrustScorer) Name() string { return "client_activity" }

// Score implements trust.TrustScorer. It returns an error ONLY when
// Activity.Summarize itself errors — a missing Activity, an empty
// signals.ClientID, or a client with no recorded history are all cold-start/
// no-signal cases, never failures (mirrors BehaviorScorer/IPReputationScorer).
func (s *ClientTrustScorer) Score(ctx context.Context, signals trust.TrustSignals) (trust.TrustScore, error) {
	if s.Activity == nil || signals.ClientID == "" {
		return trust.TrustScore{Value: ColdStartScore, Reasons: []string{"client_activity:no_signal"}}, nil
	}
	now := signals.Time
	if now.IsZero() {
		now = time.Now()
	}
	sum, err := s.Activity.Summarize(ctx, signals.ClientID, now.Add(-s.window()))
	if err != nil {
		return trust.TrustScore{}, err
	}
	if !sum.HasHistory {
		return trust.TrustScore{Value: ColdStartScore, Reasons: []string{"client_activity:cold_start"}}, nil
	}
	penalty, reasons := s.rulePenalty(sum)
	penalty = trust.ClampScore(penalty)
	if s.Decay.Enabled() && !sum.LastNegativeAt.IsZero() {
		penalty = trust.DecayValue(penalty, sum.LastNegativeAt, now, s.Decay)
	}
	if len(reasons) == 0 {
		reasons = []string{"client_activity:clean"}
	}
	return trust.TrustScore{Value: trust.ClampScore(1 - penalty), Reasons: reasons}, nil
}

// rulePenalty evaluates every rule-counter threshold against sum, returning
// the summed raw penalty (pre-decay, pre-clamp) and the short-code reasons
// trail for whichever rules tripped. Split out of Score to keep both under
// the function-length/complexity budget.
func (s *ClientTrustScorer) rulePenalty(sum ClientActivitySummary) (float64, []string) {
	var penalty float64
	var reasons []string
	if total := sum.AuthFailure + sum.AuthSuccess; total >= s.failureMinSample() {
		rate := float64(sum.AuthFailure) / float64(total)
		if rate >= s.failureRateThreshold() {
			penalty += failureRatePenalty
			reasons = append(reasons, "client_activity:high_failure_rate")
		}
	}
	if sum.SecretRotations >= s.rotationThreshold() {
		penalty += rotationFrequencyPenalty
		reasons = append(reasons, "client_activity:frequent_rotation")
	}
	if sum.ScopeAnomalies >= s.scopeAnomalyThreshold() {
		penalty += scopeAnomalyPenalty
		reasons = append(reasons, "client_activity:scope_anomaly")
	}
	return penalty, reasons
}

func (s *ClientTrustScorer) window() time.Duration {
	if s.Window > 0 {
		return s.Window
	}
	return DefaultWindow
}

func (s *ClientTrustScorer) failureRateThreshold() float64 {
	if s.FailureRateThreshold > 0 {
		return s.FailureRateThreshold
	}
	return DefaultFailureRateThreshold
}

func (s *ClientTrustScorer) failureMinSample() int {
	if s.FailureMinSample > 0 {
		return s.FailureMinSample
	}
	return DefaultFailureMinSample
}

func (s *ClientTrustScorer) rotationThreshold() int {
	if s.RotationFrequencyThreshold > 0 {
		return s.RotationFrequencyThreshold
	}
	return DefaultRotationFrequencyThreshold
}

func (s *ClientTrustScorer) scopeAnomalyThreshold() int {
	if s.ScopeAnomalyThreshold > 0 {
		return s.ScopeAnomalyThreshold
	}
	return DefaultScopeAnomalyThreshold
}

var _ trust.TrustScorer = (*ClientTrustScorer)(nil)
