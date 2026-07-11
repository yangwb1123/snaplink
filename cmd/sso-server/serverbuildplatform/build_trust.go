package serverbuildplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/trust"
)

// anomalyOutcomeSuccess mirrors the anomaly.LoginEntry.Outcome vocabulary
// ("success"/"failure" — same wire strings sso_login_attempts_total uses);
// the anomaly package deliberately keeps them as documented literals rather
// than exported consts.
const anomalyOutcomeSuccess = "success"

// AnomalyIPFailureLookup adapts anomaly.IPFailureCounter — the IP-keyed
// brute-force counter the BruteForceShadowDetector writes into — to the
// trust.IPFailureLookup seam the IP-reputation scorer reads. shared/trust
// must not import domains/anomaly (dependency direction), so the bridge
// lives here at the composition root. Reads re-apply the deployment ipSalt
// via the counter's public hashing contract — 16 hex chars = 64-bit
// truncation of sha256(salt || ip), the same scheme detectors.hashIPForBF /
// defaulttoken.HashLoginEntry write with — so both subsystems address the
// same hash space; a mismatched salt would silently count nothing.
type AnomalyIPFailureLookup struct {
	counter anomaly.IPFailureCounter
	ipSalt  []byte
}

// NewAnomalyIPFailureLookup wraps counter with the SAME deployment ipSalt
// buildAnomaly handed the detectors (anomaly.ip_salt, decoded).
func NewAnomalyIPFailureLookup(counter anomaly.IPFailureCounter, ipSalt []byte) *AnomalyIPFailureLookup {
	return &AnomalyIPFailureLookup{counter: counter, ipSalt: append([]byte(nil), ipSalt...)}
}

// CountFailures implements trust.IPFailureLookup.
func (l *AnomalyIPFailureLookup) CountFailures(ctx context.Context, ip string, since time.Time) (int, int, error) {
	if ip == "" {
		// Mirrors the detector's write path: anonymous-IP failures are never
		// recorded, so there is nothing to count.
		return 0, 0, nil
	}
	h := sha256.New()
	h.Write(l.ipSalt)
	h.Write([]byte(ip))
	sum := h.Sum(nil)
	return l.counter.Count(ctx, hex.EncodeToString(sum[:8]), since)
}

var _ trust.IPFailureLookup = (*AnomalyIPFailureLookup)(nil)

// AnomalyLoginHistory adapts anomaly.RecentLoginStore — the per-subject
// login history the behavioral detectors baseline against — to the
// trust.LoginHistoryLookup seam the behavior scorer reads. Same
// composition-root bridging rationale as AnomalyIPFailureLookup.
type AnomalyLoginHistory struct {
	store anomaly.RecentLoginStore
}

// NewAnomalyLoginHistory wraps store.
func NewAnomalyLoginHistory(store anomaly.RecentLoginStore) *AnomalyLoginHistory {
	return &AnomalyLoginHistory{store: store}
}

// History implements trust.LoginHistoryLookup. Failures are filtered AFTER
// the bounded Recent read, so a failure-heavy window can yield fewer than
// limit timestamps — acceptable for the scorer's hour-of-day baseline (less
// history means weaker signal, never an error).
func (l *AnomalyLoginHistory) History(ctx context.Context, subjectID string, limit int) ([]time.Time, error) {
	entries, err := l.store.Recent(ctx, subjectID, time.Time{}, limit)
	if err != nil {
		return nil, err
	}
	var out []time.Time
	for _, e := range entries {
		if e != nil && e.Outcome == anomalyOutcomeSuccess {
			out = append(out, e.Timestamp)
		}
	}
	return out, nil
}

var _ trust.LoginHistoryLookup = (*AnomalyLoginHistory)(nil)

// BuildTrustScorer assembles the weighted composite trust scorer backing
// sso.WithTrustScorer when trust.enabled: each key in trust.weights enables
// that reference scorer with its relative weight (a missing key excludes the
// scorer). ipLookup / history are the (possibly nil) anomaly-backed adapters
// above — nil leaves the corresponding scorer on its documented no-signal
// cold-start score, fail-open. m non-nil registers the sso_trust_score /
// sso_trust_scorer_errors_total collectors on the shared registry.
//
// Returns (nil, nil) when disabled — byte-identical to a build without it.
func BuildTrustScorer(cfg config.TrustConfig, ipLookup trust.IPFailureLookup, history trust.LoginHistoryLookup, m *metrics.Metrics) (trust.TrustScorer, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if len(cfg.Weights) == 0 {
		return nil, errors.New("trust.weights must name at least one scorer when trust.enabled")
	}
	weights, err := trustScorerWeights(cfg, ipLookup, history)
	if err != nil {
		return nil, err
	}
	var tm *trust.Metrics
	if m != nil {
		tm = trust.NewMetrics(m.Registry)
	}
	return trust.NewWeightedComposite(weights, tm), nil
}

// trustScorerWeights maps trust.weights onto the four reference scorers,
// keyed by each scorer's stable Name() so config keys and code cannot drift.
// A weight <= 0 or an unknown key fails loud at boot — a typo'd scorer name
// silently dropping a signal is exactly the dead-config failure mode this
// wiring exists to close.
func trustScorerWeights(cfg config.TrustConfig, ipLookup trust.IPFailureLookup, history trust.LoginHistoryLookup) ([]trust.ScorerWeight, error) {
	available := []trust.ScorerWeight{
		{Scorer: trust.NewGeoRiskScorer(cfg.Geo.TrustedCountries, cfg.Geo.DeniedCountries)},
		{Scorer: &trust.IPReputationScorer{
			Lookup:                   ipLookup,
			Window:                   cfg.IPReputation.Window,
			FailureThreshold:         cfg.IPReputation.FailureThreshold,
			DistinctSubjectThreshold: cfg.IPReputation.DistinctSubjectThreshold,
		}, FloorOnError: cfg.IPReputation.FloorOnError},
		{Scorer: &trust.BehaviorScorer{
			History:      history,
			HistoryLimit: cfg.Behavior.HistoryLimit,
		}, FloorOnError: cfg.Behavior.FloorOnError},
		{Scorer: trust.NewDevicePostureScorer(cfg.DevicePosture.DefaultScore)},
	}
	known := make(map[string]bool, len(available))
	var weights []trust.ScorerWeight
	for _, sw := range available {
		name := sw.Scorer.Name()
		known[name] = true
		w, ok := cfg.Weights[name]
		if !ok {
			continue
		}
		if w <= 0 {
			return nil, fmt.Errorf("trust.weights.%s: weight must be > 0, got %v", name, w)
		}
		sw.Weight = w
		weights = append(weights, sw)
	}
	for name := range cfg.Weights {
		if !known[name] {
			return nil, fmt.Errorf("trust.weights: unknown scorer %q (available: geo_risk, ip_reputation, behavior, device_posture)", name)
		}
	}
	return weights, nil
}
