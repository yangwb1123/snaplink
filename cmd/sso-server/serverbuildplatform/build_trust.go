package serverbuildplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/trust"
)

// BuildTrustScorer assembles the Zero Trust Framework Phase 1 composite trust
// scorer (trust.enabled) backing sso.WithTrustScorer: a trust.WeightedComposite
// over whichever reference scorers cfg.Weights names (geo_risk / ip_reputation
// / behavior / device_posture), each configured from its own cfg.<Scorer>
// section. The result is ADVISORY-only — the conditional-access engine only
// ever consults it at /auth/login when ALSO wired with Enforce=true (see
// docs/config-reference.md's "Trust Scoring" + "Conditional Access" sections);
// wiring this alone changes no live auth decision.
//
// ip_reputation and behavior are the two scorers that need a data source
// beyond the request-time signals. ipFailureCounter / recentLoginStore are the
// SAME domains/anomaly stores the anomaly.Runner detectors (brute-force-shadow
// / new-device / impossible-travel) already populate — nil when
// anomaly.enabled=false, or when that particular sub-store wasn't opened. The
// composition-root adapters below (trustIPFailureAdapter /
// trustLoginHistoryAdapter) translate the narrow shared/trust lookup
// interfaces onto them, hashing the caller's IP with the exact same salted
// scheme (sha256(salt||ip), truncated to 16 hex chars) the anomaly detectors
// use (infrastructure/defaultimpl/defaulttoken's hashIP /
// infrastructure/defaultimpl/detectors' hashIPForBF) so ip_reputation reads
// the exact rows those detectors already wrote — one shared IP-hash space,
// not a second one. shared/trust itself must never import domains/anomaly
// (see its package doc / architecture_layer_test.go), so this composition-time
// bridge lives here, at the cmd composition root, instead. A nil store
// degrades that one scorer to its cold-start "no_signal" value (see
// trust.IPReputationScorer / trust.BehaviorScorer) — never an error.
//
// Returns (nil, nil) when !cfg.Enabled — byte-identical to a build without the
// feature. Fails loud when cfg.Enabled with an empty Weights map (nothing to
// score), an unknown scorer name, or a weight <= 0.
func BuildTrustScorer(
	cfg config.TrustConfig,
	ipFailureCounter anomaly.IPFailureCounter,
	recentLoginStore anomaly.RecentLoginStore,
	ipSalt []byte,
	m *metrics.Metrics,
) (trust.TrustScorer, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if len(cfg.Weights) == 0 {
		return nil, errors.New("trust.weights: at least one scorer weight required when trust.enabled")
	}
	weights, err := buildTrustWeights(cfg, ipFailureCounter, recentLoginStore, ipSalt)
	if err != nil {
		return nil, err
	}
	var trustMetrics *trust.Metrics
	if m != nil {
		// Shares the SAME registry every other opt-in SDK metric binds to
		// (mirrors trust.Metrics' own doc: a nil *Metrics is zero-overhead, so
		// this only activates when metrics.enabled).
		trustMetrics = trust.NewMetrics(m.Registry)
	}
	return trust.NewWeightedComposite(weights, trustMetrics), nil
}

// buildTrustWeights translates cfg.Weights into the composite's
// []trust.ScorerWeight, constructing each named reference scorer from its own
// cfg section. Keys are sorted so a boot-time validation error names a
// deterministic first offender across runs.
func buildTrustWeights(
	cfg config.TrustConfig,
	ipFailureCounter anomaly.IPFailureCounter,
	recentLoginStore anomaly.RecentLoginStore,
	ipSalt []byte,
) ([]trust.ScorerWeight, error) {
	names := make([]string, 0, len(cfg.Weights))
	for name := range cfg.Weights {
		names = append(names, name)
	}
	sort.Strings(names)

	ipLookup := newTrustIPFailureLookup(ipFailureCounter, ipSalt)
	historyLookup := newTrustLoginHistoryLookup(recentLoginStore)

	out := make([]trust.ScorerWeight, 0, len(names))
	for _, name := range names {
		weight := cfg.Weights[name]
		if weight <= 0 {
			return nil, fmt.Errorf("trust.weights[%s]: weight must be > 0", name)
		}
		sw, err := buildOneTrustScorer(name, weight, cfg, ipLookup, historyLookup)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, nil
}

// buildOneTrustScorer constructs the named reference scorer + its
// FloorOnError. An unrecognized name fails loud at boot rather than silently
// dropping a misconfigured weights entry.
func buildOneTrustScorer(
	name string,
	weight float64,
	cfg config.TrustConfig,
	ipLookup trust.IPFailureLookup,
	historyLookup trust.LoginHistoryLookup,
) (trust.ScorerWeight, error) {
	switch name {
	case "geo_risk":
		return trust.ScorerWeight{
			Scorer: trust.NewGeoRiskScorer(cfg.Geo.TrustedCountries, cfg.Geo.DeniedCountries),
			Weight: weight,
		}, nil
	case "ip_reputation":
		return trust.ScorerWeight{
			Scorer: &trust.IPReputationScorer{
				Lookup:                   ipLookup,
				Window:                   cfg.IPReputation.Window,
				FailureThreshold:         cfg.IPReputation.FailureThreshold,
				DistinctSubjectThreshold: cfg.IPReputation.DistinctSubjectThreshold,
			},
			Weight:       weight,
			FloorOnError: cfg.IPReputation.FloorOnError,
		}, nil
	case "behavior":
		return trust.ScorerWeight{
			Scorer: &trust.BehaviorScorer{
				History:      historyLookup,
				HistoryLimit: cfg.Behavior.HistoryLimit,
			},
			Weight:       weight,
			FloorOnError: cfg.Behavior.FloorOnError,
		}, nil
	case "device_posture":
		return trust.ScorerWeight{
			Scorer: trust.NewDevicePostureScorer(cfg.DevicePosture.DefaultScore),
			Weight: weight,
		}, nil
	default:
		return trust.ScorerWeight{}, fmt.Errorf(
			"trust.weights: unknown scorer %q (supported: geo_risk, ip_reputation, behavior, device_posture)", name)
	}
}

// --- composition-root adapters -------------------------------------------
//
// shared/trust cannot import domains/anomaly (shared/ sits below domains/ in
// the dependency direction — see architecture_layer_test.go), so the bridge
// from the real anomaly stores onto trust's narrow lookup interfaces lives
// here instead, at the cmd composition root where both are already visible.

// newTrustIPFailureLookup wraps counter as a trust.IPFailureLookup, or
// returns nil when counter is nil — trust.IPReputationScorer treats a nil
// Lookup as cold-start no-signal, never an error.
func newTrustIPFailureLookup(counter anomaly.IPFailureCounter, ipSalt []byte) trust.IPFailureLookup {
	if counter == nil {
		return nil
	}
	return &trustIPFailureAdapter{counter: counter, salt: ipSalt}
}

// trustIPFailureAdapter bridges anomaly.IPFailureCounter into
// trust.IPFailureLookup.
type trustIPFailureAdapter struct {
	counter anomaly.IPFailureCounter
	salt    []byte
}

// CountFailures implements trust.IPFailureLookup: it hashes the raw ip with
// the same salted scheme domains/anomaly detectors already use before
// querying the shared counter, so ip_reputation reads the exact rows the
// brute-force-shadow detector wrote — not a second hash space.
func (a *trustIPFailureAdapter) CountFailures(ctx context.Context, ip string, since time.Time) (int, int, error) {
	hash := hashIPForTrust(ip, a.salt)
	if hash == "" {
		return 0, 0, nil
	}
	return a.counter.Count(ctx, hash, since)
}

var _ trust.IPFailureLookup = (*trustIPFailureAdapter)(nil)

// newTrustLoginHistoryLookup wraps store as a trust.LoginHistoryLookup, or
// returns nil when store is nil — trust.BehaviorScorer treats a nil History
// as cold-start no-signal, never an error.
func newTrustLoginHistoryLookup(store anomaly.RecentLoginStore) trust.LoginHistoryLookup {
	if store == nil {
		return nil
	}
	return &trustLoginHistoryAdapter{store: store}
}

// trustLoginHistoryAdapter bridges anomaly.RecentLoginStore into
// trust.LoginHistoryLookup.
type trustLoginHistoryAdapter struct {
	store anomaly.RecentLoginStore
}

// History implements trust.LoginHistoryLookup over the shared
// anomaly.RecentLoginStore — no lower time bound (Recent's since.IsZero()
// contract is "no lower bound"), just the recency limit BehaviorScorer asks
// for.
func (a *trustLoginHistoryAdapter) History(ctx context.Context, subjectID string, limit int) ([]time.Time, error) {
	entries, err := a.store.Recent(ctx, subjectID, time.Time{}, limit)
	if err != nil {
		return nil, err
	}
	out := make([]time.Time, 0, len(entries))
	for _, e := range entries {
		if e == nil {
			continue
		}
		out = append(out, e.Timestamp)
	}
	return out, nil
}

var _ trust.LoginHistoryLookup = (*trustLoginHistoryAdapter)(nil)

// hashIPForTrust reuses the exact salted SHA-256 truncation scheme
// domains/anomaly detectors use (16 hex chars = 64-bit truncation of
// sha256(salt || ip)) so ip_reputation queries land in the same IP-hash space
// the anomaly stores were written in. Kept as its own tiny copy rather than
// exporting one of theirs — the same precedent
// infrastructure/defaultimpl/detectors' hashIPForBF already follows relative
// to infrastructure/defaultimpl/defaulttoken's hashIP.
func hashIPForTrust(ip string, salt []byte) string {
	if ip == "" {
		return ""
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(ip))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}
