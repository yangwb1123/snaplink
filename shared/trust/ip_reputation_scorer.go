package trust

import (
	"context"
	"sync"
	"time"
)

// Reference thresholds/scores for IPReputationScorer. Exported constants so
// config wiring and tests can reference the same defaults the zero-value
// scorer uses.
const (
	DefaultIPReputationWindow         = time.Hour
	DefaultIPFailureThreshold         = 10
	DefaultIPDistinctSubjectThreshold = 5

	ipRepScoreNoSignal   = 0.6 // no RemoteIP / no Lookup wired: cold-start, not a penalty
	ipRepScoreClean      = 0.9
	ipRepScoreSuspicious = 0.1
)

// IPFailureLookup is a narrow read view over IP-keyed login-failure counts.
// It is intentionally decoupled from domains/anomaly.IPFailureCounter — a
// domains-layer type this shared-layer package must not import (see
// architecture_layer_test.go) — so wiring the real anomaly-backed store in
// is a composition-time adapter (translate to whatever IP-hash scheme the
// real store uses, forward to it), not an upward dependency here.
// MemoryIPFailureLookup below covers tests and single-replica dev setups.
type IPFailureLookup interface {
	// CountFailures returns the number of failed logins observed for ip
	// (total) and how many distinct subjects they were spread across
	// (distinct), for attempts at or after since. Implementations own
	// whatever hashing/normalization they apply to ip before querying their
	// store — this interface only sees the raw value TrustSignals carries.
	CountFailures(ctx context.Context, tenantID, ip string, since time.Time) (total, distinct int, err error)
}

// IPReputationScorer scores trust from recent login-failure volume observed
// for the caller's IP — the same brute-force-shadow signal domains/anomaly
// uses to flag an IP spraying attempts across many accounts, read here as an
// advisory trust signal rather than a hard block.
type IPReputationScorer struct {
	Lookup IPFailureLookup

	// Window bounds how far back CountFailures looks. Zero uses
	// DefaultIPReputationWindow.
	Window time.Duration

	// FailureThreshold / DistinctSubjectThreshold gate the "suspicious"
	// bucket: total failures >= FailureThreshold, OR distinct subjects >=
	// DistinctSubjectThreshold (the spray signal), scores low. Zero values
	// use the package defaults.
	FailureThreshold         int
	DistinctSubjectThreshold int
}

// Name implements TrustScorer.
func (s *IPReputationScorer) Name() string { return "ip_reputation" }

// Score implements TrustScorer. It returns an error ONLY when Lookup itself
// errors — an absent Lookup or empty RemoteIP is a cold-start no-signal
// case, not a failure (see WeightedComposite for how a Score error degrades
// to a configured floor rather than blocking authentication).
func (s *IPReputationScorer) Score(ctx context.Context, signals TrustSignals) (TrustScore, error) {
	if s.Lookup == nil || signals.RemoteIP == "" {
		return TrustScore{Value: ipRepScoreNoSignal, Reasons: []string{"ip_reputation:no_signal"}}, nil
	}
	since := s.observationStart(signals.Time)
	total, distinct, err := s.Lookup.CountFailures(ctx, signals.TenantID, signals.RemoteIP, since)
	if err != nil {
		return TrustScore{}, err
	}
	if total >= s.failureThreshold() || distinct >= s.distinctThreshold() {
		return TrustScore{Value: ipRepScoreSuspicious, Reasons: []string{"ip_reputation:high_failure_volume"}}, nil
	}
	return TrustScore{Value: ipRepScoreClean, Reasons: []string{"ip_reputation:clean"}}, nil
}

func (s *IPReputationScorer) observationStart(now time.Time) time.Time {
	window := s.Window
	if window <= 0 {
		window = DefaultIPReputationWindow
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.Add(-window)
}

func (s *IPReputationScorer) failureThreshold() int {
	if s.FailureThreshold > 0 {
		return s.FailureThreshold
	}
	return DefaultIPFailureThreshold
}

func (s *IPReputationScorer) distinctThreshold() int {
	if s.DistinctSubjectThreshold > 0 {
		return s.DistinctSubjectThreshold
	}
	return DefaultIPDistinctSubjectThreshold
}

var _ TrustScorer = (*IPReputationScorer)(nil)

// MemoryIPFailureLookup is an in-memory IPFailureLookup for tests and
// single-replica dev setups. Safe for concurrent use.
type MemoryIPFailureLookup struct {
	mu      sync.Mutex
	entries map[string][]ipFailureEntry // ip -> failures, unordered
}

type ipFailureEntry struct {
	subjectID string
	at        time.Time
}

// NewMemoryIPFailureLookup builds an empty MemoryIPFailureLookup.
func NewMemoryIPFailureLookup() *MemoryIPFailureLookup {
	return &MemoryIPFailureLookup{entries: make(map[string][]ipFailureEntry)}
}

// Record appends a failed-login observation for ip. subjectID may be empty
// (a failure before user resolution) — it still counts toward total, just
// not toward the distinct-subject count.
func (m *MemoryIPFailureLookup) Record(ip, subjectID string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[ip] = append(m.entries[ip], ipFailureEntry{subjectID: subjectID, at: at})
}

// CountFailures implements IPFailureLookup.
func (m *MemoryIPFailureLookup) CountFailures(_ context.Context, tenantID, ip string, since time.Time) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	total := 0
	for _, e := range m.entries[ip] {
		if e.at.Before(since) {
			continue
		}
		total++
		if e.subjectID != "" {
			seen[e.subjectID] = true
		}
	}
	return total, len(seen), nil
}

var _ IPFailureLookup = (*MemoryIPFailureLookup)(nil)
