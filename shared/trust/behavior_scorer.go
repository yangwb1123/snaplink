package trust

import (
	"context"
	"sync"
	"time"
)

// Reference tuning + scores for BehaviorScorer.
const (
	DefaultBehaviorHistoryLimit = 20

	behaviorScoreNoSignal    = 0.6 // no History wired / no UserID: cold-start, not a penalty
	behaviorScoreColdStart   = 0.6 // known subject, but no login history yet
	behaviorScoreTypicalHour = 0.9
	behaviorScoreAtypical    = 0.5
)

// LoginHistoryLookup is a narrow read view over a subject's past login
// times, used for a simple time-of-day baseline. Decoupled from
// domains/anomaly.RecentLoginStore (a domains-layer type this shared-layer
// package must not import — see architecture_layer_test.go) the same way
// IPFailureLookup is: a composition-time adapter can wrap the real store;
// MemoryLoginHistory below covers tests and single-replica dev setups.
type LoginHistoryLookup interface {
	// History returns up to limit of subjectID's most recent successful
	// login timestamps, newest first. An empty (not error) result means "no
	// history" — a brand-new subject.
	History(ctx context.Context, subjectID string, limit int) ([]time.Time, error)
}

// BehaviorScorer scores trust from a simple time-of-day baseline: has this
// subject logged in around this hour before? It is intentionally a
// heuristic, not a model — no clustering, no anomaly-score fusion (per the
// source analysis doc: "keep honest, no fake ML"). A subject with no
// history is a COLD START (neutral score, not a penalty — new users/devices
// get a default risk level, not automatic distrust).
type BehaviorScorer struct {
	History LoginHistoryLookup

	// HistoryLimit bounds how many past logins are consulted. Zero uses
	// DefaultBehaviorHistoryLimit.
	HistoryLimit int
}

// Name implements TrustScorer.
func (s *BehaviorScorer) Name() string { return "behavior" }

// Score implements TrustScorer. It returns an error ONLY when History
// itself errors — a missing History or empty UserID is a cold-start
// no-signal case, not a failure.
func (s *BehaviorScorer) Score(ctx context.Context, signals TrustSignals) (TrustScore, error) {
	if s.History == nil || signals.UserID == "" {
		return TrustScore{Value: behaviorScoreNoSignal, Reasons: []string{"behavior:no_signal"}}, nil
	}
	hist, err := s.History.History(ctx, signals.UserID, s.historyLimit())
	if err != nil {
		return TrustScore{}, err
	}
	if len(hist) == 0 {
		return TrustScore{Value: behaviorScoreColdStart, Reasons: []string{"behavior:cold_start"}}, nil
	}
	if hasObservedHour(hist, observationHour(signals.Time)) {
		return TrustScore{Value: behaviorScoreTypicalHour, Reasons: []string{"behavior:typical_hour"}}, nil
	}
	return TrustScore{Value: behaviorScoreAtypical, Reasons: []string{"behavior:atypical_hour"}}, nil
}

func (s *BehaviorScorer) historyLimit() int {
	if s.HistoryLimit > 0 {
		return s.HistoryLimit
	}
	return DefaultBehaviorHistoryLimit
}

func observationHour(t time.Time) int {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Hour()
}

func hasObservedHour(hist []time.Time, hour int) bool {
	for _, t := range hist {
		if t.UTC().Hour() == hour {
			return true
		}
	}
	return false
}

var _ TrustScorer = (*BehaviorScorer)(nil)

// MemoryLoginHistory is an in-memory LoginHistoryLookup for tests and
// single-replica dev setups. Safe for concurrent use.
type MemoryLoginHistory struct {
	mu   sync.Mutex
	logs map[string][]time.Time // subjectID -> timestamps, newest-first
}

// NewMemoryLoginHistory builds an empty MemoryLoginHistory.
func NewMemoryLoginHistory() *MemoryLoginHistory {
	return &MemoryLoginHistory{logs: make(map[string][]time.Time)}
}

// Record prepends at to subjectID's history (newest-first).
func (m *MemoryLoginHistory) Record(subjectID string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs[subjectID] = append([]time.Time{at}, m.logs[subjectID]...)
}

// History implements LoginHistoryLookup.
func (m *MemoryLoginHistory) History(_ context.Context, subjectID string, limit int) ([]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.logs[subjectID]
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	out := make([]time.Time, len(all))
	copy(out, all)
	return out, nil
}

var _ LoginHistoryLookup = (*MemoryLoginHistory)(nil)
