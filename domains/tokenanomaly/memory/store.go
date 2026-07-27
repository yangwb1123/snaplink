// Package memory is the in-memory [tokenanomaly.FindingStore]: a bounded,
// dedup-by-key table of detected token-behavior anomalies. Add UPSERTS on
// [tokenanomaly.Finding.DedupKey] so a repeatedly-detected anomaly refreshes
// one row (LastSeen/Count/Geos/escalated severity) instead of accumulating
// duplicates, and the whole table is capped like the wave-1 usage store — it
// is a rolling operational view, not an archive.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/yangwb1123/snaplink/domains/tokenanomaly"
)

// DefaultMaxFindings caps distinct findings when WithMaxFindings is not given.
const DefaultMaxFindings = 1024

// FindingStore is the in-memory bounded [tokenanomaly.FindingStore]. Safe for
// concurrent use.
type FindingStore struct {
	mu    sync.Mutex
	max   int
	byKey map[string]tokenanomaly.Finding
	// order holds keys in first-insertion order; eviction pops the front.
	order []string
}

// Option tunes the store at construction.
type Option func(*FindingStore)

// WithMaxFindings overrides the finding cap (non-positive ignored).
func WithMaxFindings(n int) Option {
	return func(s *FindingStore) {
		if n > 0 {
			s.max = n
		}
	}
}

// NewFindingStore returns an empty bounded store.
func NewFindingStore(opts ...Option) *FindingStore {
	s := &FindingStore{
		max:   DefaultMaxFindings,
		byKey: make(map[string]tokenanomaly.Finding),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Add upserts f keyed by its DedupKey. On an existing key it merges: the
// earliest FirstSeen is preserved, the latest LastSeen wins, severity only
// escalates, and the fresher finding's Count/Geos/Detail replace the prior
// (the detector recomputes these cumulatively from the live observation). A
// genuinely new key evicts the oldest entry when at cap.
func (s *FindingStore) Add(_ context.Context, f tokenanomaly.Finding) error {
	key := f.DedupKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byKey[key]; ok {
		s.byKey[key] = mergeFinding(prev, f)
		return nil
	}
	if len(s.byKey) >= s.max {
		s.evictOldestLocked()
	}
	s.byKey[key] = f
	s.order = append(s.order, key)
	return nil
}

// mergeFinding folds a re-detected finding into the stored one.
func mergeFinding(prev, next tokenanomaly.Finding) tokenanomaly.Finding {
	merged := next
	if !prev.FirstSeen.IsZero() && (next.FirstSeen.IsZero() || prev.FirstSeen.Before(next.FirstSeen)) {
		merged.FirstSeen = prev.FirstSeen
	}
	if prev.LastSeen.After(merged.LastSeen) {
		merged.LastSeen = prev.LastSeen
	}
	// Severity only escalates — a warn re-detection must not downgrade a row
	// an earlier sweep already marked critical.
	if prev.Severity == tokenanomaly.SeverityCritical {
		merged.Severity = tokenanomaly.SeverityCritical
	}
	return merged
}

// evictOldestLocked drops the earliest-inserted finding. Caller holds s.mu.
func (s *FindingStore) evictOldestLocked() {
	if len(s.order) == 0 {
		return
	}
	delete(s.byKey, s.order[0])
	s.order = s.order[1:]
}

// List returns findings matching q, ordered most-recent LastSeen first, then
// by dedup key for a stable tie-break. Limit > 0 caps the result.
func (s *FindingStore) List(_ context.Context, q tokenanomaly.FindingQuery) ([]tokenanomaly.Finding, error) {
	s.mu.Lock()
	out := make([]tokenanomaly.Finding, 0, len(s.byKey))
	for _, f := range s.byKey {
		if q.Type != "" && f.Type != q.Type {
			continue
		}
		if q.Severity != "" && f.Severity != q.Severity {
			continue
		}
		out = append(out, f)
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].DedupKey() < out[j].DedupKey()
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

var _ tokenanomaly.FindingStore = (*FindingStore)(nil)
