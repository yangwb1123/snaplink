package memorystorecredential

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
)

// MemoryIPFailureCounter is the in-process [anomaly.IPFailureCounter].
// Per-IP slice of (subject, ts) tuples guarded by single mutex.
// Suitable for single-replica + tests; SQLite peer for cluster.
type MemoryIPFailureCounter struct {
	mu      sync.Mutex
	entries map[string][]ipFailEntry
}

type ipFailEntry struct {
	subject string
	ts      time.Time
}

// NewMemoryIPFailureCounter returns an empty in-process counter.
func NewMemoryIPFailureCounter() *MemoryIPFailureCounter {
	return &MemoryIPFailureCounter{entries: make(map[string][]ipFailEntry)}
}

// Record appends a failure entry for ipHash. Empty ipHash → no-op.
func (m *MemoryIPFailureCounter) Record(_ context.Context, ipHash, subjectID string, ts time.Time) error {
	if ipHash == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[ipHash] = append(m.entries[ipHash], ipFailEntry{subject: subjectID, ts: ts})
	return nil
}

// Count returns (total, distinct subjects) for ipHash after since.
func (m *MemoryIPFailureCounter) Count(_ context.Context, ipHash string, since time.Time) (int, int, error) {
	if ipHash == "" {
		return 0, 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket := m.entries[ipHash]
	total := 0
	subjects := make(map[string]struct{}, len(bucket))
	for _, e := range bucket {
		if !since.IsZero() && e.ts.Before(since) {
			continue
		}
		total++
		if e.subject != "" {
			subjects[e.subject] = struct{}{}
		}
	}
	return total, len(subjects), nil
}

// PruneOlder removes entries with ts < cutoff across all IPs.
// Empty IP buckets after pruning are dropped.
func (m *MemoryIPFailureCounter) PruneOlder(_ context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted int64
	for ip, bucket := range m.entries {
		// Bucket is approximately time-sorted (append order), so a
		// linear walk is fine. Sort first for safety against
		// concurrent-producer reorder.
		sort.Slice(bucket, func(i, j int) bool { return bucket[i].ts.Before(bucket[j].ts) })
		i := 0
		for i < len(bucket) && bucket[i].ts.Before(cutoff) {
			i++
		}
		deleted += int64(i)
		if i >= len(bucket) {
			delete(m.entries, ip)
		} else {
			m.entries[ip] = bucket[i:]
		}
	}
	return deleted, nil
}

var _ anomaly.IPFailureCounter = (*MemoryIPFailureCounter)(nil)
