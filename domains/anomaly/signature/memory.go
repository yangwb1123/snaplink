package signature

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory Store implementation safe for concurrent
// use. Suitable for development, testing, and low-traffic deployments.
type MemoryStore struct {
	mu      sync.RWMutex
	entries []Entry
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		entries: make([]Entry, 0, 1024),
	}
}

func (m *MemoryStore) Record(_ context.Context, entry Entry) error {
	if entry.Signature == "" {
		return nil
	}
	m.mu.Lock()
	m.entries = append(m.entries, entry)
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) Seen(_ context.Context, sig string, since time.Time, subjectID string) (bool, error) {
	if sig == "" {
		return false, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	for _, e := range m.entries {
		if e.Signature != sig {
			continue
		}
		if e.Timestamp.Before(since) || e.Timestamp.After(now) {
			continue
		}
		if subjectID != "" && e.SubjectID != subjectID {
			continue
		}
		return true, nil
	}
	return false, nil
}

func (m *MemoryStore) DistinctCount(_ context.Context, prefix string, since time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	seen := make(map[string]struct{}, 64)
	for _, e := range m.entries {
		if e.Timestamp.Before(since) || e.Timestamp.After(now) {
			continue
		}
		if prefix != "" && len(e.Signature) < len(prefix) {
			continue
		}
		if prefix != "" && e.Signature[:len(prefix)] != prefix {
			continue
		}
		seen[e.Signature] = struct{}{}
	}
	return len(seen), nil
}

func (m *MemoryStore) PruneOlder(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := make([]Entry, 0, len(m.entries))
	var removed int64
	for _, e := range m.entries {
		if e.Timestamp.Before(cutoff) {
			removed++
		} else {
			kept = append(kept, e)
		}
	}
	m.entries = kept
	return removed, nil
}

var _ Store = (*MemoryStore)(nil)
