package webhook

import (
	"context"
	"sync"
)

// MemoryDeadLetterStore is a bounded, process-local ring of exhausted
// deliveries (AGENTS.md "no mocks" — a real memory impl, not a test
// double). When the ring is full, the OLDEST brand-new entry is evicted;
// an upsert-by-ID (Replay updating an existing entry) never triggers
// eviction and never changes the entry's position.
type MemoryDeadLetterStore struct {
	mu       sync.Mutex
	capacity int
	order    []string // insertion order of ids, oldest first
	byID     map[string]DeadLetterEntry
}

var _ DeadLetterStore = (*MemoryDeadLetterStore)(nil)

// NewMemoryDeadLetterStore returns an empty store. capacity <= 0 falls back
// to DefaultDeadLetterCapacity.
func NewMemoryDeadLetterStore(capacity int) *MemoryDeadLetterStore {
	if capacity <= 0 {
		capacity = DefaultDeadLetterCapacity
	}
	return &MemoryDeadLetterStore{
		capacity: capacity,
		byID:     make(map[string]DeadLetterEntry, capacity),
	}
}

// Add stores entry. An empty ID mints a new one and is subject to capacity
// eviction (oldest evicted first); a non-empty ID overwrites the existing
// entry in place (see DeadLetterStore doc).
func (m *MemoryDeadLetterStore) Add(_ context.Context, entry DeadLetterEntry) (DeadLetterEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.ID == "" {
		entry.ID = newID()
		m.order = append(m.order, entry.ID)
		if len(m.order) > m.capacity {
			oldest := m.order[0]
			m.order = m.order[1:]
			delete(m.byID, oldest)
		}
	}
	m.byID[entry.ID] = entry
	return entry, nil
}

// Get returns the entry by id, or ErrDeadLetterNotFound.
func (m *MemoryDeadLetterStore) Get(_ context.Context, id string) (DeadLetterEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return DeadLetterEntry{}, ErrDeadLetterNotFound
	}
	return e, nil
}

// List returns entries newest-first, optionally narrowed to one
// subscription, capped at f.Limit (or DefaultDeadLetterListLimit).
func (m *MemoryDeadLetterStore) List(_ context.Context, f DeadLetterFilter) ([]DeadLetterEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultDeadLetterListLimit
	}
	out := make([]DeadLetterEntry, 0, min(limit, len(m.order)))
	for i := len(m.order) - 1; i >= 0; i-- {
		e, ok := m.byID[m.order[i]]
		if !ok {
			continue
		}
		if f.SubscriptionID != "" && e.SubscriptionID != f.SubscriptionID {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Delete removes the entry. Idempotent — deleting an unknown id is a no-op.
func (m *MemoryDeadLetterStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[id]; !ok {
		return nil
	}
	delete(m.byID, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return nil
}
