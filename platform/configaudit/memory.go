package configaudit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// DefaultMemoryCapacity bounds the in-memory history used when
// NewMemoryStore is called with capacity <= 0. Mirrors audit.MemorySink's
// eviction policy: oldest entries drop first once full — config-history
// writes are low-frequency (one per admin mutation), so a generous default
// covers a long operational window before wrapping.
const DefaultMemoryCapacity = 5_000

// MemoryStore is a process-local, non-durable Store: a restart loses
// history. Suitable for development and single-replica deployments; pair
// with configaudit/sqlite for durable, cross-restart, multi-replica
// history.
type MemoryStore struct {
	mu       sync.RWMutex
	capacity int
	entries  []Entry
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns a ready MemoryStore. capacity <= 0 uses
// DefaultMemoryCapacity.
func NewMemoryStore(capacity int) *MemoryStore {
	if capacity <= 0 {
		capacity = DefaultMemoryCapacity
	}
	return &MemoryStore{capacity: capacity}
}

// Record appends e, evicting the oldest entries once over capacity.
func (m *MemoryStore) Record(_ context.Context, e Entry) error {
	if e.ID == "" {
		e.ID = newEntryID()
	}
	if e.RecordedAt.IsZero() {
		e.RecordedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	// Record is append-only, so the buffer can only ever be ONE over
	// capacity at a time — dropping the single oldest entry is enough
	// (no need for a ring buffer's index arithmetic).
	if over := len(m.entries) - m.capacity; over > 0 {
		m.entries = m.entries[over:]
	}
	return nil
}

// List returns entries matching f, newest first.
func (m *MemoryStore) List(_ context.Context, f Filter) ([]Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	limit := f.Limit
	if limit <= 0 {
		limit = DefaultMemoryCapacity
	}
	matches := make([]Entry, 0, min(limit, len(m.entries)))
	for i := len(m.entries) - 1; i >= 0; i-- {
		e := m.entries[i]
		if f.Resource != "" && e.Resource != f.Resource {
			continue
		}
		if !f.Since.IsZero() && e.RecordedAt.Before(f.Since) {
			continue
		}
		matches = append(matches, e)
		if len(matches) >= limit {
			break
		}
	}
	return matches, nil
}

// Len reports the number of entries currently retained. Test/ops helper —
// mirrors audit.MemorySink.Len.
func (m *MemoryStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

func newEntryID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
