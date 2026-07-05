package admingovernance

import (
	"context"
	"sync"
	"time"
)

// quotaCounter is one key's fixed-window bookkeeping: the window it belongs
// to plus the count consumed so far within it.
type quotaCounter struct {
	windowStart time.Time
	count       int
}

// MemoryWriteQuotaStore is an in-process, non-persistent WriteQuotaStore —
// fixed-window counters keyed by QuotaKey's output. Suitable for
// single-replica deployments, dev, and tests.
type MemoryWriteQuotaStore struct {
	mu       sync.Mutex
	counters map[string]quotaCounter
}

var _ WriteQuotaStore = (*MemoryWriteQuotaStore)(nil)

// NewMemoryWriteQuotaStore returns an empty MemoryWriteQuotaStore.
func NewMemoryWriteQuotaStore() *MemoryWriteQuotaStore {
	return &MemoryWriteQuotaStore{counters: make(map[string]quotaCounter)}
}

// Consume implements WriteQuotaStore. The window a moment belongs to is
// time.Time.Truncate(window) — a deterministic, allocation-free way to
// derive the SAME window boundary for every caller without a separate
// scheduler goroutine to reset counters; a counter for a past window is
// simply replaced the next time its key is consumed (lazy reset).
func (m *MemoryWriteQuotaStore) Consume(_ context.Context, key string, limit int, window time.Duration, now time.Time) (QuotaResult, error) {
	if limit <= 0 || window <= 0 {
		return QuotaResult{Allowed: true}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	windowStart := now.Truncate(window)
	resetAt := windowStart.Add(window)
	c := m.counters[key]
	if !c.windowStart.Equal(windowStart) {
		c = quotaCounter{windowStart: windowStart}
	}
	if c.count >= limit {
		m.counters[key] = c
		return QuotaResult{Allowed: false, Remaining: 0, ResetAt: resetAt}, nil
	}
	c.count++
	m.counters[key] = c
	return QuotaResult{Allowed: true, Remaining: limit - c.count, ResetAt: resetAt}, nil
}
