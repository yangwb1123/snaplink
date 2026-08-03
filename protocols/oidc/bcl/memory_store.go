package bcl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sort"
	"sync"
	"time"
)

const defaultMemoryCapacity = 1000

type memoryLease struct {
	token string
	until time.Time
}

type MemoryStore struct {
	mu       sync.Mutex
	entries  map[string]Failure
	leases   map[string]memoryLease
	capacity int
}

func NewMemoryStore(capacity int) *MemoryStore {
	if capacity <= 0 {
		capacity = defaultMemoryCapacity
	}
	return &MemoryStore{entries: make(map[string]Failure), leases: make(map[string]memoryLease), capacity: capacity}
}

func (m *MemoryStore) Enqueue(_ context.Context, f Failure) (Failure, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.entries[f.ID]; ok {
		f.FirstFailedAt = old.FirstFailedAt
		f.Attempts += old.Attempts
	}
	m.entries[f.ID] = f
	m.evictOldest()
	return f, nil
}

func (m *MemoryStore) evictOldest() {
	for len(m.entries) > m.capacity {
		var oldestID string
		var oldest time.Time
		for id, entry := range m.entries {
			if oldestID == "" || entry.FirstFailedAt.Before(oldest) {
				oldestID, oldest = id, entry.FirstFailedAt
			}
		}
		delete(m.entries, oldestID)
		delete(m.leases, oldestID)
	}
}

func (m *MemoryStore) List(_ context.Context, filter Filter) ([]Failure, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Failure, 0, len(m.entries))
	for _, entry := range m.entries {
		if filter.TenantID != "" && entry.TenantID != filter.TenantID {
			continue
		}
		if !filter.DueBefore.IsZero() {
			if entry.Permanent || entry.NextAttemptAt.After(filter.DueBefore) {
				continue
			}
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextAttemptAt.Before(out[j].NextAttemptAt) })
	limit := normalizedLimit(filter.Limit)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) Claim(_ context.Context, id, tenantID string, lease time.Duration) (Failure, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[id]
	if !ok || (tenantID != "" && entry.TenantID != tenantID) {
		return Failure{}, "", ErrNotFound
	}
	now := time.Now()
	if current, leased := m.leases[id]; leased && current.until.After(now) {
		return entry, "", ErrLeaseUnavailable
	}
	token := randomLeaseToken()
	m.leases[id] = memoryLease{token: token, until: now.Add(normalizedLease(lease))}
	return entry, token, nil
}

func (m *MemoryStore) Ack(_ context.Context, f Failure, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ownsLease(f.ID, token) {
		return ErrLeaseUnavailable
	}
	delete(m.entries, f.ID)
	delete(m.leases, f.ID)
	return nil
}

func (m *MemoryStore) Reschedule(_ context.Context, f Failure, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ownsLease(f.ID, token) {
		return ErrLeaseUnavailable
	}
	m.entries[f.ID] = f
	delete(m.leases, f.ID)
	return nil
}

func (m *MemoryStore) ownsLease(id, token string) bool {
	lease, ok := m.leases[id]
	return ok && token != "" && lease.token == token && lease.until.After(time.Now())
}

func randomLeaseToken() string {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func normalizedLimit(limit int) int {
	if limit <= 0 || limit > 200 {
		return 100
	}
	return limit
}

func normalizedLease(lease time.Duration) time.Duration {
	if lease <= 0 {
		return DefaultLeaseDuration
	}
	return lease
}
