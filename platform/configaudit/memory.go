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
// history and applied baselines. Suitable for development and
// single-replica deployments; pair with configaudit/sqlite for durable,
// cross-restart, multi-replica history + applied baselines.
type MemoryStore struct {
	mu       sync.RWMutex
	capacity int
	entries  []Entry
	applied  []AppliedVersion // append-only version chain, oldest first
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

// Apply records v as the new applied-config baseline and appends the
// matching config_history entry under one lock: a failure mutates nothing.
// The history entry's patch is the redacted Diff of the redacted baselines
// (the only forms ever stored), so no plaintext secret can reach history.
func (m *MemoryStore) Apply(_ context.Context, v AppliedVersion) (AppliedVersion, error) {
	if v.ID == "" {
		v.ID = newEntryID()
	}
	if v.AppliedAt.IsZero() {
		v.AppliedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev AppliedVersion
	if n := len(m.applied); n > 0 {
		prev = m.applied[n-1]
	}
	v.PrevID = prev.ID
	entry := Entry{
		Actor:      v.Actor,
		Resource:   resourceConfigApply,
		ResourceID: v.ID,
		Patch:      RedactOps(Diff(prev.Snapshot, v.Snapshot)),
		Reason:     v.Reason,
	}
	if entry.RecordedAt.IsZero() {
		entry.RecordedAt = v.AppliedAt
	}
	if entry.ID == "" {
		entry.ID = newEntryID()
	}
	m.applied = append(m.applied, v)
	m.entries = append(m.entries, entry)
	if over := len(m.entries) - m.capacity; over > 0 {
		m.entries = m.entries[over:]
	}
	return v, nil
}

// Applied returns the latest applied-config baseline, or ErrNoAppliedVersion
// before the first Apply.
func (m *MemoryStore) Applied(_ context.Context) (AppliedVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n := len(m.applied); n > 0 {
		return m.applied[n-1], nil
	}
	return AppliedVersion{}, ErrNoAppliedVersion
}

// Rollback re-declares the previous baseline as the new latest (a new
// version whose Snapshot is the previous version's), appending the
// config_history entry under one lock. ErrNoAppliedVersion when there is no
// baseline or no predecessor.
func (m *MemoryStore) Rollback(_ context.Context, actor, reason string) (AppliedVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.applied)
	if n < 2 {
		return AppliedVersion{}, ErrNoAppliedVersion
	}
	cur, prev := m.applied[n-1], m.applied[n-2]
	v := AppliedVersion{
		ID:        newEntryID(),
		AppliedAt: time.Now().UTC(),
		Actor:     actor,
		Digest:    prev.Digest,
		Reason:    reason,
		PrevID:    cur.ID,
		Snapshot:  prev.Snapshot,
	}
	entry := Entry{
		Actor:      actor,
		Resource:   resourceConfigApply,
		ResourceID: v.ID,
		Patch:      RedactOps(Diff(cur.Snapshot, prev.Snapshot)),
		Reason:     reason,
		RecordedAt: v.AppliedAt,
		ID:         newEntryID(),
	}
	m.applied = append(m.applied, v)
	m.entries = append(m.entries, entry)
	if over := len(m.entries) - m.capacity; over > 0 {
		m.entries = m.entries[over:]
	}
	return v, nil
}

// appliedVersions returns a copy of the applied-baseline chain (oldest
// first). Test helper.
func (m *MemoryStore) appliedVersions() []AppliedVersion {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]AppliedVersion(nil), m.applied...)
}

func newEntryID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
