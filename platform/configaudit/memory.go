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
	mu        sync.RWMutex
	capacity  int
	entries   []Entry
	applied   []AppliedVersion // append-only version chain, oldest first
	canary    CanaryState
	hasCanary bool
}

var _ Store = (*MemoryStore)(nil)
var _ CanaryStore = (*MemoryStore)(nil)
var _ ConditionalRollbackStore = (*MemoryStore)(nil)

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
	e = cloneEntry(e)
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
		matches = append(matches, cloneEntry(e))
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
	v = cloneAppliedVersion(v)
	if v.ID == "" {
		v.ID = newEntryID()
	}
	if v.AppliedAt.IsZero() {
		v.AppliedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hasCanary && m.canary.Status == CanaryObserving {
		return cloneAppliedVersion(v), ErrCanaryInProgress
	}
	var prev AppliedVersion
	if n := len(m.applied); n > 0 {
		prev = m.applied[n-1]
	}
	v.PrevID = prev.ID
	m.appendAppliedLocked(v, prev)
	return cloneAppliedVersion(v), nil
}

// Applied returns the latest applied-config baseline, or ErrNoAppliedVersion
// before the first Apply.
func (m *MemoryStore) Applied(_ context.Context) (AppliedVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n := len(m.applied); n > 0 {
		return cloneAppliedVersion(m.applied[n-1]), nil
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
	return m.rollbackLocked("", actor, reason)
}

// RollbackIfCurrent performs an atomic compare-and-swap rollback. It is used
// by the operator path so a stale approval cannot undo a newer baseline.
func (m *MemoryStore) RollbackIfCurrent(_ context.Context, expectedID, actor, reason string) (AppliedVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rollbackLocked(expectedID, actor, reason)
}

func (m *MemoryStore) rollbackLocked(expectedID, actor, reason string) (AppliedVersion, error) {
	if m.hasCanary && m.canary.Status == CanaryObserving {
		return AppliedVersion{}, ErrCanaryInProgress
	}
	n := len(m.applied)
	if n < 2 {
		return AppliedVersion{}, ErrNoAppliedVersion
	}
	cur, prev := m.applied[n-1], m.applied[n-2]
	if expectedID != "" && cur.ID != expectedID {
		return AppliedVersion{}, ErrRollbackConflict
	}
	v := AppliedVersion{
		ID:        newEntryID(),
		AppliedAt: time.Now().UTC(),
		Actor:     actor,
		Digest:    prev.Digest,
		Reason:    reason,
		PrevID:    cur.ID,
		Snapshot:  cloneSnapshot(prev.Snapshot),
	}
	m.appendAppliedLocked(v, cur)
	return cloneAppliedVersion(v), nil
}

// BeginCanary atomically records a candidate baseline and its observing state.
func (m *MemoryStore) BeginCanary(_ context.Context, v AppliedVersion, state CanaryState) (AppliedVersion, CanaryState, error) {
	v = cloneAppliedVersion(v)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hasCanary && m.canary.Status == CanaryObserving {
		return AppliedVersion{}, CanaryState{}, ErrCanaryInProgress
	}
	if len(m.applied) == 0 {
		return AppliedVersion{}, CanaryState{}, ErrCanaryNoBaseline
	}
	if v.ID == "" {
		v.ID = newEntryID()
	}
	if v.AppliedAt.IsZero() {
		v.AppliedAt = time.Now().UTC()
	}
	prev := m.applied[len(m.applied)-1]
	v.PrevID = prev.ID
	state = normalizeCanaryState(state, v, prev)
	m.appendAppliedLocked(v, prev)
	m.canary, m.hasCanary = state, true
	return cloneAppliedVersion(v), state, nil
}

// Canary returns the current lifecycle state.
func (m *MemoryStore) Canary(_ context.Context) (CanaryState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.hasCanary {
		return CanaryState{}, ErrNoCanary
	}
	return m.canary, nil
}

// ConfirmCanary marks an observing candidate healthy after its full window.
func (m *MemoryStore) ConfirmCanary(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasCanary || m.canary.ID != id || m.canary.Status != CanaryObserving {
		return ErrCanaryConflict
	}
	m.canary.Status = CanaryConfirmed
	return nil
}

// RollbackCanary restores the predecessor only when the candidate is still
// the latest baseline, then marks the state terminal under the same lock.
func (m *MemoryStore) RollbackCanary(_ context.Context, id, actor, reason string) (AppliedVersion, CanaryState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasCanary || m.canary.ID != id || m.canary.Status != CanaryObserving {
		return AppliedVersion{}, CanaryState{}, ErrCanaryConflict
	}
	n := len(m.applied)
	if n < 2 || m.applied[n-1].ID != m.canary.VersionID {
		return AppliedVersion{}, m.canary, ErrCanaryConflict
	}
	cur, prev := m.applied[n-1], m.applied[n-2]
	v := AppliedVersion{
		ID: newEntryID(), AppliedAt: time.Now().UTC(), Actor: actor,
		Digest: prev.Digest, Reason: reason, PrevID: cur.ID, Snapshot: cloneSnapshot(prev.Snapshot),
	}
	m.appendAppliedLocked(v, cur)
	m.canary.Status = CanaryRolledBack
	m.canary.Detail = reason
	return cloneAppliedVersion(v), m.canary, nil
}

func (m *MemoryStore) appendAppliedLocked(v, prev AppliedVersion) {
	stored := cloneAppliedVersion(v)
	entry := Entry{
		Actor: stored.Actor, Resource: resourceConfigApply, ResourceID: stored.ID,
		Patch: RedactOps(Diff(prev.Snapshot, stored.Snapshot)), Reason: stored.Reason,
		RecordedAt: stored.AppliedAt, ID: newEntryID(),
	}
	m.applied = append(m.applied, stored)
	m.entries = append(m.entries, cloneEntry(entry))
	if over := len(m.entries) - m.capacity; over > 0 {
		m.entries = m.entries[over:]
	}
}

// appliedVersions returns a copy of the applied-baseline chain (oldest
// first). Test helper.
func (m *MemoryStore) appliedVersions() []AppliedVersion {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneAppliedVersions(m.applied)
}

func cloneJSONValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneSnapshot(value)
	case []any:
		if value == nil {
			return []any(nil)
		}
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = cloneJSONValue(item)
		}
		return out
	case []string:
		if value == nil {
			return []string(nil)
		}
		out := make([]string, len(value))
		copy(out, value)
		return out
	case map[string]string:
		if value == nil {
			return map[string]string(nil)
		}
		out := make(map[string]string, len(value))
		for key, item := range value {
			out[key] = item
		}
		return out
	default:
		return value
	}
}

func cloneSnapshot(snapshot map[string]any) map[string]any {
	if snapshot == nil {
		return nil
	}
	out := make(map[string]any, len(snapshot))
	for key, value := range snapshot {
		out[key] = cloneJSONValue(value)
	}
	return out
}

func cloneOps(ops []Op) []Op {
	if ops == nil {
		return nil
	}
	out := make([]Op, len(ops))
	for i, op := range ops {
		out[i] = op
		out[i].Value = cloneJSONValue(op.Value)
	}
	return out
}

func cloneEntry(entry Entry) Entry {
	entry.Patch = cloneOps(entry.Patch)
	return entry
}

func cloneAppliedVersion(version AppliedVersion) AppliedVersion {
	version.Snapshot = cloneSnapshot(version.Snapshot)
	return version
}

func cloneAppliedVersions(versions []AppliedVersion) []AppliedVersion {
	if versions == nil {
		return nil
	}
	out := make([]AppliedVersion, len(versions))
	for i, version := range versions {
		out[i] = cloneAppliedVersion(version)
	}
	return out
}

func newEntryID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
