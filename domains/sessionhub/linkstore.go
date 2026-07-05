package sessionhub

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// DefaultLinkStoreCapacity caps how many DISTINCT global_sids the in-memory
// LinkStore tracks. Past the cap the least-recently-touched global_sid is
// evicted whole (all its legs) — the same bounded-LRU discipline the SDK
// applies to every other per-replica in-memory store keyed on live traffic
// (e.g. infrastructure/saml/idp's MemorySessionIndex): a flood of logins
// can't grow the store without bound. Eviction is benign — a dropped
// global_sid simply can no longer be looked up by Coordinator.Logout; its
// legs still terminate independently by their own natural expiry/logout
// paths, exactly as they do today without this package.
const DefaultLinkStoreCapacity = 50000

// LinkStore persists the LinkRecords a global_sid fans out into.
// Implementations MUST be safe for concurrent use. This is an INTERFACE
// (mirroring core.SessionManager / connections.Store) so an operator can
// swap in a shared backend (sqlite/redis) for a multi-replica deployment;
// the default is the bounded in-memory impl below.
type LinkStore interface {
	// Link records one leg of a global_sid's fan-out. Idempotent-ish: calling
	// it twice with the same (GlobalSID, Protocol, ExternalRef) appends a
	// duplicate row rather than erroring — callers only call it once per leg
	// in practice (at login), so this keeps the store simple.
	Link(ctx context.Context, rec LinkRecord) error

	// List returns every LinkRecord recorded for gsid (a copy; the caller may
	// mutate the slice freely). An unknown global_sid returns (nil, nil) —
	// not an error, mirroring SAMLSessionIndex.ListBySubject.
	List(ctx context.Context, gsid GlobalSID) ([]LinkRecord, error)

	// DeleteAll drops every LinkRecord for gsid (the login is now logged out
	// everywhere). A no-op when the global_sid is unknown.
	DeleteAll(ctx context.Context, gsid GlobalSID) error
}

// sidEntry holds one global_sid's accumulated legs.
type sidEntry struct {
	gsid  GlobalSID
	links []LinkRecord
}

// MemoryLinkStore is the default bounded, in-memory LinkStore: an LRU over
// global_sids (container/list + a map index, mutex-guarded — the same shape
// as infrastructure/saml/idp.MemorySessionIndex), each holding the small
// slice of legs recorded for it (realistically 1-3: core, maybe saml).
type MemoryLinkStore struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List
	index    map[GlobalSID]*list.Element
}

// NewMemoryLinkStore returns a bounded in-memory LinkStore. A non-positive
// capacity falls back to [DefaultLinkStoreCapacity].
func NewMemoryLinkStore(capacity int) *MemoryLinkStore {
	if capacity <= 0 {
		capacity = DefaultLinkStoreCapacity
	}
	return &MemoryLinkStore{
		capacity: capacity,
		ll:       list.New(),
		index:    make(map[GlobalSID]*list.Element),
	}
}

// interface guard.
var _ LinkStore = (*MemoryLinkStore)(nil)

// Link appends rec to gsid's leg list, creating the entry (and evicting the
// oldest global_sid past capacity) on first sight, else touching it to the
// most-recently-used end. A blank GlobalSID is refused (ErrEmptyGlobalSID)
// so a caller bug can't silently pollute the store under an empty key.
func (m *MemoryLinkStore) Link(_ context.Context, rec LinkRecord) error {
	if rec.GlobalSID == "" {
		return ErrEmptyGlobalSID
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.index[rec.GlobalSID]
	if !ok {
		se := &sidEntry{gsid: rec.GlobalSID}
		el = m.ll.PushBack(se)
		m.index[rec.GlobalSID] = el
		for m.ll.Len() > m.capacity {
			m.evictOldestLocked()
		}
	} else {
		m.ll.MoveToBack(el)
	}
	se := el.Value.(*sidEntry)
	se.links = append(se.links, rec)
	return nil
}

// List returns a COPY of gsid's recorded legs. Does NOT touch LRU recency —
// a read (e.g. an operator inspecting state) shouldn't keep a stale
// global_sid pinned in the store.
func (m *MemoryLinkStore) List(_ context.Context, gsid GlobalSID) ([]LinkRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.index[gsid]
	if !ok {
		return nil, nil
	}
	se := el.Value.(*sidEntry)
	out := make([]LinkRecord, len(se.links))
	copy(out, se.links)
	return out, nil
}

// DeleteAll drops every leg recorded for gsid. A no-op when unknown.
func (m *MemoryLinkStore) DeleteAll(_ context.Context, gsid GlobalSID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.index[gsid]
	if !ok {
		return nil
	}
	m.ll.Remove(el)
	delete(m.index, gsid)
	return nil
}

// evictOldestLocked drops the least-recently-touched global_sid entirely.
// Caller holds the mutex.
func (m *MemoryLinkStore) evictOldestLocked() {
	el := m.ll.Front()
	if el == nil {
		return
	}
	se := el.Value.(*sidEntry)
	m.ll.Remove(el)
	delete(m.index, se.gsid)
}

// sidCount reports the number of tracked global_sids (test/introspection).
func (m *MemoryLinkStore) sidCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ll.Len()
}
