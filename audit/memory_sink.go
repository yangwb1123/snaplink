package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
)

// DefaultMemoryCapacity is the ring-buffer size used when NewMemorySink is
// called with capacity <= 0.
const DefaultMemoryCapacity = 10_000

// MemorySink stores events in a fixed-size in-memory ring buffer. When the
// buffer is full, the oldest events are evicted. Suitable for development
// and lightweight deployments; swap for a persistent Sink in production.
type MemorySink struct {
	mu       sync.RWMutex
	capacity int
	buf      []*Event
	head     int  // index of oldest event
	full     bool // ring has wrapped at least once
	byID     map[string]*Event
}

func NewMemorySink(capacity int) *MemorySink {
	if capacity <= 0 {
		capacity = DefaultMemoryCapacity
	}
	return &MemorySink{
		capacity: capacity,
		buf:      make([]*Event, capacity),
		byID:     make(map[string]*Event, capacity),
	}
}

func (m *MemorySink) Record(_ context.Context, e *Event) error {
	if e.ID == "" {
		e.ID = newEventID()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.full {
		// Evict the slot we're about to overwrite.
		if old := m.buf[m.head]; old != nil {
			delete(m.byID, old.ID)
		}
	}
	m.buf[m.head] = e
	m.byID[e.ID] = e
	m.head = (m.head + 1) % m.capacity
	if !m.full && m.head == 0 {
		m.full = true
	}
	return nil
}

func (m *MemorySink) Get(_ context.Context, id string) (*Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrEventNotFound
	}
	return e, nil
}

func (m *MemorySink) Query(_ context.Context, q Query) ([]*Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matches := make([]*Event, 0, q.NormalizedLimit())
	m.forEachNewestFirst(func(e *Event) bool {
		if q.Match(e) {
			matches = append(matches, e)
		}
		return true
	})

	// Sort newest first so pagination is stable.
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].Timestamp.After(matches[j].Timestamp)
	})

	start := min(q.Offset, len(matches))
	end := min(start+q.NormalizedLimit(), len(matches))
	return matches[start:end], nil
}

// Facets aggregates per-dimension counts over every event matching q.
// It honors q's time range + non-dimension filters via Query.Match
// (Limit/Offset are ignored — facets describe the whole filtered window).
// Implements the optional FacetQuerier extension.
func (m *MemorySink) Facets(_ context.Context, q Query) (*Facets, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	f := newFacets()
	m.forEachNewestFirst(func(e *Event) bool {
		if q.Match(e) {
			f.add(e)
		}
		return true
	})
	return f, nil
}

// forEachNewestFirst walks the buffer from newest to oldest. visit returns
// false to stop early.
func (m *MemorySink) forEachNewestFirst(visit func(*Event) bool) {
	n := m.capacity
	if !m.full {
		n = m.head
	}
	for i := 0; i < n; i++ {
		idx := (m.head - 1 - i + m.capacity) % m.capacity
		e := m.buf[idx]
		if e == nil {
			continue
		}
		if !visit(e) {
			return
		}
	}
}

// Len returns the number of events currently stored.
func (m *MemorySink) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.full {
		return m.capacity
	}
	return m.head
}

func newEventID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
