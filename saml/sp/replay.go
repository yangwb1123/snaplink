package sp

import (
	"container/list"
	"sync"
	"time"
)

// replayStore is a bounded, in-memory dedup cache of SAML AssertionIDs seen on
// this replica, keyed by the assertion ID, valued by the assertion's
// NotOnOrAfter (so an entry can be pruned once the assertion it guards can no
// longer be validly replayed anyway).
//
// WHY a bespoke store and not the core JTIReplayStore: SAML is a different
// protocol with its own replay token (the AssertionID), and the SP-side dedup
// window is naturally bounded by the assertion lifetime — a small per-replica
// LRU is the right shape, not a shared OAuth jti store. (A multi-replica deploy
// behind a load balancer dedups per replica; an attacker who replays to a
// DIFFERENT replica is still gated by every other validation check —
// signature, audience, recipient, and the short Conditions/SubjectConfirmation
// expiry window — so the in-memory store is a hardening layer over those, the
// same posture the rest of the server takes on replay.)
//
// Eviction is twofold: expired entries are pruned opportunistically on each
// insert (cheap, amortized), and a hard capacity cap evicts the
// least-recently-inserted entry (front of the list) so the map can never grow
// without bound even under a flood of distinct IDs. All access is guarded by a
// single mutex — the store is safe for concurrent ParseAssertion calls.
type replayStore struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List               // front = oldest insert, back = newest
	index    map[string]*list.Element // assertionID -> element in ll
}

// replayEntry is the list-element payload: the assertion ID and the time after
// which it is no longer valid (so the entry is safe to prune).
type replayEntry struct {
	id      string
	expires time.Time
}

// newReplayStore returns a replay store holding up to capacity assertion IDs.
// A non-positive capacity falls back to DefaultReplayStoreSize.
func newReplayStore(capacity int) *replayStore {
	if capacity <= 0 {
		capacity = DefaultReplayStoreSize
	}
	return &replayStore{
		capacity: capacity,
		ll:       list.New(),
		index:    make(map[string]*list.Element),
	}
}

// checkAndRemember atomically reports whether id has been seen before (within
// its validity window) and, if not, records it with the given expiry. It
// returns true when the id is FRESH (not a replay) and false when it is a
// REPLAY. Expired entries are pruned first, so an id whose previous sighting
// has lapsed is treated as fresh again (by then the assertion's own expiry has
// passed, so re-acceptance is moot — the caller's expiry check rejects it).
//
// now is passed in (not read from the clock) so callers share one consistent
// timestamp across all of an assertion's checks and tests stay deterministic.
func (s *replayStore) checkAndRemember(id string, expires, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)

	if _, ok := s.index[id]; ok {
		// Still-live prior sighting ⇒ replay. (pruneExpiredLocked already
		// dropped any lapsed sighting, so a hit here is genuinely live.)
		return false
	}

	el := s.ll.PushBack(&replayEntry{id: id, expires: expires})
	s.index[id] = el

	// Enforce the hard cap: evict oldest inserts until within capacity. This
	// runs after the expiry prune, so it only bites under a genuine flood of
	// distinct, still-valid IDs.
	for s.ll.Len() > s.capacity {
		s.evictOldestLocked()
	}
	return true
}

// pruneExpiredLocked drops every entry whose expiry is at or before now.
// Entries are inserted in time order only loosely (expiry isn't monotonic
// across inserts because different assertions carry different lifetimes), so it
// scans the whole list — bounded by capacity, this stays cheap. Caller holds
// the mutex.
func (s *replayStore) pruneExpiredLocked(now time.Time) {
	var next *list.Element
	for el := s.ll.Front(); el != nil; el = next {
		next = el.Next()
		ent := el.Value.(*replayEntry)
		if !ent.expires.After(now) { // expires <= now
			s.ll.Remove(el)
			delete(s.index, ent.id)
		}
	}
}

// evictOldestLocked removes the front (oldest-inserted) entry. Caller holds the
// mutex and has already confirmed the list is non-empty.
func (s *replayStore) evictOldestLocked() {
	el := s.ll.Front()
	if el == nil {
		return
	}
	ent := el.Value.(*replayEntry)
	s.ll.Remove(el)
	delete(s.index, ent.id)
}

// len reports the current entry count (test + introspection helper).
func (s *replayStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ll.Len()
}
