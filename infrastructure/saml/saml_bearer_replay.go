package saml

import (
	"container/list"
	"sync"
	"time"
)

// DefaultBearerReplayStoreSize bounds the in-memory RFC 7522 bearer-assertion
// replay-dedup cache when BearerAssertionValidatorConfig.ReplayStoreSize is
// unset. Mirrors saml/sp's DefaultReplayStoreSize: a bearer-grant client base
// is small and each entry lives only one assertion lifetime, so 10k is ample
// without unbounded growth.
const DefaultBearerReplayStoreSize = 10000

// bearerReplayStore is a bounded, in-memory dedup cache of RFC 7522 bearer
// AssertionIDs this validator has processed, keyed by the assertion ID,
// valued by the time after which the assertion can no longer possibly be
// valid (so the entry is safe to prune). It is the token-grant analogue of
// saml/sp's replayStore / saml/idp's logoutReplayStore -- same shape
// (container/list + map, mutex-guarded, capacity-capped, opportunistic
// expiry prune on every insert) -- kept as its own small type here rather
// than imported from saml/sp or saml/idp: this root package deliberately
// does not import either subpackage (BearerAssertionValidator is a
// standalone RFC 7522 grant-input validator, not an SP/IdP SSO participant).
type bearerReplayStore struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List               // front = oldest insert, back = newest
	index    map[string]*list.Element // assertion ID -> element in ll
}

// bearerReplayEntry is the list-element payload: the assertion ID and the
// time after which it is no longer valid (so the entry is safe to prune).
type bearerReplayEntry struct {
	id      string
	expires time.Time
}

// newBearerReplayStore returns a store holding up to capacity assertion IDs.
// A non-positive capacity falls back to DefaultBearerReplayStoreSize.
func newBearerReplayStore(capacity int) *bearerReplayStore {
	if capacity <= 0 {
		capacity = DefaultBearerReplayStoreSize
	}
	return &bearerReplayStore{
		capacity: capacity,
		ll:       list.New(),
		index:    make(map[string]*list.Element),
	}
}

// CheckAndRemember atomically reports whether id has been seen before (within
// its validity window) and, if not, records it with the given expiry. It
// returns true when id is FRESH (not a replay) and false when it is a REPLAY.
// Expired entries are pruned first, so an id whose previous sighting has
// lapsed is treated as fresh again -- by then the assertion's own Conditions/
// SubjectConfirmationData expiry has passed too (the caller's own time checks
// already rejected it before this is ever reached), so re-acceptance is moot.
func (s *bearerReplayStore) CheckAndRemember(id string, expires, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)

	if _, ok := s.index[id]; ok {
		return false // still-live prior sighting => replay
	}

	el := s.ll.PushBack(&bearerReplayEntry{id: id, expires: expires})
	s.index[id] = el

	for s.ll.Len() > s.capacity {
		s.evictOldestLocked()
	}
	return true
}

// pruneExpiredLocked drops every entry whose expiry is at or before now.
// Caller holds the mutex.
func (s *bearerReplayStore) pruneExpiredLocked(now time.Time) {
	var next *list.Element
	for el := s.ll.Front(); el != nil; el = next {
		next = el.Next()
		ent := el.Value.(*bearerReplayEntry)
		if !ent.expires.After(now) { // expires <= now
			s.ll.Remove(el)
			delete(s.index, ent.id)
		}
	}
}

// evictOldestLocked removes the front (oldest-inserted) entry. Caller holds
// the mutex and has confirmed the list is non-empty.
func (s *bearerReplayStore) evictOldestLocked() {
	el := s.ll.Front()
	if el == nil {
		return
	}
	ent := el.Value.(*bearerReplayEntry)
	s.ll.Remove(el)
	delete(s.index, ent.id)
}

// len reports the current entry count (test + introspection helper).
func (s *bearerReplayStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ll.Len()
}
