package idp

import (
	"container/list"
	"sync"
	"time"
)

// DefaultLogoutReplayStoreSize bounds the in-memory LogoutRequest-ID dedup cache
// when Deps.LogoutReplayStoreSize is unset. A SP-initiated SLO directory is
// small and each entry lives only one freshness window, so 10k is ample without
// unbounded growth — the same sizing as the SP-side assertion replay store.
const DefaultLogoutReplayStoreSize = 10000

// DefaultLogoutRequestWindow is the freshness window for an inbound SP-initiated
// LogoutRequest (Fix 2): a LogoutRequest whose IssueInstant is older than this
// is rejected, and a validated request's ID is deduped for this long. 5m mirrors
// the OAuth/DPoP iat-window posture (SAML Bindings mandates no specific value)
// and is the TTL for the replay store.
const DefaultLogoutRequestWindow = 5 * time.Minute

// logoutMaxClockSkew is the small future-skew allowance on a LogoutRequest's
// IssueInstant (one further in the future is a clock-forward forgery, rejected).
const logoutMaxClockSkew = 1 * time.Minute

// logoutReplayStore is a bounded, in-memory dedup cache of SAML LogoutRequest
// IDs seen on this replica, keyed by the request ID, valued by the time after
// which the request can no longer be fresh (so the entry is safe to prune). It
// MIRRORS the SP-side assertion replayStore (saml/sp/replay.go) exactly — a
// small per-replica LRU bounded by the freshness window, the right shape for a
// SAML replay token, not a shared OAuth jti store.
//
// WHY a separate store and not the assertion replayStore: the IdP package has no
// assertion-consumer replay store (it ISSUES assertions); the LogoutRequest ID
// is its own ID space. A multi-replica deploy dedups per replica; an attacker
// replaying to a DIFFERENT replica is still gated by the IssueInstant freshness
// window (the captured request ages out), so the in-memory store is a hardening
// layer over that bound — the same posture the SP side takes on assertion
// replay.
//
// Eviction is twofold: expired entries pruned opportunistically on each insert,
// and a hard capacity cap evicts the least-recently-inserted entry, so the map
// can never grow without bound under a flood of distinct IDs. All access is
// mutex-guarded — safe for concurrent SLO calls.
type logoutReplayStore struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List               // front = oldest insert, back = newest
	index    map[string]*list.Element // request ID -> element in ll
}

// logoutReplayEntry is the list-element payload: the request ID and the time
// after which it is no longer valid (safe to prune).
type logoutReplayEntry struct {
	id      string
	expires time.Time
}

// newLogoutReplayStore returns a store holding up to capacity LogoutRequest IDs.
// A non-positive capacity falls back to DefaultLogoutReplayStoreSize.
func newLogoutReplayStore(capacity int) *logoutReplayStore {
	if capacity <= 0 {
		capacity = DefaultLogoutReplayStoreSize
	}
	return &logoutReplayStore{
		capacity: capacity,
		ll:       list.New(),
		index:    make(map[string]*list.Element),
	}
}

// checkAndRemember atomically reports whether id is FRESH (not previously seen
// within its validity window) and, if so, records it with the given expiry. It
// returns true when fresh and false when it is a REPLAY. Expired entries are
// pruned first. now is passed in so callers share one consistent timestamp and
// tests stay deterministic.
func (s *logoutReplayStore) checkAndRemember(id string, expires, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)

	if _, ok := s.index[id]; ok {
		return false // still-live prior sighting ⇒ replay
	}

	el := s.ll.PushBack(&logoutReplayEntry{id: id, expires: expires})
	s.index[id] = el

	for s.ll.Len() > s.capacity {
		s.evictOldestLocked()
	}
	return true
}

// pruneExpiredLocked drops every entry whose expiry is at or before now. Caller
// holds the mutex.
func (s *logoutReplayStore) pruneExpiredLocked(now time.Time) {
	var next *list.Element
	for el := s.ll.Front(); el != nil; el = next {
		next = el.Next()
		ent := el.Value.(*logoutReplayEntry)
		if !ent.expires.After(now) { // expires <= now
			s.ll.Remove(el)
			delete(s.index, ent.id)
		}
	}
}

// evictOldestLocked removes the front (oldest-inserted) entry. Caller holds the
// mutex and has confirmed the list is non-empty.
func (s *logoutReplayStore) evictOldestLocked() {
	el := s.ll.Front()
	if el == nil {
		return
	}
	ent := el.Value.(*logoutReplayEntry)
	s.ll.Remove(el)
	delete(s.index, ent.id)
}

// len reports the current entry count (test + introspection helper).
func (s *logoutReplayStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ll.Len()
}
