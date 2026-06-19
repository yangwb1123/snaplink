package idp

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// logoutChainStore is a bounded, in-memory, single-use store of in-flight
// front-channel logout chains. Consume is DELETE-on-read (a chain id is usable
// exactly once per hop; the next hop re-inserts under a FRESH id), expired
// entries are pruned opportunistically on Insert, and a hard capacity cap evicts
// the oldest insert. All access is mutex-guarded; safe for concurrent chains.
// It mirrors the PendingStore discipline exactly.
//
// Memory-only this phase (a load-balanced IdP front-channel chain hops through
// the browser; a /continue landing on a different replica finds no chain →
// saml_request_invalid, which is strictly safe — it can't forge a logout there
// either). A shared sqlite/redis peer is the natural multi-replica follow-up.
type logoutChainStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	capacity int
	ll       *list.List               // front = oldest insert, back = newest
	index    map[string]*list.Element // state id -> element
}

type logoutChainEntry struct {
	id    string
	state logoutChainState
}

// newLogoutChainStore returns a chain store with the given TTL + capacity.
// Non-positive values fall back to DefaultLogoutChainTTL / DefaultLogoutChainCapacity.
func newLogoutChainStore(ttl time.Duration, capacity int) *logoutChainStore {
	if ttl <= 0 {
		ttl = DefaultLogoutChainTTL
	}
	if capacity <= 0 {
		capacity = DefaultLogoutChainCapacity
	}
	return &logoutChainStore{
		ttl:      ttl,
		capacity: capacity,
		ll:       list.New(),
		index:    make(map[string]*list.Element),
	}
}

// insert stores state under a freshly generated, cryptographically random chain
// id and returns that id. ExpiresAt is set to now()+ttl when the caller left it
// zero. Expired entries are pruned first, then the hard cap is enforced. now is
// passed in so a chain's hops share one clock (deterministic tests).
func (s *logoutChainStore) insert(state logoutChainState, now time.Time) (string, error) {
	id, err := newChainID()
	if err != nil {
		return "", err
	}
	if state.ExpiresAt.IsZero() {
		state.ExpiresAt = now.Add(s.ttl)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)

	el := s.ll.PushBack(&logoutChainEntry{id: id, state: state})
	s.index[id] = el

	for s.ll.Len() > s.capacity {
		s.evictOldestLocked()
	}
	return id, nil
}

// peek looks up the chain for id WITHOUT removing it, returning a COPY and true
// only when a LIVE entry exists. It is used to resolve the acknowledging SP's
// cert so the inbound LogoutResponse signature can be validated BEFORE the chain
// is consumed — so a FORGED LogoutResponse (rejected) neither advances the chain
// nor burns a legitimate chain's single-use state. Unknown/expired ⇒ false
// (oracle-safe). Expired entries are pruned opportunistically.
func (s *logoutChainStore) peek(id string, now time.Time) (logoutChainState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)

	el, ok := s.index[id]
	if !ok {
		return logoutChainState{}, false
	}
	ent := el.Value.(*logoutChainEntry)
	if !ent.state.ExpiresAt.After(now) {
		return logoutChainState{}, false
	}
	// Return a copy whose Remaining slice is independent (the caller mutates its
	// own Remaining when advancing; the stored entry must stay intact until
	// consume).
	st := ent.state
	st.Remaining = append([]chainSP(nil), ent.state.Remaining...)
	return st, true
}

// consume atomically looks up + REMOVES the chain for id (single-use), returning
// it and true only when a LIVE entry exists. An unknown id, an expired entry, or
// an already-consumed id all return (logoutChainState{}, false) — the caller
// collapses every false to the SAME oracle-safe saml_request_invalid. Concurrent
// consumers of the same id: exactly ONE gets true (the single-use guarantee).
func (s *logoutChainStore) consume(id string, now time.Time) (logoutChainState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prune first so an expired entry is indistinguishable from an unknown one.
	s.pruneExpiredLocked(now)

	el, ok := s.index[id]
	if !ok {
		return logoutChainState{}, false
	}
	ent := el.Value.(*logoutChainEntry)
	if !ent.state.ExpiresAt.After(now) {
		s.ll.Remove(el)
		delete(s.index, id)
		return logoutChainState{}, false
	}
	s.ll.Remove(el)
	delete(s.index, id)
	return ent.state, true
}

func (s *logoutChainStore) pruneExpiredLocked(now time.Time) {
	var next *list.Element
	for el := s.ll.Front(); el != nil; el = next {
		next = el.Next()
		ent := el.Value.(*logoutChainEntry)
		if !ent.state.ExpiresAt.After(now) { // ExpiresAt <= now
			s.ll.Remove(el)
			delete(s.index, ent.id)
		}
	}
}

func (s *logoutChainStore) evictOldestLocked() {
	el := s.ll.Front()
	if el == nil {
		return
	}
	ent := el.Value.(*logoutChainEntry)
	s.ll.Remove(el)
	delete(s.index, ent.id)
}

// len reports the current chain count (test + introspection helper).
func (s *logoutChainStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ll.Len()
}

// newChainID returns a 256-bit URL-safe random chain id. 32 bytes of crypto/rand
// is unguessable — an attacker cannot fabricate a valid chain id to hijack or
// advance a logout chain at /saml/slo/continue without having gone through the
// IdP's chain start.
func newChainID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
