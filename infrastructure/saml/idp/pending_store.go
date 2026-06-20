package idp

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// DefaultPendingTTL bounds how long a pending SP-initiated AuthnRequest stays
// resumable between /saml/sso (store) and /saml/sso/finish (consume). 10
// minutes spans a normal interactive login (the user authenticates at
// /auth/login in between) without keeping stale correlation state around.
const DefaultPendingTTL = 10 * time.Minute

// DefaultPendingCapacity caps the in-memory pending store so a flood of
// AuthnRequests can't grow it without bound; the oldest insert is evicted past
// the cap (the same hard-cap discipline as the SP replay store).
const DefaultPendingCapacity = 10000

// PendingRequest is the correlation state captured at /saml/sso when an SP
// initiates SSO, resumed at /saml/sso/finish after the user authenticates. It
// is keyed by a SERVER-GENERATED opaque id (the saml_request_id threaded
// through /auth/login as state), NOT by any SP-controlled value.
//
// SECURITY: ACSURL is the SP's REGISTERED Assertion Consumer Service URL
// (validated against the SP's allowlist at /saml/sso), so the eventual
// assertion is POSTed only where the SP pre-registered — the response builder
// uses THIS field, never a value taken from the AuthnRequest at finish time.
type PendingRequest struct {
	// SPClientID is the resolved sso.Client.ID of the SP (the bridge between
	// the SAML entityID and the server's client/tenant model). The finish
	// handler resolves the per-tenant signing key from this.
	SPClientID string

	// SPEntityID is the SP's SAML entity identifier (the AuthnRequest Issuer);
	// stamped into the assertion AudienceRestriction.
	SPEntityID string

	// ACSURL is the SP's REGISTERED ACS URL (allowlist-validated at /saml/sso).
	// The assertion's SubjectConfirmation Recipient + the auto-POST form action
	// are set from THIS — never from the response/finish input.
	ACSURL string

	// RequestID is the SP's AuthnRequest ID, echoed back as the Response /
	// SubjectConfirmation InResponseTo (SP-side correlation).
	RequestID string

	// RelayState is the SP's opaque RelayState, echoed back verbatim in the
	// auto-POST form (SAML requires it returned unchanged).
	RelayState string

	// NameIDFormat is the requested NameID format (from the SP's registered
	// config / the AuthnRequest NameIDPolicy), or empty for the default.
	NameIDFormat string

	// ExpiresAt is the absolute deadline after which this pending entry is
	// pruned and Consume treats it as unknown.
	ExpiresAt time.Time
}

// PendingStore is a bounded, in-memory, single-use store of pending
// AuthnRequests. Consume is DELETE-on-read (a pending id is usable exactly
// once), expired entries are pruned opportunistically on Insert, and a hard
// capacity cap evicts the oldest insert. All access is mutex-guarded; the
// store is safe for concurrent Insert/Consume.
//
// Memory-only this phase. A SQLite peer (mirroring the DELETE … RETURNING
// single-use atomic the rest of the server uses) is the natural follow-up for
// multi-replica IdP deploys; until then a load-balanced IdP correlates per
// replica (an attacker hitting a different replica's finish endpoint with a
// captured saml_request_id finds no pending entry → saml_request_invalid,
// which is strictly safe — it can't forge a session there either).
type PendingStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	capacity int
	ll       *list.List               // front = oldest insert, back = newest
	index    map[string]*list.Element // saml_request_id -> element
}

type pendingEntry struct {
	id  string
	req PendingRequest
}

// NewPendingStore returns a pending store with the given TTL + capacity.
// Non-positive values fall back to DefaultPendingTTL / DefaultPendingCapacity.
func NewPendingStore(ttl time.Duration, capacity int) *PendingStore {
	if ttl <= 0 {
		ttl = DefaultPendingTTL
	}
	if capacity <= 0 {
		capacity = DefaultPendingCapacity
	}
	return &PendingStore{
		ttl:      ttl,
		capacity: capacity,
		ll:       list.New(),
		index:    make(map[string]*list.Element),
	}
}

// Insert stores req under a freshly generated, cryptographically random
// saml_request_id and returns that id. ExpiresAt is set to now()+ttl when the
// caller left it zero (the common path); a caller may set a shorter explicit
// deadline. Expired entries are pruned first, then the hard cap is enforced.
func (s *PendingStore) Insert(req PendingRequest) (string, error) {
	id, err := newPendingID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = now.Add(s.ttl)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)

	el := s.ll.PushBack(&pendingEntry{id: id, req: req})
	s.index[id] = el

	for s.ll.Len() > s.capacity {
		s.evictOldestLocked()
	}
	return id, nil
}

// Consume atomically looks up + REMOVES the pending entry for id (single-use),
// returning it and true only when a LIVE entry exists. An unknown id, an
// expired entry, or an already-consumed id all return (PendingRequest{}, false)
// — the caller collapses every false to the SAME oracle-safe
// saml_request_invalid, so a probe can't distinguish them.
func (s *PendingStore) Consume(id string) (PendingRequest, bool) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Prune first so an expired entry is treated identically to an unknown one
	// (no "expired vs never-existed" timing or presence oracle).
	s.pruneExpiredLocked(now)

	el, ok := s.index[id]
	if !ok {
		return PendingRequest{}, false
	}
	ent := el.Value.(*pendingEntry)
	// Defensive: an entry surviving the prune is live, but re-check the deadline
	// in case ttl semantics ever change.
	if !ent.req.ExpiresAt.After(now) {
		s.ll.Remove(el)
		delete(s.index, id)
		return PendingRequest{}, false
	}
	s.ll.Remove(el)
	delete(s.index, id)
	return ent.req, true
}

// pruneExpiredLocked drops every entry whose deadline is at or before now.
// Caller holds the mutex.
func (s *PendingStore) pruneExpiredLocked(now time.Time) {
	var next *list.Element
	for el := s.ll.Front(); el != nil; el = next {
		next = el.Next()
		ent := el.Value.(*pendingEntry)
		if !ent.req.ExpiresAt.After(now) { // ExpiresAt <= now
			s.ll.Remove(el)
			delete(s.index, ent.id)
		}
	}
}

// evictOldestLocked removes the front (oldest-inserted) entry. Caller holds the
// mutex and has confirmed the list is non-empty.
func (s *PendingStore) evictOldestLocked() {
	el := s.ll.Front()
	if el == nil {
		return
	}
	ent := el.Value.(*pendingEntry)
	s.ll.Remove(el)
	delete(s.index, ent.id)
}

// len reports the current entry count (test + introspection helper).
func (s *PendingStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ll.Len()
}

// newPendingID returns a 256-bit URL-safe random correlation id. 32 bytes of
// crypto/rand is unguessable — an attacker cannot fabricate a valid pending id
// to drive /saml/sso/finish without having gone through /saml/sso.
func newPendingID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
