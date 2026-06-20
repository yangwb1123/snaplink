package idp

import (
	"container/list"
	"context"
	"sync"
)

// DefaultSessionIndexSubjects caps how many DISTINCT subjects the in-memory
// SAMLSessionIndex tracks. Past the cap the least-recently-recorded subject is
// evicted whole (all its SP rows) so a flood of distinct subjects can't grow the
// index without bound. The eviction is benign: a dropped subject simply won't
// fan out to its SPs on a later SP-initiated logout (those SP sessions still
// lapse by their own assertion/session expiry) — availability over a perfect
// fan-out, the same posture the replay/pending stores take.
const DefaultSessionIndexSubjects = 10000

// DefaultSessionIndexSPsPerSubject caps how many SP rows a single subject may
// accumulate. A subject realistically federates to a handful of SAML SPs; the
// cap stops an adversary who can drive logins from inflating one subject's row
// list unboundedly. Past the cap the oldest SP row for that subject is dropped.
const DefaultSessionIndexSPsPerSubject = 64

// SAMLSPSession is one record in the SAMLSessionIndex: the subject has (or had)
// an active SAML SSO session at this SP, established when the IdP issued the
// assertion. The fan-out reads these to build a signed LogoutRequest to each
// OTHER SP on an SP-initiated logout.
//
// EVERY field is recorded from SERVER-SIDE state at assertion-issuance — the SP
// entity id, the SP's REGISTERED SLO URL (from Client.Attributes, never request
// input), the SP's binding, the assertion NameID, and the SessionIndex the
// assertion carried — so the fan-out destination + payload are not attacker-
// influenceable (the SLO-URL-only-from-registered-config invariant, the fan-out
// analogue of the ACS/SLO allowlists).
type SAMLSPSession struct {
	// SPEntityID is the SP's SAML entity identifier (Client.Attributes
	// saml_sp_entity_id). The fan-out EXCLUDES the initiating SP by matching on
	// this, and stamps it as the LogoutRequest's audience-equivalent (the SP
	// validates the request Issuer == this IdP, not this field; it is the
	// dedup/exclude key).
	SPEntityID string

	// SPClientID is the resolved sso.Client.ID. The fan-out re-resolves the
	// client fresh from the ClientStore by this id at dispatch time (so a
	// deleted/rotated SP is handled, and the per-tenant signing key is resolved
	// through the SAME signerForClient path issuance used) — the recorded
	// SPSLOUrl/binding are a fast path, the live client is authoritative.
	SPClientID string

	// SPSLOUrl is the SP's REGISTERED Single Logout Service URL captured at
	// issuance (the first AttrSPSLOUrls entry). The fan-out LogoutRequest is sent
	// ONLY here — never a request-supplied destination. Empty ⇒ the SP registered
	// no SLO URL ⇒ it is skipped in the fan-out (nowhere to deliver).
	SPSLOUrl string

	// SPBinding selects how the back-channel LogoutRequest is delivered:
	// BindingRedirect (HTTP-Redirect, a GET with a DETACHED §3.4.4.1 signature —
	// the default and what saml/sp ProcessLogoutRequest validates) or BindingPost
	// (HTTP-POST, an auto-submit form carrying an enveloped-XML-DSig
	// LogoutRequest). Empty ⇒ BindingRedirect. Applies ONLY to the back-channel
	// fan-out (front-channel always uses HTTP-Redirect).
	SPBinding string

	// SPChannel selects WHICH SLO mode this SP participates in:
	// ChannelBackchannel (the default — the IdP delivers the LogoutRequest
	// server-to-server via the async fan-out) or ChannelFrontchannel (the IdP
	// redirects the user's BROWSER through this SP's SLO URL as part of the
	// front-channel chain). Empty ⇒ ChannelBackchannel. The front-channel chain
	// reads THIS to decide which SPs to visit via the browser; the back-channel
	// fan-out handles the rest. Recorded server-side at issuance (from the
	// registered client), never request-influenceable.
	SPChannel string

	// NameID is the assertion subject (== user.ID). The fan-out LogoutRequest's
	// NameID — the SP terminates the matching local session(s) for it.
	NameID string

	// SessionIndex is the SessionIndex value the assertion carried for this SP
	// (currently empty — the IdP does not emit a per-session SessionIndex, so the
	// SP does full-subject logout). Recorded for forward-compatibility: if the
	// IdP later stamps a SessionIndex into assertions, the fan-out request can
	// narrow the SP's termination to that exact session.
	SessionIndex string
}

// Binding identifiers for SAMLSPSession.SPBinding (kept package-local strings,
// not the crewjam binding URIs, so the index has no crewjam coupling).
const (
	// BindingRedirect is the SAML HTTP-Redirect SLO binding (a GET with a
	// detached §3.4.4.1 query-param signature). The default.
	BindingRedirect = "redirect"
	// BindingPost is the SAML HTTP-POST SLO binding (an auto-submit form with an
	// enveloped-XML-DSig LogoutRequest).
	BindingPost = "post"
)

// SAMLSessionIndex records, per subject (NameID), the SAML SPs that subject has
// an active SSO session with, populated at assertion-issuance and read at
// SP-initiated logout to drive the multi-SP SLO fan-out (the SAML analogue of
// the OIDC BCL subject-client index).
//
// It is an INTERFACE so an operator can plug a shared backend (sqlite/redis)
// for a multi-replica IdP later; the default is the bounded in-memory impl
// below (single-replica, the same posture as the PendingStore). A nil index
// disables the fan-out entirely (byte-identical to the pre-fan-out single-SP
// SLO) — the handlers neither record nor read it.
//
// All methods take a context for the shared-backend implementations; the memory
// impl ignores it. Record/Remove/RemoveAll are best-effort from the caller's
// perspective (a record/cleanup failure is logged, never surfaced — it must not
// break the assertion or the logout response).
type SAMLSessionIndex interface {
	// Record adds (or refreshes) the SP session for subject. Recording the same
	// (subject, SPEntityID) again UPDATES the row in place (re-login refreshes
	// the recorded SLO URL/binding/SessionIndex) rather than duplicating it, so
	// the fan-out never double-sends to one SP.
	Record(ctx context.Context, subject string, sess SAMLSPSession) error

	// ListBySubject returns the SP sessions recorded for subject (a copy; the
	// caller may mutate the slice freely). An unknown subject returns nil.
	ListBySubject(ctx context.Context, subject string) ([]SAMLSPSession, error)

	// Remove drops the single (subject, spEntityID) row (e.g. after one SP
	// acknowledges its logout). A no-op when absent.
	Remove(ctx context.Context, subject, spEntityID string) error

	// RemoveAll drops every SP row for subject (the subject is now logged out
	// everywhere). Called after the fan-out so stale subject->SP entries don't
	// leak. A no-op when absent.
	RemoveAll(ctx context.Context, subject string) error
}

// MemorySessionIndex is the default bounded, in-memory SAMLSessionIndex. It is
// a two-level bounded LRU: an outer LRU over subjects (capped at maxSubjects,
// oldest-recorded subject evicted whole), each holding an inner per-subject list
// of SP rows (capped at maxSPsPerSubject, oldest SP row evicted). It mirrors the
// logoutReplayStore/PendingStore discipline exactly — container/list + a map
// index, all access mutex-guarded for concurrent SLO/finish calls — so it can
// never grow without bound under a flood of subjects or SPs.
//
// WHY no TTL on rows: a SAML SP session lives as long as the IdP session that
// minted it; there is no independent expiry to age a row out on. The bounds
// (subject LRU + per-subject SP cap) are the growth guard, and RemoveAll on
// logout is the normal reclamation path. A subject that never logs out is
// eventually LRU-evicted under subject pressure — benign (its SPs lapse by their
// own session expiry).
type MemorySessionIndex struct {
	mu               sync.Mutex
	maxSubjects      int
	maxSPsPerSubject int

	// ll orders subjects by recency of Record (front = oldest, back = newest);
	// index maps subject -> its element. The element value is a *subjectEntry.
	ll    *list.List
	index map[string]*list.Element
}

// subjectEntry holds one subject's SP rows. sps preserves SP insertion order
// (front = oldest) for the per-subject cap; spIndex maps SPEntityID -> element
// so a re-record updates in place.
type subjectEntry struct {
	subject string
	sps     *list.List               // values are *SAMLSPSession
	spIndex map[string]*list.Element // SPEntityID -> element in sps
}

// NewMemorySessionIndex returns a bounded in-memory index. Non-positive bounds
// fall back to the package defaults.
func NewMemorySessionIndex(maxSubjects, maxSPsPerSubject int) *MemorySessionIndex {
	if maxSubjects <= 0 {
		maxSubjects = DefaultSessionIndexSubjects
	}
	if maxSPsPerSubject <= 0 {
		maxSPsPerSubject = DefaultSessionIndexSPsPerSubject
	}
	return &MemorySessionIndex{
		maxSubjects:      maxSubjects,
		maxSPsPerSubject: maxSPsPerSubject,
		ll:               list.New(),
		index:            make(map[string]*list.Element),
	}
}

// interface guard.
var _ SAMLSessionIndex = (*MemorySessionIndex)(nil)

// Record adds or refreshes the SP row for subject. A blank subject or blank SP
// entity id is ignored (nothing meaningful to key on) — never an error, so a
// degenerate assertion can't fail the issue path. Recording moves the subject to
// the most-recently-used end of the subject LRU.
func (m *MemorySessionIndex) Record(_ context.Context, subject string, sess SAMLSPSession) error {
	if subject == "" || sess.SPEntityID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.index[subject]
	if !ok {
		se := &subjectEntry{
			subject: subject,
			sps:     list.New(),
			spIndex: make(map[string]*list.Element),
		}
		el = m.ll.PushBack(se)
		m.index[subject] = el
		// Enforce the subject cap (evict the oldest WHOLE subject).
		for m.ll.Len() > m.maxSubjects {
			m.evictOldestSubjectLocked()
		}
	} else {
		// Touch: most-recently-used.
		m.ll.MoveToBack(el)
	}
	se := el.Value.(*subjectEntry)

	// Copy so the stored row is decoupled from the caller's value.
	row := sess
	if spEl, ok := se.spIndex[sess.SPEntityID]; ok {
		// Update in place (re-login refreshes the recorded SLO URL/binding/index).
		spEl.Value = &row
		se.sps.MoveToBack(spEl)
		return nil
	}
	spEl := se.sps.PushBack(&row)
	se.spIndex[sess.SPEntityID] = spEl
	for se.sps.Len() > m.maxSPsPerSubject {
		m.evictOldestSPLocked(se)
	}
	return nil
}

// ListBySubject returns a COPY of subject's SP rows (caller-mutable). It does NOT
// touch the LRU recency (a read shouldn't keep a logged-out subject pinned).
func (m *MemorySessionIndex) ListBySubject(_ context.Context, subject string) ([]SAMLSPSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.index[subject]
	if !ok {
		return nil, nil
	}
	se := el.Value.(*subjectEntry)
	out := make([]SAMLSPSession, 0, se.sps.Len())
	for e := se.sps.Front(); e != nil; e = e.Next() {
		out = append(out, *e.Value.(*SAMLSPSession))
	}
	return out, nil
}

// Remove drops the single (subject, spEntityID) row. When the subject's last SP
// row is removed the (empty) subject entry is dropped too, so an emptied subject
// doesn't linger in the LRU.
func (m *MemorySessionIndex) Remove(_ context.Context, subject, spEntityID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.index[subject]
	if !ok {
		return nil
	}
	se := el.Value.(*subjectEntry)
	spEl, ok := se.spIndex[spEntityID]
	if !ok {
		return nil
	}
	se.sps.Remove(spEl)
	delete(se.spIndex, spEntityID)
	if se.sps.Len() == 0 {
		m.ll.Remove(el)
		delete(m.index, subject)
	}
	return nil
}

// RemoveAll drops every SP row for subject (the subject is logged out
// everywhere). A no-op when the subject is unknown.
func (m *MemorySessionIndex) RemoveAll(_ context.Context, subject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.index[subject]
	if !ok {
		return nil
	}
	m.ll.Remove(el)
	delete(m.index, subject)
	return nil
}

// evictOldestSubjectLocked drops the least-recently-recorded subject (front of
// the LRU) entirely. Caller holds the mutex.
func (m *MemorySessionIndex) evictOldestSubjectLocked() {
	el := m.ll.Front()
	if el == nil {
		return
	}
	se := el.Value.(*subjectEntry)
	m.ll.Remove(el)
	delete(m.index, se.subject)
}

// evictOldestSPLocked drops the oldest SP row for one subject. Caller holds the
// mutex.
func (m *MemorySessionIndex) evictOldestSPLocked(se *subjectEntry) {
	spEl := se.sps.Front()
	if spEl == nil {
		return
	}
	row := spEl.Value.(*SAMLSPSession)
	se.sps.Remove(spEl)
	delete(se.spIndex, row.SPEntityID)
}

// subjectCount reports the number of tracked subjects (test/introspection).
func (m *MemorySessionIndex) subjectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ll.Len()
}
