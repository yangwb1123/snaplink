// Package health implements the OPTIONAL federation metadata-health lifecycle:
// per-peer observability (last fetch success/failure, consecutive failures,
// last-observed TLS certificate expiry) for the entities a
// federation.TrustChainResolver talks to. It is PURE OBSERVABILITY, wired as
// a decorator around the existing federation.EntityStatementFetcher seam
// (observer.go) — it never alters a fetch's result, so trust-chain validation
// and its fail-closed semantics (AGENTS.md: "Trust-chain FAIL-CLOSED; anchor
// keys NEVER fetched") are completely unaffected. Default-off: a nil
// ConnectionHealth (the zero value of every caller's field) is byte-identical
// to a build without this package.
package health

import "time"

// PeerHealth is the point-in-time observability snapshot for ONE federation
// peer's fetch path. "Peer" is an Entity Identifier: either the leaf/superior
// entity a well-known Entity Configuration was fetched from, or the issuer of
// a Subordinate Statement endpoint (the entity that endpoint BELONGS to, not
// the URL itself — an operator recognizes a peer by its entity id).
type PeerHealth struct {
	// PeerID is the federation Entity Identifier this snapshot describes.
	PeerID string
	// LastSuccessAt is when a fetch from this peer last succeeded. Zero ⇒
	// never observed a success.
	LastSuccessAt time.Time
	// LastFailureAt is when a fetch from this peer last failed. Zero ⇒ never
	// observed a failure.
	LastFailureAt time.Time
	// LastError is the most recent failure's error text (cleared on the next
	// success). Empty when the last attempt succeeded or none was ever made.
	// Operator-only observability (this never reaches a credential-facing
	// wire response), so no oracle-leak concern applies to the raw text.
	LastError string
	// ConsecutiveFailures counts fetch failures since the last success (reset
	// to 0 on RecordSuccess). A rising count is the "this peer is unreachable"
	// signal an operator dashboards on.
	ConsecutiveFailures int
	// CertNotAfter is the NotAfter of the peer's TLS leaf certificate, as
	// observed on the most recent fetch that completed a FRESH TLS handshake
	// (a reused keep-alive connection performs no new handshake, so this
	// value persists across such calls rather than going stale-blank). Zero ⇒
	// never observed (no successful fetch yet, a non-TLS test fetcher, or a
	// fetch that only ever reused an existing connection).
	CertNotAfter time.Time
	// CertObservedAt is when CertNotAfter was captured (the fetch's clock
	// reading), so a consumer can judge how stale the observation is.
	CertObservedAt time.Time
}

// ExpiresWithin reports whether this peer's OBSERVED certificate expires
// within d of now. Returns false when no expiry has ever been observed
// (CertNotAfter zero) — there is nothing to alert on, and an unknown expiry
// must never be treated as "already expired" (that would misreport a healthy,
// merely-unobserved peer as at-risk).
func (p PeerHealth) ExpiresWithin(now time.Time, d time.Duration) bool {
	if p.CertNotAfter.IsZero() {
		return false
	}
	return !p.CertNotAfter.After(now.Add(d))
}

// ConnectionHealth is the SPI federation peer fetch-health is recorded
// against and queried from. Every method MUST be safe for concurrent use: a
// decorator (observer.go) records from the trust-chain resolver's fetch path
// (whatever goroutines drive resolution) while the admin handler queries it.
//
// A nil ConnectionHealth means health tracking is OFF (the default) — callers
// (observer.go's NewObservingFetcher) treat nil as "do not wrap" rather than
// nil-dereferencing, so a build that never wires a ConnectionHealth pays zero
// cost and behaves byte-identically to one without this package.
type ConnectionHealth interface {
	// RecordSuccess records a successful fetch of peerID at checkedAt.
	// certNotAfter is the peer's observed TLS leaf-certificate expiry, or the
	// zero Time when no fresh TLS handshake was observed on this call (see
	// PeerHealth.CertNotAfter) — a zero value here must NOT erase a
	// previously-observed non-zero expiry.
	RecordSuccess(peerID string, checkedAt time.Time, certNotAfter time.Time)
	// RecordFailure records a failed fetch of peerID at checkedAt with errMsg
	// (the coarse failure description — see PeerHealth.LastError for the
	// oracle-safety note). Does not touch any previously-observed CertNotAfter
	// (a failed fetch doesn't erase what a past success last saw).
	RecordFailure(peerID string, checkedAt time.Time, errMsg string)
	// List returns every tracked peer's current snapshot. Implementations
	// should return a stable (e.g. PeerID-sorted) order so repeated admin
	// listings don't jitter.
	List() []PeerHealth
	// ExpiringWithin returns every tracked peer whose observed certificate
	// expiry falls within d of now (PeerHealth.ExpiresWithin), in the same
	// stable order as List. Peers with no observed expiry are excluded —
	// there is nothing to alert on.
	ExpiringWithin(now time.Time, d time.Duration) []PeerHealth
}
