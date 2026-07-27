// Package signingkeys defines the opt-in shared registry through which the
// replicas of a leaderless multi-replica SSO deployment exchange their
// signing PUBLIC keys.
//
// The problem it solves. In a leaderless deployment each replica holds its
// OWN in-process signing key with a distinct kid (sharing one kid needs a
// shared KMS key — out of scope here). A token minted by replica A and then
// presented — to an RP, /introspect, or /userinfo — on replica B fails:
// B's JWKS and verify-set lack A's kid, so B can neither serve the key to
// an RP nor verify the token itself.
//
// The fix this package enables. Each replica PUBLISHES its signing public
// keys (never private material) to a shared Registry; every replica ADOPTS
// its peers' public keys as VERIFY-ONLY into the matching-alg issuer. The
// union is then served by JWKS() and accepted by Validate() on every node,
// while each replica still SIGNS only with its own private key. No shared
// private key, no leader election, no rotation coordination.
//
// The contract is deliberately best-effort and fail-open, mirroring
// cluster.Bus: a dropped or stale announcement only narrows a replica's
// verify-set back toward its own keys (today's behavior) — it never causes
// a wrong answer, because adoption only ever ADDS verify-only keys whose
// signatures are still cryptographically checked.
package signingkeys

import (
	"context"

	"github.com/yangwb1123/snaplink/shared/core"
)

// EventType discriminates what changed in a Registry announcement so a
// subscriber knows whether to adopt or drop the carried keys.
type EventType string

const (
	// EventKeysUpserted signals that a replica published (or renewed) its
	// set of signing public keys. Subscribers adopt every carried key into
	// the matching-alg issuer as verify-only.
	EventKeysUpserted EventType = "keys_upserted"

	// EventKeysRemoved signals that a replica's announcement expired or was
	// withdrawn. Subscribers drop every key they previously adopted from
	// that replica. The carried Keys MAY be empty — ReplicaID is the
	// authoritative identifier for what to drop.
	EventKeysRemoved EventType = "keys_removed"
)

// Announcement is one replica's published set of signing public keys.
// Keys carries the SAME wire shape an issuer already emits from JWKS()
// ([]core.JWK) so there is exactly one public-key encoding in the codebase;
// only public material ever appears here. LeaseSeconds is the announcer's
// requested lease — a backend with real lease expiry (etcd) drops the
// announcement after that long without a renewing Publish; the in-process
// memory peer keeps the latest announcement until the next Publish replaces
// it (single process, no expiry needed).
type Announcement struct {
	ReplicaID    string
	Keys         []core.JWK
	LeaseSeconds int64
}

// Event is one change signal fanned to subscribers. Announcement.ReplicaID
// identifies the affected replica; for EventKeysRemoved the Keys slice MAY
// be empty.
type Event struct {
	Type         EventType
	Announcement Announcement
}

// Registry fans signing-public-key announcements out to every replica.
//
// Publish is lease-backed and idempotent: a replica re-calls it to renew
// its lease and to reflect a key rotation (the announcement replaces the
// replica's prior one wholesale). List returns the union of every currently
// live replica's announcement — used once at startup to seed the local
// verify-set before the subscription stream takes over. Subscribe returns a
// receive-only stream that closes when ctx is cancelled or the Registry is
// closed. Implementations MUST be safe for concurrent use.
type Registry interface {
	Publish(ctx context.Context, ann Announcement) error
	List(ctx context.Context) ([]Announcement, error)
	Subscribe(ctx context.Context) (<-chan Event, error)
	Close() error
}
