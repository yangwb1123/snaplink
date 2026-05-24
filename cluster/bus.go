// Package cluster defines the cross-replica coordination primitive used
// to keep per-replica caches consistent in a multi-node deployment.
//
// Several server caches are per-replica TTL caches (tenant-suspension
// state, discovery snapshot, JWKS). On a single node an admin mutation
// invalidates the local cache directly; across N replicas the other
// nodes only converge after their own TTL elapses — a small but real
// window during which a just-suspended tenant or just-rotated key is
// still honored elsewhere. The Bus closes that window: a mutating node
// Publishes an Event, every node Subscribes and clears the matching
// local cache on receipt.
//
// The contract is deliberately best-effort, not a durable queue: a
// dropped Event degrades a replica to its existing TTL fallback (today's
// behavior), never to a wrong answer. Invalidation is idempotent and
// order-independent — a cleared cache simply repopulates from the
// authoritative store on the next read — so the Bus needs no delivery
// or ordering guarantees to be correct.
package cluster

import "context"

// EventKind discriminates what a node should invalidate on receipt.
// The set is open by design: new coordinated caches (key rotation,
// token revocation, discovery reload) add a kind here and a dispatch
// arm on the subscriber side without touching the Bus contract.
type EventKind string

const (
	// KindTenantSuspension signals that a tenant's suspended/active
	// status changed; subscribers drop the cached status for Event.Key
	// (the tenant ID) so the next validate re-reads the tenant store.
	KindTenantSuspension EventKind = "tenant_suspension"
)

// Event is one coordination signal. Key identifies the affected entity
// (e.g. a tenant ID); Payload carries optional kind-specific detail and
// may be nil. Events are values — backends copy them across the wire.
type Event struct {
	Kind    EventKind         `json:"kind"`
	Key     string            `json:"key"`
	Payload map[string]string `json:"payload,omitempty"`
}

// Bus fans coordination Events out to every subscribing replica.
//
// Publish is fire-and-forget from the caller's perspective: it returns
// an error only for transport-level failures (which callers log and
// continue past, since the local mutation already succeeded). Subscribe
// returns a receive-only stream that closes when ctx is cancelled or the
// Bus is closed. Implementations MUST be safe for concurrent use.
type Bus interface {
	Publish(ctx context.Context, evt Event) error
	Subscribe(ctx context.Context) (<-chan Event, error)
	Close() error
}
