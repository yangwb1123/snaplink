package sso

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/platform/signingkeys"
)

// clusterState holds cross-replica signing-key aggregation, invalidation-bus degradation, coordinated key-rotation, and cross-replica revocation fields.
type clusterState struct {
	// Opt-in leaderless multi-replica signing-key aggregation. When
	// signingKeyRegistry is wired (WithSharedSigningKeyRegistry), each
	// replica publishes its signing public keys and adopts its peers' keys
	// VERIFY-ONLY, so JWKS + Validate serve the union (see
	// signing_key_aggregation.go). Nil = the feature is entirely off:
	// behavior is byte-identical to a build without it.
	signingKeyRegistry signingkeys.Registry
	replicaID          string
	signingKeyLeaseTTL time.Duration
	// signingKeyAggDegraded is true while the aggregation subscriber is
	// between resubscribe attempts (the registry's Subscribe channel closed
	// while the run context was still live). True ⇒ this replica is no longer
	// adopting peers' newly-rotated keys, so SigningKeyAggregationReady reports
	// not-ready and sso_signing_key_aggregation_up reads 0. Set/cleared only by
	// the single subscriber goroutine; read by /readyz from another goroutine,
	// so it must be atomic. Always false (and never read by a registered check)
	// when no registry is wired.
	signingKeyAggDegraded atomic.Bool
	// signingKeyAggBackoffBase overrides the resubscribe backoff base for
	// tests only (0 ⇒ the production const). Lets a test exercise the
	// resubscribe loop without waiting real seconds. Never set in production.
	signingKeyAggBackoffBase time.Duration

	// invalidationBusDegraded is true while the cross-replica invalidation-bus
	// subscriber is between resubscribe attempts (the bus's Subscribe channel
	// closed while the run context was still live). True ⇒ this replica is no
	// longer APPLYING cross-replica invalidations (tenant suspension, client
	// cache, coordinated key rotation, token revocation), so InvalidationBusReady
	// reports not-ready and sso_invalidation_bus_up reads 0. Mirrors
	// signingKeyAggDegraded exactly: set/cleared only by the single subscriber
	// goroutine; read by /readyz from another goroutine, so it must be atomic.
	// Always false (and never read by a registered check) when no bus is wired.
	invalidationBusDegraded atomic.Bool
	// invalidationBusBackoffBase overrides the bus resubscribe backoff base for
	// tests only (0 ⇒ the production const). Mirrors signingKeyAggBackoffBase.
	// Never set in production.
	invalidationBusBackoffBase time.Duration
	// adoptedPeerKids tracks, per peer replicaID, the kids this replica has
	// adopted from it, so a KeysRemoved (or a shrinking KeysUpserted) drops
	// exactly the keys that replica owns. Guarded by adoptedPeerMu.
	adoptedPeerMu   sync.Mutex
	adoptedPeerKids map[string][]string
	// adoptedKidRefs refcounts each adopted kid by how many DISTINCT live
	// replicas currently announce it. Invariant: a kid is only DropVerifyKey'd
	// from the issuer when this count falls to 0, so dropping one replica
	// (KeysRemoved / shrinking announcement) never evicts a kid that another
	// live replica still announces (fingerprint collision / shared key /
	// misconfig). Guarded by adoptedPeerMu (same lock as adoptedPeerKids, so
	// the per-replica kid set and its refcounts mutate atomically together).
	adoptedKidRefs map[string]int
	// issuerAlgs caches each token issuer's signing alg (from its JWKS at
	// wiring time) so the event handler can route an announced key to the
	// matching-alg issuer without re-querying JWKS per event. Built lazily,
	// once, by ensureIssuerAlgs.
	issuerAlgsOnce sync.Once
	issuerAlgs     map[string]string

	// coordinatedKeyRotation opts this Server into deadline-coordinated
	// same-kid signing-key rotation cutover (WithCoordinatedKeyRotation). When
	// true AND an invalidation bus is wired, a local rotation PUBLISHES a
	// cluster.KindSigningKeyRotation Event (the demoted + new kid + a
	// now+GracePeriod retire deadline) and a received such Event DEFERS the
	// demoted kid's retirement to that deadline (only ever widening the verify
	// window — see deferSigningKeyRetire) while adopting the new kid verify-only
	// at once. False (the default) ⇒ the publish side is a no-op and a received
	// KindSigningKeyRotation Event is ignored, so behavior is byte-identical to
	// a build without the feature. The bus carries the Event regardless, but no
	// armed subscriber acts on it — safe for a mixed-armed cluster.
	coordinatedKeyRotation bool
	// pendingSigningRetires tracks the deferred-retire timers this replica has
	// scheduled in response to coordinated-rotation Events, keyed by the demoted
	// kid, so a clean shutdown (the subscriber ctx cancel) stops every pending
	// retire (no leaked goroutine) and a duplicate Event for the same kid never
	// stacks two timers. pendingSigningRetireDeadlines holds each timer's
	// currently-promised target instant so an EXTEND only ever pushes it LATER
	// (the fail-safe never-shorten rule). Both guarded by pendingSigningRetireMu.
	pendingSigningRetireMu        sync.Mutex
	pendingSigningRetires         map[string]*pendingRetire
	pendingSigningRetireDeadlines map[string]time.Time

	// crossReplicaRevocation opts this Server into cross-replica access-token
	// revocation propagation (WithCrossReplicaRevocation). When true AND an
	// invalidation bus is wired, a local /token/revoke that hit at least one
	// issuer PUBLISHES a cluster.KindTokenRevoked Event, and a received such
	// Event ADDS the carried token to this replica's per-issuer deny-set WITHOUT
	// re-publishing (the adopt path is local-only — no broadcast loop). False
	// (the default) ⇒ the publish side is a no-op and a received
	// KindTokenRevoked Event is ignored, so revocation stays per-process,
	// byte-identical to a build without the feature.
	crossReplicaRevocation bool
	// coordinatedRetireMinDeferralOverride / MaxOverride let tests shrink the
	// clamp floor/ceiling so the retire fires in milliseconds instead of the
	// 1-minute production floor. 0 ⇒ the production const. Never set in
	// production (no Option wires them — only the test seam does).
	coordinatedRetireMinDeferralOverride time.Duration
	coordinatedRetireMaxDeferralOverride time.Duration
}
