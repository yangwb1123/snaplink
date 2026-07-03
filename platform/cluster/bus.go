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

	// KindDiscoveryReload signals that discovery-affecting state changed
	// (a client's scopes/registration), so subscribers drop their cached
	// discovery snapshot + rendered documents and recompute on the next
	// request. Event.Key is unused (the discovery doc is global, derived
	// from the union of all clients), so it is empty.
	KindDiscoveryReload EventKind = "discovery_reload"

	// KindAuthzPolicyChange signals that a client's role DEFINITIONS
	// changed (a role added/updated/removed or its menus reset), so
	// subscribers drop the cached authorization policy bundle for
	// Event.Key (the client ID) and re-render it from the permissions
	// provider on the next sidecar pull. Best-effort like every kind: a
	// dropped Event only degrades a replica to its bundle-cache TTL.
	KindAuthzPolicyChange EventKind = "authz_policy_change"

	// KindTenantResidency signals that a tenant's data-residency policy
	// (HomeRegion / AllowedRegions / EnforceWrites) changed; subscribers
	// drop the cached residency policy for Event.Key (the tenant ID) so the
	// next enforcement check re-reads the tenant store. Mirrors
	// KindTenantSuspension: best-effort, a dropped Event only degrades a
	// replica to its residency-cache TTL.
	KindTenantResidency EventKind = "tenant.residency"

	// KindClientChange signals that a client's metadata changed (an admin
	// Create/Update/Delete/RotateSecret or a DCR register/update/delete), so
	// subscribers drop the cached client entity for Event.Key (the client ID)
	// from the opt-in per-login ClientStore cache and re-read the
	// authoritative store on the next Get. Best-effort like every kind: a
	// dropped Event only degrades a replica to its client-cache TTL. The
	// credential path (ValidateSecret) bypasses that cache entirely, so this
	// Event only affects metadata freshness, never a credential decision.
	KindClientChange EventKind = "client.change"

	// KindConnectionChange signals that an enterprise connection was created,
	// updated, or deleted via the admin API. Subscribers must reload their
	// local connection config on the next home-realm-discovery lookup so
	// stale IdP configs (including compromised ones that were deleted) are not
	// served to users whose requests land on a peer replica. Best-effort:
	// a dropped Event only prolongs the stale-config window by one cache TTL.
	KindConnectionChange EventKind = "connection.change"

	// KindSigningKeyRotation signals that the publishing replica rotated its
	// signing key: a NEW kid is now the active signer and an OLD (demoted) kid
	// is verify-only, scheduled for retirement at a wall-clock deadline. The
	// receiver's job is NOT to invalidate a cache but to COORDINATE the cutover
	// — keep the demoted kid verifiable AT LEAST until the carried deadline (so
	// a token signed under it on the rotating replica never hits a premature
	// "unknown kid" 401 on a lagging one), and adopt the new kid verify-only
	// immediately so the new-signer side propagates without waiting for the
	// replica's own JWKS poll / aggregation cycle. Event.Key is unused (the
	// rotation is per-issuer, addressed by the carried kids, not a single entity
	// id). The detail rides Event.Payload (Meta*Kid / MetaRetireDeadline):
	// changing the Event STRUCT shape would break mixed-version peers, but a
	// new kind + new payload keys are ignored gracefully by an older
	// applyInvalidation default arm. Best-effort like every kind, and FAIL-SAFE
	// by construction: a dropped or garbage Event only ever DELAYS the local
	// retire (the per-replica grace-window fallback still runs), never drops the
	// old kid early — it can only WIDEN the verify window, never narrow it.
	KindSigningKeyRotation EventKind = "signing_key_rotation"

	// KindTokenRevoked signals that an access token was revoked on the
	// publishing replica (via /token/revoke). Subscribers ADD the carried
	// token to their own per-issuer in-process revocation deny-set, so a
	// token revoked on one replica stops validating on every armed replica
	// instead of only the one that handled the revoke. The deny-set is
	// per-process (the JWT issuers' `revoked` map) — Redis peers cover
	// session/refresh/etc. but NOT this set, and CAEP pushes to external RPs,
	// not to the server's own replicas, so this Event is the only cross-replica
	// propagation for the access-token deny-set.
	//
	// Event.Key is unused (the token is the addressed entity, carried in
	// Payload rather than Key so a token never lands in a log/metric label).
	// The detail rides Event.Payload (MetaRevokedToken + MetaRevokedExp).
	//
	// ADDITIVE + FAIL-OPEN by construction: applying it only ever ADDS a token
	// to a deny-set (more tokens rejected, never fewer). A dropped/garbage Event
	// just means that replica doesn't revoke that token — it degrades to today's
	// per-replica behavior (the token still expires on its own exp), NEVER to a
	// valid token being wrongly rejected. Trusted exactly like every other kind
	// (mesh-internal bus; same trust model as KindTenantSuspension). Best-effort
	// like every kind.
	KindTokenRevoked EventKind = "token_revoked"

	// KindConfigDigest carries this replica's current effective-config
	// digest (platform/configaudit.Digest output) so peers can compare it to
	// their own and flag configuration drift. UNLIKE every other kind,
	// applying it invalidates nothing — the comparison is purely REPORT-ONLY
	// (an audit event + a metric bump on mismatch, never a behavior change),
	// so a garbage or missing payload is simply ignored. Event.Key carries
	// the PUBLISHING replica's ID (not an entity ID, unlike every other
	// kind) so a receiver can attribute a mismatch to a specific peer;
	// Event.Payload carries the digest itself (MetaConfigDigest). Off by
	// default — only wired when platform/configaudit.DriftDetector.Run is
	// started with a positive interval (config/config_configaudit.go).
	KindConfigDigest EventKind = "config_digest"
)

// Token-revocation Event.Payload keys (KindTokenRevoked). Map keys on the
// existing Event.Payload map[string]string — NOT new Event struct fields — so a
// mixed-version peer that doesn't know the kind drops the whole Event at its
// default arm and the keys never matter to it.
const (
	// MetaRevokedToken is the FULL access token to add to the local deny-set.
	// Carried in Payload (not Key) so it never reaches a log/metric label.
	MetaRevokedToken = "revoked_token"

	// MetaRevokedExp is the revoked token's `exp` (unix SECONDS, decimal
	// string), so the receiver records an exp-bounded deny-set entry that
	// self-prunes after the token would have expired anyway. Optional/advisory:
	// an absent or unparsable value just lets the receiver re-derive exp from
	// the token itself (its own Revoke decodes the payload), so the adopt still
	// works — the receiver never trusts this value over the token's own claim.
	MetaRevokedExp = "revoked_exp"
)

// Signing-key-rotation Event.Payload keys (KindSigningKeyRotation). These are
// map keys on the existing Event.Payload map[string]string — NOT new Event
// struct fields — so a mixed-version peer that doesn't know the kind drops the
// whole Event at its default arm and the keys never matter to it.
const (
	// MetaOldKid is the demoted (now verify-only) signing kid whose retirement
	// the receiver must DEFER until MetaRetireDeadline.
	MetaOldKid = "old_kid"

	// MetaNewKid is the freshly-promoted active signing kid the receiver should
	// adopt verify-only immediately (so peers validate new-kid tokens at once).
	MetaNewKid = "new_kid"

	// MetaRetireDeadline is the wall-clock instant (unix NANOSECONDS, decimal
	// string) at or after which the receiver may retire MetaOldKid. It is the
	// publisher's now + GracePeriod. The receiver clamps a garbage/far-future
	// value to a sane ceiling but NEVER retires before it — the deadline can
	// only push the local retire LATER than the per-replica grace fallback.
	MetaRetireDeadline = "retire_deadline"

	// MetaNewJWK is the new active key's public material as a JSON-encoded
	// core.JWK string, so the receiver can adopt it verify-only WITHOUT fetching
	// it (the kid alone is not enough to install a verify key). Optional: absent
	// or undecodable ⇒ the receiver simply skips the new-kid adoption (the
	// leaderless-aggregation path, if wired, still propagates it) and STILL
	// applies the old-kid retire deferral — the fail-safe half is independent of
	// the new-key half.
	MetaNewJWK = "new_jwk"
)

// MetaConfigDigest is the Event.Payload key for the sha256 hex digest
// carried by a KindConfigDigest Event (platform/configaudit.Digest output).
const MetaConfigDigest = "config_digest"

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
