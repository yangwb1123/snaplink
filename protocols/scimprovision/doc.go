// Package scimprovision implements OUTBOUND SCIM 2.0 provisioning: the push
// counterpart of protocols/scim's inbound receiver. Where protocols/scim lets
// an upstream IdP (Okta, Azure AD, ...) provision INTO this server, this
// package lets this server push user/group lifecycle changes OUT to a
// downstream SCIM-compliant application — the same role Okta/Azure AD play
// for the apps THEY provision. Together the two packages let this server act
// as a SCIM hub: receive from one upstream, fan out to N downstream apps.
//
// # Why a separate package, not more of protocols/scim
//
// protocols/scim is at its frozen per-directory file-count ceiling
// (directory_fanout_test.go dirFileCountExemptions) — the ceiling may only
// shrink, so new files land in a fresh sibling package instead. Reuse still
// happens at the TYPE level: SCIMProvisioner and HTTPSCIMProvisioner exchange
// scim.Resource / scim.GroupResource, the exact wire types the receiver
// parses/emits (scim.UserToResource / scim.RoleToGroup are exported for this
// purpose) — there is exactly one SCIM schema in the codebase, not a parallel
// one for the push direction.
//
// # How it taps the audit pipeline (same seam as CAEP / the webhook engine)
//
//   - Sink composes as an audit.Sink exactly like protocols/caep's
//     Transmitter and platform/lifecycle/webhook.Engine: wired via
//     sso.WithSCIMProvisioner, the same AddSink/MultiSink seam, so it taps
//     the existing user/group lifecycle events with no change to how they
//     are recorded elsewhere (interfaces/admin, interfaces/grpcserver/
//     grpcadmin, protocols/scim's own receiver all already emit
//     EventAdminUser{Created,Updated,Deleted,EmailChanged,
//     LifecycleChanged} and EventAdminRole{Added,Updated,Removed} — see
//     event_types_admin.go for the taxonomy this Sink reacts to).
//   - Retry reuses platform/audit/auditsink.RetryingSink UNCHANGED (the same
//     primitive platform/audit's own audit.webhook config section and
//     platform/lifecycle/webhook.Engine use), wrapping a small per-event
//     delivery adapter rather than duplicating backoff logic.
//   - A delivery that exhausts its retry budget is recorded into a
//     platform/lifecycle/webhook.DeadLetterStore (the SAME storage
//     abstraction the generic webhook engine uses for its own dead-letter
//     queue) — reused for the queryable/replayable diagnostic ring, not
//     duplicated.
//
// # Vocabulary is fixed, not operator-configurable
//
// Unlike platform/lifecycle/webhook (an intentionally GENERIC fan-out of any
// audit.EventType an operator subscribes to), this Sink's vocabulary is the
// FIXED set of user/group lifecycle events it knows how to translate into
// SCIM operations (DefaultEventTypes) — there is no "subscribe to arbitrary
// events" surface, because a SCIM Resource is a specific, opinionated shape
// this package would not know how to render from an unrelated event.
//
// # Downstream identity resolution
//
// A downstream SCIM service assigns its OWN resource ids on create — this
// server's user/role ids are not assumed to share that id space. Every
// outbound Resource/GroupResource carries ExternalID set to this server's own
// id, and HTTPSCIMProvisioner resolves "does this already exist downstream"
// via GET .../Users?filter=externalId eq "..." (RFC 7644 §3.4.2.2) before a
// replace/delete — the same filter idiom protocols/scim's own /Users list
// endpoint speaks, resolved FRESH on every call (no cache), mirroring CAEP's
// "resolve fresh" philosophy. A downstream service that does not support
// filtering on externalId is a known limitation of this reference
// implementation (see http_provisioner.go); operators integrating such a
// target should implement SCIMProvisioner directly instead.
//
// Notably, THIS SDK's own protocols/scim receiver is one such target for
// Groups specifically: a SCIM Group maps onto a permissions.Role, which has
// no externalId column (unlike core.User, which does), so a hub-to-hub
// deployment pushing group membership into ANOTHER instance of this same
// server will re-create a new downstream group on every push rather than
// updating the same one. Membership still lands correctly (nothing is
// lost), it just isn't deduplicated across repeated pushes — Users are
// unaffected (core.User.ExternalID round-trips losslessly).
//
// # Group membership is full-state reconciliation, not a delta
//
// The audit vocabulary this Sink taps records "a group's role/membership
// changed," not a member-level add/remove delta (EventAdminRoleUpdated fires
// identically for a displayName rename and a single membership edit). Rather
// than invent metadata plumbing across every existing emission site to carry
// a diff, ReplaceGroupMembers always pushes the group's CURRENT full
// membership (resolved fresh from the permissions.Provider at delivery time)
// — idempotent and correct under retry/replay/reordering, at the cost of one
// PATCH replace per group event rather than a minimal per-member PATCH op.
//
// # Known gap: gRPC-direct role assignment
//
// PermissionAdminService.AssignRoles/UnassignRoles (interfaces/grpcserver/
// grpcadmin) record EventAdminRoleAssigned/Unassigned carrying only
// "<client_id>/<user_id>" — no role code — so this Sink cannot resolve WHICH
// group changed from those two event types alone and does not subscribe to
// them. Membership changes made through the SCIM /Groups receiver (the
// primary "hub" use case) fire EventAdminRoleAdded/Updated/Removed with a
// resolvable group id and are fully covered.
//
// # Opt-in / fail-open
//
// Wire via sso.WithSCIMProvisioner; unwired ⇒ no sink tap, zero outbound SCIM
// traffic — byte-identical to a build without this feature (config.SCIM.Push
// defaults to Enabled: false). A delivery failure can never affect the
// triggering operation (fail-open, the same contract as CAEP broadcast and
// the generic webhook engine).
package scimprovision
