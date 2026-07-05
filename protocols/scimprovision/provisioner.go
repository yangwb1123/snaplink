package scimprovision

import (
	"context"
	"errors"

	"github.com/snaplink/sso/protocols/scim"
)

// SCIMProvisioner pushes user/group lifecycle changes to a downstream SCIM
// 2.0 application (RFC 7644) that this server acts as the CLIENT for — the
// outbound counterpart of protocols/scim's inbound receiver. Every method
// takes and returns the SAME wire types the receiver already parses/emits
// (scim.Resource, scim.GroupResource), so there is exactly one SCIM schema
// in the codebase.
//
// Implementations MUST be safe for concurrent use: Sink calls these from a
// per-event goroutine (mirroring platform/lifecycle/webhook.Engine.deliver),
// and a single Sink may have several deliveries in flight at once.
type SCIMProvisioner interface {
	// CreateUser provisions a new user downstream (POST /Users, RFC 7644
	// §3.3). user.ExternalID identifies this server's own user id to the
	// downstream service (RFC 7643 §3.1) — the returned Resource's ID is
	// downstream-assigned and does not need to be persisted by the caller;
	// subsequent calls re-resolve the downstream id via ExternalID.
	CreateUser(ctx context.Context, user scim.Resource) (scim.Resource, error)

	// ReplaceUser overwrites the downstream user identified by
	// user.ExternalID (PUT /Users/{id}, RFC 7644 §3.5.1). A downstream
	// service that has never seen this user (feature just enabled, or the
	// user predates it) is NOT an error the caller must special-case —
	// implementations may self-heal by creating it instead; see
	// HTTPSCIMProvisioner.
	ReplaceUser(ctx context.Context, user scim.Resource) (scim.Resource, error)

	// DeleteUser removes the downstream user identified by externalID
	// (DELETE /Users/{id}). Idempotent: a downstream 404 is treated as
	// success — the end state ("the user is not there") is already
	// achieved.
	DeleteUser(ctx context.Context, externalID string) error

	// ReplaceGroupMembers reconciles the downstream group identified by
	// group.ExternalID to EXACTLY group.Members (SCIM PATCH members
	// "replace", RFC 7644 §3.5.2) — full-state reconciliation rather than
	// an add/remove delta (see doc.go for why). A downstream service that
	// has never seen this group self-heals by creating it (POST /Groups).
	ReplaceGroupMembers(ctx context.Context, group scim.GroupResource) (scim.GroupResource, error)

	// DeleteGroup removes the downstream group identified by externalID
	// (DELETE /Groups/{id}). Idempotent, same 404 contract as DeleteUser.
	DeleteGroup(ctx context.Context, externalID string) error
}

// ErrNotConfigured is returned by Sink construction helpers when no
// SCIMProvisioner was wired — mirrors core.ErrWebhookNotConfigured's "opt-in
// feature not wired" convention.
var ErrNotConfigured = errors.New("scimprovision: no SCIMProvisioner configured")
