package core

import (
	"context"
	"errors"
	"time"
)

// Invitation is a single-use, emailed credential that grants org (tenant)
// membership to a recipient. An org/admin mints one bound to a target email,
// tenant, and the TenantRole to grant on accept; the opaque Token is delivered
// out-of-band (email) and redeemed exactly once. Redemption is what creates the
// membership edge, so the token IS a live credential — it MUST NOT be serialized
// in any API response (the Token json tag is "-"); only its non-secret metadata
// (tenant, email, role, expiry) is safe to expose to an admin roster view.
type Invitation struct {
	Token     string     `json:"-"` // opaque token value (store primary key); NEVER serialized — it is a live credential
	TenantID  string     `json:"tenant_id"`
	Email     string     `json:"email"`
	Role      TenantRole `json:"role"` // org standing to grant on accept
	ExpiresAt time.Time  `json:"expires_at"`
}

// IsExpired reports whether the invitation has passed its expiry.
func (i *Invitation) IsExpired() bool { return time.Since(i.ExpiresAt) > 0 }

// InvitationStore persists single-use org-invitation tokens. When nil (not
// wired), org invitations are disabled — byte-identical to a build without them.
// memory + sqlite peers ship in defaultimpl + defaultimpl/sqlite. Mirrors the
// other single-use credential stores: Issue then a destructive Consume.
type InvitationStore interface {
	// Issue stores a new invitation (keyed by inv.Token).
	Issue(ctx context.Context, inv *Invitation) error

	// Consume atomically retrieves AND deletes the invitation. Missing, expired,
	// or already-consumed all return ErrInvitationNotFound (single response —
	// oracle-safe; the accept handler collapses all three to one response). The
	// single-use delete is what stops a replayed invitation.
	Consume(ctx context.Context, token string) (*Invitation, error)

	// ListByTenant returns the pending invitations for an org (admin roster view).
	// Implementations MAY include expired rows; callers MUST NOT surface the token
	// value (the Token json tag enforces this on the wire).
	ListByTenant(ctx context.Context, tenantID string) ([]*Invitation, error)
}

// ErrInvitationNotFound is the sentinel Consume returns when an invitation is
// missing, expired, or already consumed. Callers MUST collapse all three to a
// single wire response (anti-enumeration / oracle-safe).
var ErrInvitationNotFound = errors.New("sso: invitation not found or expired")
