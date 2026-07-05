// Cross-tenant B2B collaboration: tenant A can register a lightweight
// "guest" pointer to a user who natively belongs to tenant B — WITHOUT
// duplicating that user's record anywhere — and tenant B's user can then
// exchange their home-tenant token for one scoped to tenant A (see
// internal/handler/tokengrant/token_exchange.go's
// tokExEnforceTenantCollaboration, the RFC 8693 resolution path this backs).
// Lives in this package (rather than its own domains/tenantcollab) because
// domains/ is at its frozen per-directory subdir-fanout ceiling
// (directory_fanout_test.go) and this feature is tenant-scoped by nature.
//
// Two DISTINCT, cooperating records model the whole feature:
//
//   - [TenantCollaboration] is the tenant-to-tenant TRUST relationship: a
//     guest tenant explicitly opts in to accepting guest tokens whose home is
//     a named other tenant. Absence of a row is NO TRUST — the default,
//     fail-closed stance (AGENTS.md §3 Tenant & Residency): a tenant must
//     EXPLICITLY collaborate with another before anything crosses the
//     boundary. This is the allow-list; there is no deny-list, no wildcard,
//     and no transitive trust (A trusts B and B trusts C does NOT imply A
//     trusts C).
//
//   - [GuestRecord] is the per-user membership pointer: it registers that one
//     specific external subject (identified by the RAW subject id their home
//     tenant's client issues them under) may act as a guest of one specific
//     guest tenant, carrying guest-scoped Roles/Attributes. It does NOT copy
//     the user's password, profile, or any other home-tenant data — the
//     pointer is the entire footprint.
//
// Both are REQUIRED for a cross-tenant token-exchange to succeed: a
// TenantCollaboration with no matching GuestRecord (or vice versa) still
// denies. This mirrors domains/tokenexchange's Policy SPI discipline: the
// gate is opt-in (nil stores are a no-op, byte-identical to a build without
// this feature) and fail-closed (a store error or a missing record both
// collapse to the SAME denial the token-exchange grant already returns for
// every other cause — no oracle on WHICH check failed).
//
// memory.ExternalUserStore + memory.CollaborationStore are the in-process
// reference implementations; any Store backend a deployment needs (sqlite,
// etcd, ...) implements the same two interfaces.
package tenant

import (
	"context"
	"errors"
	"time"
)

// GuestRecord is the lightweight cross-tenant membership pointer: tenant
// GuestTenantID has registered ExternalSubjectID — a user who natively
// belongs to HomeTenantID — as a guest, without duplicating the user record.
// (GuestTenantID, ExternalSubjectID) is the identity of the record: at most
// one guest registration per subject per guest tenant, mirroring
// domains/tenant's core.TenantMembership (TenantID, UserID) discipline — Add
// upserts on that pair rather than creating a duplicate.
type GuestRecord struct {
	// GuestTenantID is the tenant granting guest access — the tenant whose
	// resources ExternalSubjectID may now reach.
	GuestTenantID string `json:"guest_tenant_id"`
	// HomeTenantID is the tenant ExternalSubjectID natively belongs to. Kept
	// on the record (not just implied) so the token-exchange gate can
	// cross-check it against the subject_token's independently-resolved home
	// tenant — a mismatch here is treated as tampering/misconfiguration, not
	// a trusted guest hop (see tokExAuthorizeGuestHop).
	HomeTenantID string `json:"home_tenant_id"`
	// ExternalSubjectID is the RAW subject id (core.TokenClaims.Subject) the
	// home tenant's issuer stamps on this user's tokens — NOT a locally
	// duplicated user record's ID. The guest tenant never sees or stores
	// anything else about this user.
	ExternalSubjectID string `json:"external_subject_id"`
	// Roles are guest-scoped entitlements: when non-empty, they further
	// NARROW (never widen) the scopes the cross-tenant exchange may grant —
	// a guest is virtually never entitled to everything a native member of
	// the guest tenant is. Empty = no additional narrowing beyond the
	// exchange's existing scope resolution.
	Roles []string `json:"roles,omitempty"`
	// Attributes are opaque guest-specific metadata (e.g. a display name or
	// external directory reference) an operator's own tooling may want
	// alongside the pointer. Not interpreted by the exchange gate itself.
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

// Validate sanity-checks a GuestRecord before persistence. All three key
// fields are required so the record can never resolve to an ambiguous or
// wildcard guest hop.
func (g *GuestRecord) Validate() error {
	if g.GuestTenantID == "" {
		return errors.Join(ErrInvalidGuestRecord, errors.New("guest_tenant_id required"))
	}
	if g.HomeTenantID == "" {
		return errors.Join(ErrInvalidGuestRecord, errors.New("home_tenant_id required"))
	}
	if g.ExternalSubjectID == "" {
		return errors.Join(ErrInvalidGuestRecord, errors.New("external_subject_id required"))
	}
	if g.GuestTenantID == g.HomeTenantID {
		// Not a cross-tenant hop at all — the token-exchange gate never
		// consults this store for a same-tenant exchange, so a record like
		// this could never match anything and only invites confusion.
		return errors.Join(ErrInvalidGuestRecord, errors.New("guest_tenant_id and home_tenant_id must differ"))
	}
	return nil
}

// ExternalUserStore persists [GuestRecord] pointers. When nil (not wired),
// the cross-tenant B2B collaboration gate is a complete no-op — byte-
// identical to a build without this feature. memory.ExternalUserStore ships
// as the in-process reference implementation.
type ExternalUserStore interface {
	// Add upserts the record keyed by (GuestTenantID, ExternalSubjectID): a
	// first call registers the guest, a subsequent call for the same pair
	// replaces its HomeTenantID/Roles/Attributes. Idempotent re-registration,
	// same discipline as core.TenantUserStore.Add.
	Add(ctx context.Context, g *GuestRecord) error

	// Remove deletes the (guestTenantID, externalSubjectID) registration.
	// Idempotent: removing a registration that does not exist returns nil
	// (no oracle on whether the subject was ever registered).
	Remove(ctx context.Context, guestTenantID, externalSubjectID string) error

	// Get returns the registration for (guestTenantID, externalSubjectID), or
	// ErrNoGuestRecord when the subject is not registered as a guest of that
	// tenant.
	Get(ctx context.Context, guestTenantID, externalSubjectID string) (*GuestRecord, error)

	// ListByGuestTenant returns every guest registered in guestTenantID (the
	// guest tenant's full external roster).
	ListByGuestTenant(ctx context.Context, guestTenantID string) ([]*GuestRecord, error)
}

// ErrNoGuestRecord is the sentinel Get returns when (guestTenantID,
// externalSubjectID) has no registration. Callers MUST NOT distinguish "no
// such tenant" from "no such subject" from "subject not registered" — all
// collapse to this single response (mirrors core.ErrNoMembership).
var ErrNoGuestRecord = errors.New("tenant: no such guest record")

// ErrInvalidGuestRecord wraps GuestRecord.Validate failures.
var ErrInvalidGuestRecord = errors.New("tenant: invalid guest record")

// TenantCollaboration is the explicit, opt-in tenant-to-tenant trust
// relationship: GuestTenantID has decided to accept guest tokens whose home
// is HomeTenantID. Absence of a row is NO TRUST — the default, fail-closed
// stance (AGENTS.md §3): a tenant must EXPLICITLY opt in to accepting
// another tenant's users as guests. There is no wildcard/deny-list form and
// no transitivity: trust is a direct, named, one-way edge.
type TenantCollaboration struct {
	// GuestTenantID is the tenant DECIDING to trust (the one accepting guest
	// tokens).
	GuestTenantID string `json:"guest_tenant_id"`
	// HomeTenantID is the tenant BEING trusted (the one whose users may
	// arrive as guests).
	HomeTenantID string    `json:"home_tenant_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// Validate sanity-checks a TenantCollaboration before persistence.
func (c *TenantCollaboration) Validate() error {
	if c.GuestTenantID == "" {
		return errors.Join(ErrInvalidCollaboration, errors.New("guest_tenant_id required"))
	}
	if c.HomeTenantID == "" {
		return errors.Join(ErrInvalidCollaboration, errors.New("home_tenant_id required"))
	}
	if c.GuestTenantID == c.HomeTenantID {
		return errors.Join(ErrInvalidCollaboration, errors.New("guest_tenant_id and home_tenant_id must differ"))
	}
	return nil
}

// ErrInvalidCollaboration wraps TenantCollaboration.Validate failures.
var ErrInvalidCollaboration = errors.New("tenant: invalid tenant collaboration")

// CollaborationStore persists [TenantCollaboration] trust rows. When nil (not
// wired), the cross-tenant B2B collaboration gate is a complete no-op —
// byte-identical to a build without this feature (same contract as a nil
// ExternalUserStore; BOTH must be wired for the gate to activate).
// memory.CollaborationStore ships as the in-process reference implementation.
type CollaborationStore interface {
	// Put upserts the trust row keyed by (GuestTenantID, HomeTenantID).
	Put(ctx context.Context, c *TenantCollaboration) error

	// Remove revokes the trust row. Idempotent: removing a relationship that
	// does not exist returns nil.
	Remove(ctx context.Context, guestTenantID, homeTenantID string) error

	// IsTrusted reports whether guestTenantID currently trusts homeTenantID.
	// Returns (false, nil) — NOT an error — when no such row exists; this is
	// the expected, common "no trust" answer, not a failure. A non-nil error
	// means the backend itself failed (fail-closed: the token-exchange gate
	// treats an error identically to an explicit false).
	IsTrusted(ctx context.Context, guestTenantID, homeTenantID string) (bool, error)

	// ListByGuestTenant returns every tenant guestTenantID currently trusts.
	ListByGuestTenant(ctx context.Context, guestTenantID string) ([]*TenantCollaboration, error)
}
