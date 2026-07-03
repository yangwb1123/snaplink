package core

import (
	"context"
	"time"
)

// AdminToken records an issued admin bearer token with its metadata.
// Used by the admin API to list and revoke active tokens.
type AdminToken struct {
	// ID is the opaque token identifier (not the full token value).
	ID string `json:"id"`

	// Label is an operator-supplied human name (e.g. "ci-cd pipeline").
	Label string `json:"label,omitempty"`

	// AdminID is the actor who requested the token.
	AdminID string `json:"admin_id,omitempty"`

	// Scopes granted to this token (e.g. ["admin:read", "admin:write"]).
	Scopes []string `json:"scopes,omitempty"`

	// CreatedAt is when the token was issued.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the token expires. Zero = never.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// LastUsedAt is the last time this token was used.
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// AdminTokenStore persists and manages admin bearer tokens. Without
// this store, admin tokens can only be revoked by clearing the
// underlying session or temp-token store — there's no visibility
// into which tokens exist or when they expire.
type AdminTokenStore interface {
	// Record persists a new admin token record.
	Record(ctx context.Context, token AdminToken) error

	// GetByID returns a single token record by ID. Returns
	// ErrTokenNotFound when the ID is unknown or the token was
	// revoked.
	GetByID(ctx context.Context, id string) (AdminToken, error)

	// List returns all non-expired admin tokens, newest first.
	// When adminID is non-empty, filters to tokens issued by
	// that admin.
	List(ctx context.Context, adminID string) ([]AdminToken, error)

	// Revoke marks a token as revoked (idempotent). Returns
	// nil even when the ID is unknown (anti-enumeration).
	Revoke(ctx context.Context, id string) error

	// Touch updates the LastUsedAt timestamp for a token.
	Touch(ctx context.Context, id string) error
}

// AdminScope is the privilege level of a break-glass admin session.
// Least privilege is the default: readonly grants NO impersonation
// session at all, so no bearer exists that could act as the user.
type AdminScope string

const (
	// AdminScopeReadonly permits viewing the target user's state through
	// the existing admin:read endpoints only. No impersonation session is
	// ever minted for a readonly grant — mutation as the user is
	// structurally impossible, not merely policy-checked.
	AdminScopeReadonly AdminScope = "readonly"
	// AdminScopeImpersonate mints a marked target-user session
	// (SessionKindAdminImpersonation) the support admin uses as bearer.
	AdminScopeImpersonate AdminScope = "impersonate"
	// AdminScopeEscalate is impersonate for change operations (helpdesk
	// "do X for the user"). The minted session is identical to
	// impersonate — the target user's own permission boundary still
	// applies; break-glass NEVER widens it.
	AdminScopeEscalate AdminScope = "escalate"
)

// AdminSessionStatus is the lifecycle state of a break-glass admin session.
type AdminSessionStatus string

const (
	AdminSessionPending AdminSessionStatus = "pending"
	AdminSessionActive  AdminSessionStatus = "active"
	AdminSessionRevoked AdminSessionStatus = "revoked"
	AdminSessionExpired AdminSessionStatus = "expired"
)

// SessionKindAdminImpersonation marks a Session minted under a break-glass
// admin session, so downstream consumers (audit enrichment, session lists)
// can distinguish "the user logged in" from "support acted as the user".
const SessionKindAdminImpersonation = "admin_impersonation"

// AdminSession is a break-glass (emergency support) grant: a bounded,
// audited window in which AdminUserID may act on behalf of TargetUserID.
// SOC 2 CC6.1/CC6.2, PCI DSS 7.2, and HIPAA 164.312(a) evidence chain.
type AdminSession struct {
	ID           string `json:"id"`
	AdminUserID  string `json:"admin_user_id"`
	TargetUserID string `json:"target_user_id"`
	TenantID     string `json:"tenant_id,omitempty"`

	// Reason is the mandatory ticket/incident reference. Creation without
	// it is rejected — an unexplained break-glass is an audit finding.
	Reason string `json:"reason"`

	Scope     AdminScope         `json:"scope"`
	Status    AdminSessionStatus `json:"status"`
	ExpiresAt time.Time          `json:"expires_at"`
	CreatedAt time.Time          `json:"created_at"`

	// ApprovedBy is empty until a second admin approves a pending grant.
	// The approver MUST differ from AdminUserID (no self-approval).
	ApprovedBy string `json:"approved_by,omitempty"`

	// AuditID links to the admin_break_glass_created audit event so an
	// auditor can walk from the grant to its evidence record directly.
	AuditID string `json:"audit_id,omitempty"`

	// SessionIDs are the impersonation sessions minted under this grant.
	// Revocation and expiry cascade SessionManager.Destroy over them —
	// a derived session never outlives its break-glass window.
	SessionIDs []string `json:"session_ids,omitempty"`
}

// IsExpired reports whether the break-glass window has closed.
func (a *AdminSession) IsExpired() bool { return time.Since(a.ExpiresAt) > 0 }

// BreakGlassStore persists break-glass admin sessions. Reads are lazily
// expiry-aware: a pending/active record past ExpiresAt is reported with
// AdminSessionExpired so no caller ever observes a stale-active grant,
// even between sweeper passes.
type BreakGlassStore interface {
	// Create persists a new break-glass record.
	Create(ctx context.Context, s AdminSession) error

	// Get returns one record by ID (lazy expiry applied). Returns
	// ErrAdminSessionNotFound when the ID is unknown.
	Get(ctx context.Context, id string) (AdminSession, error)

	// List returns the pending + active (non-expired) records, newest
	// first. Revoked and expired records are excluded.
	List(ctx context.Context) ([]AdminSession, error)

	// Approve atomically transitions a pending record to active, stamping
	// ApprovedBy and attaching the impersonation sessionIDs minted for the
	// activation. MUST reject approverID == AdminUserID with
	// ErrAdminSessionSelfApproval and a non-pending (incl. lazily expired)
	// record with ErrAdminSessionNotPending — the store is the atomic
	// authority even when handlers pre-check.
	Approve(ctx context.Context, id, approverID string, sessionIDs []string) (AdminSession, error)

	// Revoke marks a record revoked and returns it (with SessionIDs, so
	// the caller can cascade). Idempotent on an already revoked/expired
	// record; unknown ID returns ErrAdminSessionNotFound.
	Revoke(ctx context.Context, id string) (AdminSession, error)

	// DeleteExpired removes every record past ExpiresAt and returns the
	// ones that were still pending/active — the sweeper cascades session
	// destruction + emits the expiry audit event for exactly those.
	// Already-revoked records past ExpiresAt are garbage-collected
	// silently (their cascade ran at revoke time).
	DeleteExpired(ctx context.Context) ([]AdminSession, error)
}
