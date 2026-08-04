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

const (
	// BreakGlassImpersonationClientID is the synthetic OAuth client_id stamped
	// on a break-glass impersonation access token. The emergency-support flow
	// has no real relying party, but RFC 9068 §2.2 requires a client_id; a
	// reserved URN keeps the token self-describing (unmistakably break-glass
	// minted, never a real client) and cannot collide with any operator-
	// registered client id — so the anti-abuse marking survives on the wire.
	BreakGlassImpersonationClientID = "urn:snaplink:break-glass"
	// AMRBreakGlass is the RFC 8176 authentication-method marker stamped on an
	// impersonation token's amr, so it can NEVER be read as the target user
	// having authenticated themselves (the distinguishability invariant).
	AMRBreakGlass = "break_glass"
	// ClaimBreakGlassAdminSessionID / ClaimBreakGlass are the impersonation
	// token's Extra-claim keys carrying the SOC 2 evidence chain (which grant,
	// and that this bearer is a break-glass credential) so "who acted as whom,
	// under which grant" rides the credential into every downstream audit.
	ClaimBreakGlassAdminSessionID = "break_glass_admin_session_id"
	ClaimBreakGlass               = "break_glass"
	// MetaBreakGlassAdminID is the audit Event.Metadata key naming the admin
	// acting through a break-glass impersonation bearer on the REQUEST path. The
	// event's ActorID stays the TARGET subject (the bearer authenticates as the
	// target); this key + ClaimBreakGlassAdminSessionID + ClaimBreakGlass restore
	// the admin+target SOC 2 evidence chain on EVERY action, not just the mint.
	MetaBreakGlassAdminID = "break_glass_admin_id"
)

// IsBreakGlassImpersonationClaims reports whether validated token claims carry
// the break-glass live-impersonation marker. Belt-and-suspenders: ANY surviving
// marker (the durable break_glass_admin_session_id evidence claim, the break_glass
// boolean claim, or amr=break_glass) is sufficient — a break-glass impersonation
// bearer must be recognizable even if one marker is stripped. Used to (1) REFUSE
// the RFC 8693 token-exchange laundering path (the token is NON-DELEGABLE) and
// (2) enrich request-path audit attribution with the acting admin.
func IsBreakGlassImpersonationClaims(c *TokenClaims) bool {
	if c == nil {
		return false
	}
	if c.Extra[ClaimBreakGlassAdminSessionID] != "" || c.Extra[ClaimBreakGlass] == "true" {
		return true
	}
	for _, m := range c.AMR {
		if m == AMRBreakGlass {
			return true
		}
	}
	return false
}

// BreakGlassActor is the acting-admin attribution carried on the request context
// while an action is performed under a break-glass impersonation bearer, so the
// audit Recorder can stamp the admin + grant id onto every event the action
// produces (the target subject remains the event's primary ActorID).
type BreakGlassActor struct {
	AdminID        string
	AdminSessionID string
}

type breakGlassActorKey struct{}

// ContextWithBreakGlassActor stamps the break-glass acting-admin attribution onto
// ctx. The bearer-validation seam calls this when a request presents a break-glass
// impersonation token; audit.Recorder.Record reads it back.
func ContextWithBreakGlassActor(ctx context.Context, a BreakGlassActor) context.Context {
	return context.WithValue(ctx, breakGlassActorKey{}, a)
}

// BreakGlassActorFromContext returns the break-glass acting-admin attribution
// stamped by ContextWithBreakGlassActor, or ok=false for an ordinary request.
func BreakGlassActorFromContext(ctx context.Context) (BreakGlassActor, bool) {
	a, ok := ctx.Value(breakGlassActorKey{}).(BreakGlassActor)
	return a, ok
}

// ImpersonationCredential is the marked, TTL-bounded bearer minted by the
// break-glass POST .../{id}/impersonate endpoint. Its access token
// authenticates as the TARGET user (sub = AdminSession.TargetUserID) — NEVER
// the admin — so it flows through the exact same authorization checks any user
// token does and grants no admin scope (NON-BYPASS). It carries the RFC 8693
// `act` claim naming the admin plus ClaimBreakGlassAdminSessionID, and its
// lifetime is clamped to the grant window (ExpiresAt <= AdminSession.ExpiresAt).
type ImpersonationCredential struct {
	Token     string    `json:"access_token"`
	TokenType string    `json:"token_type"`
	ExpiresIn int       `json:"expires_in"`
	ExpiresAt time.Time `json:"-"`
	// SessionID is the marked (Kind=admin_impersonation) session this bearer is
	// anchored to via its `sid` claim. Empty when no SessionManager was wired.
	SessionID string `json:"session_id,omitempty"`
}

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

	// ImpersonationTokens are the bearer credentials the .../impersonate
	// endpoint minted under this grant. Held server-side SOLELY so the
	// revoke/expiry cascade can deny them across every issuer the instant the
	// grant ends — a stateless JWT cannot self-revoke, so the cascade needs the
	// token value (the same pattern logout's RevokeAcrossIssuers uses). json:"-"
	// keeps these bearer secrets off EVERY wire response (List/Get never echo
	// them). Additive + best-effort: a legacy record reads the nil zero value
	// and every existing store keeps working unchanged.
	ImpersonationTokens []string `json:"-"`
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

	// Activate atomically transitions a pending record to active for the
	// creating admin and attaches the sessions minted after Create succeeded.
	// This ordering prevents a failed Create from orphaning a derived session.
	Activate(ctx context.Context, id, adminID string, sessionIDs []string) (AdminSession, error)

	// Approve atomically transitions a pending record to active, stamping
	// ApprovedBy and attaching the impersonation sessionIDs minted for the
	// activation. MUST reject approverID == AdminUserID with
	// ErrAdminSessionSelfApproval and a non-pending (incl. lazily expired)
	// record with ErrAdminSessionNotPending — the store is the atomic
	// authority even when handlers pre-check.
	Approve(ctx context.Context, id, approverID string, sessionIDs []string) (AdminSession, error)

	// Revoke marks a record revoked and returns it (with SessionIDs +
	// ImpersonationTokens, so the caller can cascade). Idempotent on an already
	// revoked/expired record; unknown ID returns ErrAdminSessionNotFound.
	Revoke(ctx context.Context, id string) (AdminSession, error)

	// AttachImpersonationToken appends a freshly minted impersonation bearer to
	// an ACTIVE grant's revocation set so the revoke/expiry cascade can later
	// deny it. It re-checks the grant's live status atomically (lazy-expiry
	// aware) — the store is the authority even when the handler pre-checks —
	// returning ErrAdminSessionNotFound for an unknown id and
	// ErrAdminSessionNotActive when the grant is not active (pending / expired /
	// revoked). The caller MUST destroy the just-minted token on any error so a
	// rejected attach never orphans a live impersonation credential.
	AttachImpersonationToken(ctx context.Context, id, token string) (AdminSession, error)

	// DeleteExpired removes every record past ExpiresAt and returns the
	// ones that were still pending/active — the sweeper cascades session
	// destruction + emits the expiry audit event for exactly those.
	// Already-revoked records past ExpiresAt are garbage-collected
	// silently (their cascade ran at revoke time).
	DeleteExpired(ctx context.Context) ([]AdminSession, error)
}
