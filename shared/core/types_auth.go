package core

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

// Session represents an active user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`

	// LastActiveAt is updated on each API request that uses this session, if
	// the SessionManager implements LastActiveUpdater. Best-effort, never
	// security load-bearing. Zero value = not tracked.
	LastActiveAt time.Time `json:"last_active_at,omitempty"`

	// IP and UserAgent are the device/location context captured at session
	// creation, surfaced in the self-service session list (/sessions/me) so a
	// user can recognize and revoke unfamiliar sessions. Best-effort: populated
	// only when the SessionManager implements SessionMetaCreator AND the login
	// flow had a request to read them from (empty otherwise — never security
	// load-bearing). The IP honors the same first-hop X-Forwarded-For trust model
	// as the rest of the server (safe only behind a trusted edge).
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	// TenantID binds the session to the tenant that owns the authenticating
	// client, enabling SessionTenantIndex.DeleteByTenant to revoke every
	// session of a suspended/deleted tenant in one pass. Best-effort: empty
	// when the login flow had no tenant in scope (single-tenant deployments)
	// or when the SessionManager doesn't persist it — never security
	// load-bearing on its own (the suspension check + roster-based revocation
	// remain the enforcement floor).
	TenantID string `json:"tenant_id,omitempty"`

	// DeviceID links this session to an authenticated device record, set during
	// login when a DeviceStore is wired. Best-effort, never security load-bearing.
	DeviceID string `json:"device_id,omitempty"`

	// Kind distinguishes special session classes from interactive logins.
	// Currently the only value is SessionKindAdminImpersonation — a session
	// minted under a break-glass admin grant — so audit enrichment can
	// separate "the user did this" from "support did this as the user".
	// Best-effort like IP/UserAgent: persisted only by managers that store
	// it (memory does); never security load-bearing — break-glass tracks
	// its derived sessions by ID for the revocation cascade.
	Kind string `json:"kind,omitempty"`

	// TrustScore + TrustSetAt back the zero-trust session-trust-decay feature
	// (WithSessionTrustDecay, Direction 3 Phase 3). TrustScore is the [0,1]
	// confidence bound to the session at creation; TrustSetAt is the instant it
	// was set — the decay baseline the trust curve erodes from
	// (shared/trust.DecayedScore). Both are ADDITIVE + best-effort: a legacy row
	// / a manager that doesn't persist them reads the zero value, and the zero
	// value is the feature-off contract — TrustSetAt zero means "no trust signal
	// bound", so DecayedScore returns the raw score and the min-trust gate
	// fail-OPENS (never a hard deny on absent scoring data). Never on the wire in
	// a token; purely internal session state.
	TrustScore float64   `json:"trust_score,omitempty"`
	TrustSetAt time.Time `json:"trust_set_at,omitempty"`

	// StepUpRequired is the advisory flag the ContinuousVerificationAgent sets
	// (platform/lifecycle/continuousverify) when a live session's decayed trust
	// fell below the configured floor: the next request through a min-trust gate
	// observes it and issues an RFC 9470 step-up challenge. Additive + best-
	// effort like TrustScore: the zero value (false) is the default and leaves
	// behavior byte-identical. Cleared implicitly on re-authentication (a fresh
	// session with a fresh score), never security load-bearing on its own — the
	// gate re-derives from the live decayed score too.
	StepUpRequired bool `json:"step_up_required,omitempty"`
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Since(s.ExpiresAt) > 0
}

// SessionTrustManager is the OPTIONAL extension a SessionManager MAY implement
// so the zero-trust continuous-verification agent (platform/lifecycle/
// continuousverify) can update a live session's decayed trust state. Backends
// without session storage (pure JWT issuers) simply don't implement it — the
// agent then finds no marker on the wired manager and no-ops for that build,
// leaving behavior byte-identical (the feature needs a session store anyway).
//
// Both methods are best-effort + fail-open at the call site: the agent logs and
// continues on error rather than wedging its sweep, since the decay/gate are
// advisory infra that must never hard-deny on their own error.
type SessionTrustManager interface {
	// MarkStepUp sets Session.StepUpRequired on the identified session so the
	// next request through a min-trust gate is challenged for step-up. Idempotent
	// (re-marking an already-flagged session is a no-op). A missing session is
	// not an error (it may have expired between the sweep's List and this call).
	MarkStepUp(ctx context.Context, sessionID string) error

	// SetTrust (re)binds a session's trust baseline (TrustScore + TrustSetAt) —
	// used to seed the score at creation from an out-of-band scorer or to reset
	// the decay baseline after a re-verification. A missing session is not an
	// error.
	SetTrust(ctx context.Context, sessionID string, score float64, setAt time.Time) error
}

// AuthRequest holds the input for an authentication attempt.
type AuthRequest struct {
	Provider   string
	Credential map[string]string // username/password, code, assertion, etc.
	Redirect   *url.URL
	ClientID   string
	Scope      []string
	State      string

	// LoginHint is the OIDC Core §3.1.2.1 `login_hint` parameter
	// — a hint to the AS about the End-User's identifier (email,
	// phone, account name). Authenticators that render UIs use
	// it to pre-fill the username field; password / code
	// authenticators MAY validate that the supplied credential
	// matches the hint and reject mismatches. Empty when the
	// RP didn't supply a hint.
	LoginHint string

	// ACRValues is the OIDC Core §3.1.2.1 `acr_values` parameter
	// — space-separated list of ACR values the RP prefers, in
	// descending preference order. Authenticators that can pick
	// among methods use this to choose the strongest method
	// matching one of the requested ACRs. The AchievedACR field
	// on AuthResult communicates back what was actually used;
	// the AS surfaces that value as the id_token's `acr` claim.
	// Empty = no preference (authenticator picks freely).
	ACRValues []string

	// UILocales is the OIDC Core §3.1.2.1 `ui_locales` parameter
	// — space-separated list of BCP-47 language tags in descending
	// preference order. Authenticators that render UIs use it to
	// pick a localization (e.g. "fr-CA en-US"). The AS itself
	// doesn't render UIs today, but this field is plumbed so
	// future UI-rendering authenticators (WebAuthn flows, etc.)
	// get the signal end-to-end. Falls back to Accept-Language /
	// geo when empty (authenticator's choice).
	UILocales []string

	// RequestedClaims is the OIDC Core §5.5 `claims` request
	// parameter — a JSON object asking for specific claims in
	// the id_token or userinfo response. Shape:
	//
	//	{"userinfo": {"email": null, "name": {"essential": true}},
	//	 "id_token": {"acr": {"values": ["urn:level:high"]}}}
	//
	// Preserved as raw JSON so extension claim names pass through
	// unmodified. Authenticators / issuers that honor the
	// parameter project these claims into their output;
	// implementations that don't simply ignore the field.
	RequestedClaims json.RawMessage
}

// AuthResult holds the result of a successful authentication.
//
// CountryCode (ISO 3166-1 alpha-2, e.g. "US", "CN") and
// RecommendedLanguage (BCP-47, e.g. "en-US") are forwarded to the
// login client so the post-login UI can render in the user's
// most-likely region + language without an extra round trip.
// Authenticators with a stronger signal (a phone authenticator
// that knows the SIM region; a saved user preference) populate
// these directly; otherwise the geo middleware fills them from
// the request IP. Empty values mean "no hint, use the client's
// own preference" — the response key is omitted entirely so
// clients can rely on its absence.
type AuthResult struct {
	UserID              string
	ExternalID          string
	Provider            string
	Attributes          map[string]string
	AuthMethods         []string // how the user was authenticated
	CountryCode         string   // ISO 3166-1 alpha-2, optional
	RecommendedLanguage string   // BCP-47, optional

	// AchievedACR is the Authentication Context Class Reference the
	// authenticator actually satisfied on this login (RFC 9068 §2.2 /
	// OIDC Core §2).  Authenticators that can achieve different ACR
	// levels (e.g. a multi-method provider that chose password vs MFA)
	// populate this to tell the AS which level was reached; the AS
	// stamps it as the id_token acr claim and checks it against the
	// RP's acr_values request.  Empty = authenticator didn't report an
	// ACR (no acr claim is emitted in the token; any acr_values check
	// treats it as unmet).
	AchievedACR string

	// CredentialHealth carries a non-blocking login-time signal about
	// the password's strength/breach status. It is deliberately a typed
	// field rather than an Attributes entry: Attributes flows into the
	// id_token Claims, so a health signal stashed there would leak onto
	// the wire. nil = no signal (the credential was healthy or the check
	// was disabled). The login orchestrator only reads it to emit an
	// audit event.
	//
	// json:"-" keeps this advisory signal off ALL generic AuthResult
	// serialization (tokens, and — critically — the MFA challenge store,
	// which persists the whole *AuthResult as a resume blob). The MFA
	// step-up path re-threads it explicitly through mfaResumeState so the
	// post-step-up audit still fires; nothing else carries it.
	CredentialHealth *CredentialHealth `json:"-"`
}

// CredentialHealth carries a non-blocking login-time signal about the
// password's strength/breach status. nil = no signal (healthy or check
// disabled). Never serialized into tokens.
type CredentialHealth struct {
	Weak        bool
	Compromised bool
	Reason      string // operator-facing; audit metadata only, never on the wire
}

// CallbackState holds the state for a callback (OIDC/OAuth flow).
type CallbackState struct {
	Code     string
	State    string
	Redirect *url.URL
	ClientID string
	Scope    []string
}

// User represents an authenticated user.
//
// Username is the platform-unique user-chosen handle (latin-only
// [a-zA-Z0-9_], 3-50 chars) — the identity the user types at login.
// Unlike ExternalID (which is an upstream IDP's opaque identifier),
// Username is a first-class platform identity that IS queryable and
// displayable. It is required for admin-created users; existing users
// migrated from a schema without it carry Username="" (which the
// caller interprets as "not yet set"). JSON omitempty so old consumers
// that never send it stay byte-compatible.
//
// DisplayName is the optional user-facing full name (typically
// "First Last") distinct from Name (which may be a SAML-displayed
// name or a SCIM attribute). Empty when not set.
type User struct {
	ID         string            `json:"id"`
	ExternalID string            `json:"external_id,omitempty"`
	Provider   string            `json:"provider,omitempty"`
	Email      string            `json:"email,omitempty"`
	Username   string            `json:"username,omitempty"`
	Name       string            `json:"name,omitempty"`
	DisplayName string           `json:"display_name,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// UserAttrActive is the User.Attributes key SCIM writes the RFC 7643 `active`
// flag to (protocols/scim). UserAttrInactive is its deprovisioned value. Only an
// explicit "false" means deactivated; an absent or any other value is active, so
// non-SCIM deployments (which never write the key) are unaffected.
const (
	UserAttrActive   = "scim:active"
	UserAttrInactive = "false"
)

// IsActive reports whether the user may authenticate. False ONLY when SCIM has
// deprovisioned the account (Attributes["scim:active"] == "false"); absent /
// any other value is active. A nil user is treated as active (the caller's
// not-found / non-SCIM path decides separately). The login path MUST consult
// this AFTER credential verification so a deprovisioned user cannot obtain
// tokens even with a correct credential (RFC 7643 §4.1.2 active=false).
func (u *User) IsActive() bool {
	if u == nil {
		return true
	}
	return u.Attributes[UserAttrActive] != UserAttrInactive
}
