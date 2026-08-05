package core

import (
	"context"
	"net/http"
	"time"
)

// Authenticator defines how a user is authenticated.
// Implement this interface to support any SSO provider (password, OIDC, SAML, LDAP, etc.).
type Authenticator interface {
	// Name returns the unique identifier for this authenticator (e.g., "password", "oidc", "saml").
	Name() string

	// Authenticate validates credentials and returns the authenticated user info.
	Authenticate(ctx context.Context, req *AuthRequest) (*AuthResult, error)

	// Callback handles the return from an external identity provider (OAuth/OIDC code exchange, SAML assertion, etc.).
	Callback(ctx context.Context, state *CallbackState) (*AuthResult, error)

	// LoginURL returns the URL to redirect the user to for login.
	// For direct credential auth (password), return empty string.
	LoginURL(state string) string
}

// LockoutKeyer is an OPTIONAL Authenticator extension reporting the canonical,
// NORMALIZED identity this authenticator actually authenticates on, for
// per-account brute-force lockout keying. Authenticators whose real identity
// field is NOT the first present in security.LockoutKey's field precedence — or
// whose field needs normalization the precedence skips — MUST implement it.
// Otherwise an attacker can inject a higher-precedence field the authenticator
// ignores (e.g. a varying `username` on a phone/email OTP login), or vary the
// case/whitespace of the real field, to spread brute-force attempts across
// distinct lockout keys and defeat the per-account lockout entirely. Return ""
// to declare a credential lockout-unkeyable for this authenticator.
type LockoutKeyer interface {
	LockoutIdentity(credential map[string]string) string
}

// UserProvider manages user data storage and retrieval. List + Delete are
// the admin-only methods; reads + CreateOrUpdate are the runtime hot path.
type UserProvider interface {
	GetByID(ctx context.Context, id string) (*User, error)
	GetByExternalID(ctx context.Context, provider string, externalID string) (*User, error)
	CreateOrUpdate(ctx context.Context, user *User) error

	// List returns every known user. Order unspecified; pagination is the
	// caller's responsibility.
	List(ctx context.Context) ([]*User, error)

	// Delete removes a user by ID. Idempotent: missing IDs return nil.
	Delete(ctx context.Context, id string) error
}

// ClientStore manages registered SSO client applications. Get + ValidateSecret
// are the runtime hot path; the rest (List/Update/Delete/RotateSecret/Add)
// power the admin control plane and are also used at boot to load YAML seed
// clients. Backends backed by a database can implement these directly;
// in-memory or YAML-only setups can wrap defaultimpl.MemoryClientStore.
type ClientStore interface {
	Get(ctx context.Context, clientID string) (*Client, error)
	ValidateSecret(ctx context.Context, clientID, clientSecret string) error

	// List returns every registered client. Order is unspecified.
	List(ctx context.Context) ([]*Client, error)

	// Add inserts a new client. Returns ErrClientExists if the ID is taken —
	// admin Create RPCs map this to AlreadyExists/409.
	Add(ctx context.Context, c *Client) error

	// Update replaces an existing client by ID. ErrNoSuchClient when missing.
	Update(ctx context.Context, c *Client) error

	// Delete removes a client by ID. Idempotent — missing IDs return nil so
	// reconciliation loops don't churn.
	Delete(ctx context.Context, clientID string) error

	// RotateSecret generates a new secret for the client, persists it, and
	// returns the new value. Implementations choose secret format/length;
	// callers MUST treat the returned string as opaque.
	RotateSecret(ctx context.Context, clientID string) (string, error)
}

// TenantScopedClientStore is an optional extension a ClientStore
// MAY implement to expose efficient tenant-scoped listing. Admin
// UIs that show "all clients owned by tenant acme" want this
// path; backends without an index can fall back to filtering
// List() in the caller.
//
// The pattern mirrors permissions.MenuLister: callers type-assert
// before using, so adding this interface doesn't break existing
// ClientStore implementations.
type TenantScopedClientStore interface {
	ListByTenant(ctx context.Context, tenantID string) ([]*Client, error)
}

// ClientStoreStats is an optional extension a ClientStore MAY
// implement to expose a CHEAP fingerprint of the client set without
// materializing every client. The OIDC discovery document is derived
// from the client store (scope union, RequirePAR-any, etc.) and is
// TTL-cached; on cache expiry the server can call Stats() to decide
// whether anything that affects the document actually changed before
// paying for a full List() + re-projection.
//
// hash is a stable digest over the discovery-relevant fields of every
// client (client IDs + AllowedScopes at minimum). It MUST be
// deterministic regardless of storage iteration order: the same
// logical client set always yields the same hash, and any change that
// would alter the discovery document flips it. count is returned
// alongside as a cheap secondary signal so a caller never has to act
// on a hash whose client cardinality disagrees with the cached one.
//
// The pattern mirrors TenantScopedClientStore: callers type-assert
// before using, so adding this interface never breaks an existing
// ClientStore implementation. Backends that cannot compute a
// fingerprint more cheaply than a full List() simply don't implement
// it — the caller falls back to List() + recompute (pure
// backward-compat).
//
// hash values are comparable ONLY within a single backend instance:
// two backends that persist different columns may digest the same
// logical client to different values, which is correct (their
// discovery documents genuinely differ). Implementations SHOULD use
// ClientSetFingerprint so every backend shares one canonical encoding
// and the digest stays insensitive to iteration order.
type ClientStoreStats interface {
	Stats(ctx context.Context) (count int, hash string, err error)
}

// SessionManager handles user session lifecycle. ListByUser + ListAll back
// the TokenAdminService.ListSessions RPC and are the only safe way to get a
// "list active sessions" view (JWT issuers are stateless and cannot answer).
type SessionManager interface {
	Create(ctx context.Context, userID string) (*Session, error)
	Get(ctx context.Context, sessionID string) (*Session, error)
	Destroy(ctx context.Context, sessionID string) error
	Refresh(ctx context.Context, sessionID string) (*Session, error)

	// ListByUser returns every active session for a user. Empty list if none.
	ListByUser(ctx context.Context, userID string) ([]*Session, error)

	// ListAll returns every active session. Backends with millions of sessions
	// MAY return ErrUnsupportedOperation rather than load the whole world.
	ListAll(ctx context.Context) ([]*Session, error)
}

// SessionActivityTracker is an OPTIONAL SessionManager extension. When a
// SessionManager implements it, the server calls TrackActivity on each
// authenticated request to update the session's last-active timestamp.
type SessionActivityTracker interface {
	TrackActivity(ctx context.Context, sessionID string) error
}

// SessionMeta is the optional device/location context captured at session
// creation for the self-service session list.
type SessionMeta struct {
	IP        string
	UserAgent string
	ClientID  string
	// AuthorizedScopes is copied at creation and may only shrink through
	// SessionAuthorizationManager. AuthTime preserves the original login time.
	AuthorizedScopes []string
	AuthTime         time.Time

	// TenantID, when set, binds the session to the tenant that owns the
	// authenticating client. It lets SessionTenantIndex.DeleteByTenant kill
	// every session for a suspended tenant directly (one query) instead of
	// walking the org roster. Optional + best-effort: empty when the login
	// flow had no tenant in scope, and a manager that doesn't persist it stays
	// byte-identical (tenant suspension then falls back to the roster path).
	TenantID string

	// DeviceID links this session to a device record, set during login when
	// a DeviceStore is wired. Best-effort, never security load-bearing.
	DeviceID string

	// Kind, when set, marks the session class (see Session.Kind). The
	// break-glass flow passes SessionKindAdminImpersonation here so the
	// minted session is distinguishable from an interactive login.
	// Best-effort: a manager that doesn't persist it stays byte-identical.
	Kind string

	// TrustScore + TrustSetAt bind an initial zero-trust score to the session at
	// creation (Session.TrustScore / TrustSetAt). Set by the login flow ONLY when
	// WithSessionTrustDecay is wired; both zero (the default) means "no trust
	// bound" and the session behaves byte-identically to today. A manager that
	// doesn't persist them stays byte-identical (the decay/gate then fail-open on
	// the zero baseline).
	TrustScore float64
	TrustSetAt time.Time
}

// SessionMetaCreator is the OPTIONAL extension a SessionManager implements to
// persist device/location context (IP, user-agent) on a new session. The login
// flow type-asserts it and calls CreateWithMeta when available, falling back to
// the plain Create otherwise — so a manager that doesn't implement it (e.g. a
// scale-layer backend) keeps working with empty metadata. memory + sqlite peers
// implement it.
type SessionMetaCreator interface {
	CreateWithMeta(ctx context.Context, userID string, meta SessionMeta) (*Session, error)
}

// SessionKindManager atomically publishes an internally pending session after
// its quota lease is durable. Missing sessions are idempotent no-ops.
type SessionKindManager interface {
	SetKind(ctx context.Context, sessionID, kind string) error
}

// SessionAuthorizationManager is the optional durable authorization-state
// extension used by conditional-access convergence. Implementations replace
// the session's scope ceiling atomically; callers guarantee the replacement is
// a subset of the prior grant. A missing session is an idempotent no-op.
type SessionAuthorizationManager interface {
	SetAuthorizedScopes(ctx context.Context, sessionID string, scopes []string) error
}

// SessionTenantIndex is the OPTIONAL extension a SessionManager MAY implement to
// support bulk per-tenant revocation. When an admin suspends or deletes a tenant
// the server kills that tenant's active sessions so a privilege-escape window
// (a session minted while the tenant was Active surviving until natural expiry)
// is closed proactively rather than waiting on the lazy suspension check.
//
// Backends without an index (e.g. pure JWT issuers with no session storage) that
// can't enumerate by tenant simply don't implement it — the server falls back to
// revoking sessions via the tenant's membership roster (TenantUserStore).
//
// DeleteByTenant only matches sessions whose TenantID was stamped at creation
// (SessionMeta.TenantID); an empty tenantID MUST be a no-op, not a wildcard.
type SessionTenantIndex interface {
	DeleteByTenant(ctx context.Context, tenantID string) (int, error)
}

// SessionTenantLister is the OPTIONAL read-side counterpart of SessionTenantIndex.
// A SessionManager MAY implement it to support per-tenant session listing for
// tenant-admin dashboards. Backends without a tenant index simply don't implement
// it — the admin UI falls back to listing all sessions and filtering client-side.
//
// ListByTenant only matches sessions whose TenantID was stamped at creation
// (SessionMeta.TenantID); an empty tenantID returns an empty list (no wildcard).
type SessionTenantLister interface {
	ListByTenant(ctx context.Context, tenantID string) ([]*Session, error)
}

// TokenIssuer handles token lifecycle: issuance, validation, and revocation.
type TokenIssuer interface {
	Issue(ctx context.Context, subject *Subject, scopes []string) (*Token, error)
	Validate(ctx context.Context, token string) (*TokenClaims, error)
	Revoke(ctx context.Context, token string) error
}

// TokenFormatHinter is an OPTIONAL extension that lets a TokenIssuer
// declare which inbound token shapes it can possibly validate. The
// multi-issuer dispatcher (`validateAnyToken`) uses this to skip
// issuers that obviously can't accept a token — avoiding the cost of
// e.g. attempting a base64 + signature parse on an opaque session
// token via the JWT issuer. Issuers that don't implement this
// interface are always tried (legacy behavior preserved).
//
// AcceptsTokenFormat MUST be pure (no I/O, no allocation in the hot
// path) — it's called once per Validate dispatch. False positives
// (returning true for a token this issuer can't actually validate)
// just cost a wasted Validate; false negatives (returning false for
// a token this issuer COULD validate) cause spurious validation
// failures. When in doubt, return true.
type TokenFormatHinter interface {
	AcceptsTokenFormat(token string) bool
}

// TokenLister is an OPTIONAL extension to TokenIssuer for backends that can
// enumerate issued tokens (session-backed, DB-backed). Stateless backends
// like JWT MUST NOT implement this — admin RPCs check the type assertion
// and respond Unimplemented (gRPC) / 501 (HTTP) when absent.
type TokenLister interface {
	ListActive(ctx context.Context) ([]TokenMeta, error)
}

// TokenMeta is the lightweight summary returned by TokenLister.ListActive —
// enough for admins to identify and revoke a token without exposing its bytes.
type TokenMeta struct {
	TokenID   string   `json:"token_id"`
	SubjectID string   `json:"subject_id"`
	Scopes    []string `json:"scopes,omitempty"`
	IssuedAt  int64    `json:"issued_at_unix,omitempty"`
	ExpiresAt int64    `json:"expires_at_unix,omitempty"`
	Strategy  string   `json:"strategy,omitempty"` // "jwt" | "session" | ...
}

// ConsentGrant records that a user granted a client permission to access
// a set of scopes. The grant is per-(user, client) pair; each call to
// RecordConsent REPLACES the prior grant for that pair.
type ConsentGrant struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"` // sorted, deduplicated
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // server-enforced max TTL; zero = no expiry
}

// IsExpired returns true when ExpiresAt is non-zero and the grant has
// passed its expiration deadline.
func (g *ConsentGrant) IsExpired() bool {
	if g.ExpiresAt.IsZero() {
		return false
	}
	return time.Since(g.ExpiresAt) > 0
}

// ConsentStore persists end-user consent decisions. Callers are the
// /auth/login flow (record grant) and the self-service portal (list/revoke).
// When nil (not wired), the Server skips all consent checks — behavior is
// byte-identical to a pre-consent build.
type ConsentStore interface {
	RecordConsent(ctx context.Context, grant ConsentGrant) error
	GetConsent(ctx context.Context, userID, clientID string) (ConsentGrant, error)
	RevokeConsent(ctx context.Context, userID, clientID string) error
	ListByUser(ctx context.Context, userID string) ([]ConsentGrant, error)
}

// ResourceType, TenantQuota, TenantUsage, and TenantQuotaStore live in
// tenant_user.go — thematically tenant SPI, and this file was at its
// 500-line budget (AGENTS.md §0.1).

// PasswordCredentialStore persists per-user password hashes for the
// self-service password-change flow (POST /me/password). Keyed by the stable
// UserID (the bearer's sub), so one store can back BOTH /me/password and an
// operator's login authenticator (resolve username -> UserID, then
// VerifyPassword) — keeping the credential the user changes and the one login
// checks the same. When nil (not wired), /me/password is not mounted —
// byte-identical to a build without it.
type PasswordCredentialStore interface {
	// SetPassword stores newPassword for userID, hashing it at rest. Creates
	// the credential when absent, replaces it otherwise.
	SetPassword(ctx context.Context, userID, newPassword string) error

	// VerifyPassword returns nil when plaintext matches the stored hash for
	// userID, and ErrPasswordMismatch on mismatch OR unknown user (the caller
	// MUST NOT distinguish — the unknown path runs a cost-matched dummy compare
	// for timing parity, matching the password authenticator's anti-enumeration).
	VerifyPassword(ctx context.Context, userID, plaintext string) error
}

// PasswordRehashNeeder is the OPTIONAL extension of
// [PasswordCredentialStore] that reports whether a stored hash is below the
// current hashing policy (passwordhash.NeedsRehash). The login verifier
// consults it after a successful verify and upgrades the hash in place —
// progressive rehash-on-login — so imported low-cost hashes converge to the
// policy target without a batch migration. Implementations return (false,
// nil) on absent credentials; errors are fail-open (the login already
// succeeded; a rehash is best-effort).
type PasswordRehashNeeder interface {
	NeedsRehash(ctx context.Context, userID string) (bool, error)
}

// PasswordHashImporter is an optional extension a PasswordCredentialStore MAY
// satisfy to seed a PRE-COMPUTED bcrypt hash (no plaintext) — e.g. importing
// existing users from a YAML seed, an Auth0/Keycloak export, or a prior store.
// Callers type-assert. Implementations MUST reject a value that is not a bcrypt
// hash (no "$2" prefix) so a misconfigured plaintext can never be stored as a
// hash. memory + sqlite peers satisfy it.
type PasswordHashImporter interface {
	SetPasswordHash(ctx context.Context, userID, bcryptHash string) error
}

// PasswordCredentialDeleter is another OPTIONAL PasswordCredentialStore
// extension; declared in password_reset.go (not here) to stay under this
// file's 500-line budget — see the "PasswordCredentialStore extensions"
// section there for why, alongside PasswordAgeReader.

// MFAEnrolledFactor describes one registered second factor for the
// self-service management view (GET/DELETE /me/mfa). It carries only
// non-sensitive metadata — never the TOTP secret or WebAuthn private material.
type MFAEnrolledFactor struct {
	// ID is the opaque per-factor handle used to unbind it. Stable per factor.
	ID string `json:"id"`
	// Method is the factor kind ("totp", "webauthn", "push", ...).
	Method string `json:"method"`
	// Label is an optional human-friendly name (e.g. a passkey's device name).
	Label string `json:"label,omitempty"`
	// AddedAt is when the factor was registered.
	AddedAt time.Time `json:"added_at,omitzero"`
	// Discoverable reports whether this factor is a WebAuthn discoverable
	// (resident) credential usable for passwordless/conditional-mediation
	// login (captured from the credProps extension). Nil for non-WebAuthn
	// factors, or when the issuing store never captured it — "unknown",
	// never an explicit false.
	Discoverable *bool `json:"discoverable,omitempty"`
}

// MFAEnrollmentStore lists and removes a user's registered second factors for
// self-service management (GET/DELETE /me/mfa). Verification + challenges stay
// on MFAProvider / MFAChallengeStore; this is the MANAGEMENT seam an operator
// implements over their concrete factor backends (TOTP secrets, WebAuthn
// credentials, ...). When nil (not wired), /me/mfa is not mounted —
// byte-identical to a build without it.
type MFAEnrollmentStore interface {
	// ListFactors returns userID's registered factors (empty slice, not error,
	// when none). Order unspecified.
	ListFactors(ctx context.Context, userID string) ([]MFAEnrolledFactor, error)

	// RemoveFactor unbinds the factor with factorID from userID. Idempotent:
	// a missing factor (or one owned by another user) returns nil — the
	// handler enforces ownership via ListFactors so a cross-user delete is a
	// 404, never a silent removal of someone else's factor.
	RemoveFactor(ctx context.Context, userID, factorID string) error
}

// TOTPEnrollmentWriter is an OPTIONAL extension a MFAEnrollmentStore MAY also
// implement to support TOTP self-service enrollment (POST /me/mfa/totp/confirm).
// The enrollment confirm handler type-asserts the wired MFAEnrollmentStore to
// this interface; when absent the route is not mounted (byte-identical to a
// build without it) and the existing MFAEnrollmentStore implementers compile
// unchanged — this is purely additive.
//
// AddTOTPFactor persists secret so it is BOTH usable at login-time TOTP
// verification (the same store backs the TOTP authenticator's secret reads)
// AND listed by ListFactors as factorID. Because TOTP verification keys on the
// user (one shared secret per user), a second enrollment for the same user
// REPLACES the prior TOTP factor + secret rather than accumulating an
// unverifiable second secret.
type TOTPEnrollmentWriter interface {
	AddTOTPFactor(ctx context.Context, userID, factorID, label string, secret []byte) error
}

// WebAuthnRegistrar is the server-side seam for AUTHENTICATED self-service
// passkey registration (POST /me/mfa/webauthn/{begin,finish}). It inverts a
// dependency: the WebAuthn ceremony Helper lives in authenticators/webauthn,
// which imports the server package — so the server calls through this interface
// and webauthn.NewRegistrar adapts the Helper to it.
//
// SECURITY: the server passes the BEARER SUBJECT as the registration user to
// BeginRegistration (NEVER request input), and FinishRegistration binds the new
// credential to whatever user the begin session encoded. So a passkey can only
// ever be added to the caller's OWN authenticated account — the existing
// signup ceremony (username from the request body, unauthenticated) is NOT safe
// for "add a passkey to my account" and must not be reused for it.
type WebAuthnRegistrar interface {
	// BeginRegistration starts a ceremony for userID, returning the
	// CredentialCreation options (marshaled JSON for the browser) + an opaque
	// session id the client returns to FinishRegistration. displayName is
	// cosmetic (shown in the authenticator); empty is fine.
	BeginRegistration(ctx context.Context, userID, displayName string) (optionsJSON []byte, sessionID string, err error)
	// FinishRegistration verifies the attestation in r against the session and
	// persists the credential against the session's user, returning the new
	// credential id (base64url). The session — not request input — determines
	// the owning user. expectedUserID must match the session's user; pass ""
	// to skip the check (unauthenticated ceremony path only).
	FinishRegistration(ctx context.Context, sessionID, expectedUserID string, r *http.Request) (credentialID string, err error)
}

// TOTPEnroller is the server-side seam the self-service TOTP enrollment handlers
// call to generate/encode/decode secrets, build the otpauth provisioning URI,
// and verify the confirm code. It exists to INVERT a dependency: the concrete
// TOTP primitives live in the authenticators package, which imports the server
// package — so the server cannot import them directly without a cycle. The
// server depends on this interface instead; authenticators.NewTOTPEnroller
// adapts the concrete primitives to it. Wired via WithTOTPEnroller; nil ⇒ the
// enrollment routes are not mounted (byte-identical off).
type TOTPEnroller interface {
	// GenerateSecret mints a fresh raw TOTP secret.
	GenerateSecret() ([]byte, error)
	// EncodeSecret renders the base32 form shown in the QR / for manual entry.
	EncodeSecret(secret []byte) string
	// DecodeSecret parses the base32 form (as round-tripped from begin) back to
	// raw bytes. A malformed value MUST return an error, not panic.
	DecodeSecret(encoded string) ([]byte, error)
	// OTPAuthURI builds the otpauth://totp/... provisioning URI for issuer +
	// account that authenticator apps consume from a QR code.
	OTPAuthURI(issuer, account string, secret []byte) string
	// VerifyCode reports whether code matches secret at the current time
	// (within the configured skew), WITHOUT consulting any store.
	VerifyCode(secret []byte, code string) bool
}

// IdempotentCache provides idempotency-key semantics for the /token
// endpoint. When a client sends an Idempotency-Key header, the server
// caches the first successful response and returns it for subsequent
// requests with the same key — preventing duplicate token issuance on
// network-level retries.
//
// The implementation must be safe for concurrent access and should
// enforce a TTL (typically aligned with the token's lifetime or a
// maximum of 1 hour) so stale entries don't accumulate indefinitely.
type IdempotentCache interface {
	// Get returns the cached response for key, or nil when not found / expired.
	Get(ctx context.Context, key string) ([]byte, bool, error)
	// Set stores the response body for key with the given TTL.
	Set(ctx context.Context, key string, body []byte, ttl time.Duration) error
}
