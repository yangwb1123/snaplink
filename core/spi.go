package core

import "context"

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
