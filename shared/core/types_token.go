package core

import (
	"encoding/json"
	"time"
)

// Token represents an issued access token.
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope"`
	CreatedAt    time.Time `json:"created_at"`
}

// TokenClaims holds the validated claims from a token.
//
// ClientID / JTI / AuthTime / ACR / AMR are RFC 9068 (JWT Profile
// for OAuth 2.0 Access Tokens) claims. JTI is the per-token unique
// identifier suitable for replay defense + revocation tracking;
// ClientID is the OAuth client the token was issued to; AuthTime /
// ACR / AMR carry authentication-event metadata. Empty / zero for
// tokens minted before this profile was wired or by issuers that
// don't speak RFC 9068.
type TokenClaims struct {
	Subject   string            `json:"sub"`
	Issuer    string            `json:"iss"`
	Audience  []string          `json:"aud"`
	Scopes    []string          `json:"scopes"`
	ExpiresAt time.Time         `json:"exp"`
	NotBefore time.Time         `json:"nbf"`
	IssuedAt  time.Time         `json:"iat"`
	Extra     map[string]string `json:"extra,omitempty"`

	ClientID string    `json:"client_id,omitempty"`
	JTI      string    `json:"jti,omitempty"`
	AuthTime time.Time `json:"auth_time,omitempty"`
	ACR      string    `json:"acr,omitempty"`
	AMR      []string  `json:"amr,omitempty"`

	// SID is the OIDC Core §2 / Back-Channel Logout 1.0 §2.4
	// session identifier. Populated when the token was minted in
	// the context of a server-managed session; downstream RPs
	// can correlate this with the same claim in a future
	// logout_token to know which local session to invalidate.
	// Empty for tokens minted without a session (client_credentials,
	// service-to-service token-exchange where no end-user is in
	// the loop).
	SID string `json:"sid,omitempty"`

	// ConfirmationJKT is the RFC 9449 DPoP JWK thumbprint when
	// the token was issued bound to a DPoP key. Empty for
	// unbound bearer tokens. Resource servers receiving this
	// token MUST verify a fresh DPoP proof's thumbprint matches.
	ConfirmationJKT string `json:"-"`

	// ConfirmationX5TS256 is the RFC 8705 §3 mTLS client cert
	// SHA-256 thumbprint when the token was issued bound to a
	// TLS client certificate. Empty for non-mTLS-bound tokens.
	// Resource servers receiving this token MUST verify the
	// inbound connection's client cert thumbprint matches.
	ConfirmationX5TS256 string `json:"-"`

	// AuthorizationDetails is the RFC 9396 fine-grained authorization
	// array originally consented to. Validate() echoes this back so
	// downstream grants (token-exchange, refresh rotation) can
	// preserve the binding across the chain. Empty = the token had
	// no RAR claim.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// Actor is the validated RFC 8693 §4.1 `act` claim, populated
	// when the token carries delegation provenance. Nil when the
	// token represents direct subject access (no delegation in
	// flight).
	Actor *ActorClaim `json:"act,omitempty"`

	// MayAct is the RFC 8693 §4.4 `may_act` claim from the
	// subject_token, indicating the only actor authorized to
	// exchange it. When non-nil, the AS MUST verify the actor
	// token's subject matches MayAct.Subject. Nil means the
	// token imposes no actor constraint (AS policy applies).
	MayAct *ActorClaim `json:"may_act,omitempty"`

	// RequestedClaims is the OIDC Core §5.5 `claims` parameter carried
	// in the access token so /userinfo can project the RP-requested
	// claims. Preserved as raw JSON. Empty = no extra projection beyond
	// scope-driven defaults (byte-identical behavior).
	RequestedClaims json.RawMessage `json:"_claims_,omitempty"`
}

// Subject holds the minimal identity info for token issuance.
//
// Resources carries RFC 8707 resource indicators — the URIs the
// access token is intended for. TokenIssuer implementations should
// stamp these into the token's `aud` claim so a resource server
// can verify the token was actually meant for it. Empty Resources
// = no audience binding (legacy behavior).
//
// ClientID / AuthTime / AMR / ACR are RFC 9068 (JWT Profile for
// OAuth 2.0 Access Tokens) claim sources. The issuer stamps them
// into the standardized claims of the same name when populated.
// All are optional — TokenIssuer implementations that don't speak
// RFC 9068 simply ignore them, and call sites that don't know the
// values leave them zero (the issuer omits the claim).
type Subject struct {
	ID        string
	Provider  string
	Claims    map[string]string
	Resources []string

	// ClientID is the OAuth 2.0 client identifier the token was
	// minted for. REQUIRED by RFC 9068 §2.2; populated by every
	// /auth/login + /token grant path.
	ClientID string

	// AuthTime is when the underlying end-user authentication
	// event occurred. Stamped as `auth_time` per RFC 9068 §2.2
	// (RECOMMENDED). Zero = omit (e.g. client_credentials has
	// no end-user auth event; refresh_token rotations don't
	// reset it).
	AuthTime time.Time

	// AMR (Authentication Methods References, RFC 8176) lists
	// the identifiers of the authentication methods used. For
	// this server: ["password"], ["phone"], ["webauthn"], etc.
	// Stamped as `amr` per RFC 9068 §2.2.
	AMR []string

	// ACR (Authentication Context Class Reference) names the
	// assurance level achieved by the authentication. Today
	// always empty — populated when step-up auth (RFC 9470)
	// lands.
	ACR string

	// AuthorizationDetails is the RFC 9396 array of fine-grained
	// authorization elements, preserved as raw JSON so extension
	// fields pass through unmodified. Stamped into the issued
	// token's `authorization_details` claim by RFC 9396-aware
	// issuers; non-aware issuers ignore it. Empty = no
	// authorization_details on the token.
	AuthorizationDetails json.RawMessage

	// TTL overrides the TokenIssuer's default access-token
	// lifetime for THIS specific issuance. Sourced from
	// Client.AccessTokenTTL at every issue call site; issuers
	// that honor it (Ed25519JWTIssuer does) use it in place of
	// their configured tokenTTL. Zero = let the issuer pick
	// (backward-compatible default).
	TTL time.Duration

	// SID is the OIDC Core §2 session identifier propagated into
	// the token's `sid` claim. Populated from the active
	// SessionManager session at login time; carried through
	// refresh-token rotation and prompt=none silent renewal so
	// the sid stays stable for the lifetime of the session.
	// Empty = no session anchor (client_credentials, service
	// flows, etc.).
	SID string

	// ConfirmationJKT is the RFC 9449 DPoP JWK thumbprint that
	// binds this access token to a specific public key. When non-
	// empty, the issued JWT carries `cnf: {jkt: <value>}` (RFC
	// 7800) and the response's token_type flips from Bearer to
	// DPoP — a resource server checks for a matching DPoP proof
	// on every protected-resource request.
	ConfirmationJKT string

	// ConfirmationX5TS256 is the RFC 8705 §3 mTLS certificate
	// thumbprint that binds this access token to a specific
	// client TLS cert. When non-empty, the issued JWT carries
	// `cnf: {x5t#S256: <value>}`. Mutually exclusive with
	// ConfirmationJKT — a single token uses one PoP mechanism.
	ConfirmationX5TS256 string

	// Actor (RFC 8693 §4.1) names the party acting on behalf of
	// the Subject for delegation chains. When set, the issued
	// access token carries an `act` claim — a nested object
	// with at least the actor's `sub`. Today's token-exchange
	// grant populates this when called with `actor_token`;
	// other grants leave it nil. Multi-hop delegation chains
	// (RFC 8693 §4.1.1) are preserved: when the subject_token
	// already carries `act`, the new ActorClaim prepends the
	// current actor and nests the previous chain underneath,
	// so reading outside-in walks the delegation in time-order
	// (outermost = most recent).
	Actor *ActorClaim

	// RequestedClaims is the OIDC Core §5.5 `claims` parameter carried
	// from /auth/login into the access token so /userinfo can project
	// the RP-requested claims. Preserved as raw JSON (same representation
	// as AuthRequest.RequestedClaims). Empty = no claim projection beyond
	// scope-driven defaults (byte-identical to pre-§5.5 behavior).
	RequestedClaims json.RawMessage
}

// ActorClaim is the RFC 8693 §4.1 `act` claim shape. Carries the
// acting party's subject identifier plus an optional nested `act`
// for multi-hop delegation chains (B acting on behalf of A's
// previously-delegated session through C, etc.). The spec
// permits arbitrary nesting; downstream services walk the chain
// to reconstruct provenance for audit + authorization decisions.
//
// Chain ordering: outermost `act` is the MOST RECENT actor, the
// deepest nested entry is the FIRST one to act. Reading the chain
// outside-in mirrors how the delegations happened in time —
// "right now C is acting, having received the right from B, who
// received it from A's original session."
type ActorClaim struct {
	Subject string      `json:"sub,omitempty"`
	Actor   *ActorClaim `json:"act,omitempty"`
}
