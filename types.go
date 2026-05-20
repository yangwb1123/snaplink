package sso

import (
	"encoding/json"
	"net/url"
	"slices"
	"time"
)

// User represents an authenticated user.
type User struct {
	ID         string            `json:"id"`
	ExternalID string            `json:"external_id,omitempty"`
	Provider   string            `json:"provider,omitempty"`
	Email      string            `json:"email,omitempty"`
	Name       string            `json:"name,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Client represents a registered application that can request tokens.
//
// Per-app policy lives here:
//   - AllowedAuthenticators whitelists which login methods this app accepts
//     (empty = allow every Authenticator registered on the Server).
//   - TokenStrategy names which TokenIssuer mints this app's tokens
//     (empty = use Server's default strategy).
type Client struct {
	ID                    string   `json:"id"`
	Secret                string   `json:"-"`
	Name                  string   `json:"name"`
	RedirectURIs          []string `json:"redirect_uris"`
	AllowedScopes         []string `json:"allowed_scopes"`
	AllowedAuthenticators []string `json:"allowed_authenticators,omitempty"`
	TokenStrategy         string   `json:"token_strategy,omitempty"`
	Active                bool     `json:"active"`

	// TenantID binds this client to one tenant in multi-tenant
	// deployments. When set, request handlers reject login /
	// callback flows whose resolved tenant doesn't match (the
	// tenant middleware populates the resolved tenant on
	// HandlerContext). Empty TenantID means "no tenant
	// affinity" — handlers serve the client from any tenant
	// context, which is the backward-compatible behavior for
	// single-tenant deployments.
	TenantID string `json:"tenant_id,omitempty"`

	// RequirePKCE forces authorization_code requests against this
	// client to carry a code_challenge — the standard tightening
	// for public clients (SPAs, mobile apps) that can't safely hold
	// a client_secret. When true, /auth/login with response_type=code
	// without a code_challenge returns 400 pkce_required. When false
	// (the default), PKCE is opt-in per-request — the exchange
	// verifies the challenge only when one was presented at login.
	RequirePKCE bool `json:"require_pkce,omitempty" yaml:"require_pkce,omitempty"`

	// AllowedResources is the RFC 8707 resource-indicator allowlist.
	// When non-empty, every `resource` parameter on /token /
	// /auth/login / /device/code MUST appear in this list — the
	// token endpoint rejects requests for unregistered audiences
	// with `invalid_target`. Empty list = no resource binding
	// enforcement (legacy behavior; the token still mints but
	// without an aud claim from this source).
	AllowedResources []string `json:"allowed_resources,omitempty" yaml:"allowed_resources,omitempty"`

	// RegistrationAccessToken authenticates RFC 7592 Dynamic
	// Client Management calls (GET/PUT/DELETE /register/:client_id)
	// against this client. Issued at /register time alongside the
	// client_secret; constant-time compared on every management
	// request. Empty means dynamic management is disabled for this
	// client (legacy / operator-provisioned clients never had one).
	RegistrationAccessToken string `json:"-" yaml:"-"`

	// PostLogoutRedirectURIs is the allowlist of URLs the OIDC
	// RP-Initiated Logout endpoint will redirect the user back to
	// after killing the session. Per OIDC RP-Initiated Logout 1.0
	// §2, the redirect MUST come from this list — an attacker who
	// crafts a logout URL with a phishing redirect_uri must not be
	// able to send the user anywhere not pre-registered. Empty
	// list = no post-logout redirect honored (the endpoint still
	// kills the session and returns 204 + no Location header).
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty" yaml:"post_logout_redirect_uris,omitempty"`

	// AllowedAuthorizationDetailsTypes is the RFC 9396 type
	// allowlist for authorization_details elements. Each element
	// in the wire array MUST have a `type` field; when this
	// allowlist is non-empty, every element's type MUST appear in
	// the list — non-matching requests fail with
	// invalid_authorization_details. Empty list = no
	// authorization_details enforcement (legacy compat); the
	// parameter is still accepted but unconstrained.
	AllowedAuthorizationDetailsTypes []string `json:"allowed_authorization_details_types,omitempty" yaml:"allowed_authorization_details_types,omitempty"`

	// RefreshTokenTTL overrides the server-wide refresh-token
	// lifetime for THIS client. Useful when one deployment serves
	// both public SPAs (where shorter refresh tokens limit blast
	// radius if exfiltrated) and confidential service clients
	// (which want longer refresh chains to avoid frequent
	// re-auth). Zero = inherit the server's WithRefreshTokenStore
	// ttl (or DefaultRefreshTokenTTL when that's also unset).
	// Applies at every issuance: first-mint at /auth/login,
	// authorization_code exchange, and rotation grant alike.
	RefreshTokenTTL time.Duration `json:"refresh_token_ttl,omitempty" yaml:"refresh_token_ttl,omitempty"`

	// AccessTokenTTL overrides the TokenIssuer's default lifetime
	// for access (and ID) tokens minted on behalf of THIS client.
	// Plumbed via Subject.TTL into Ed25519JWTIssuer.Issue (and
	// IDTokenRequest.TTL for id_tokens). Zero = use the issuer's
	// configured tokenTTL. Same SPA-vs-service shaping rationale
	// as RefreshTokenTTL above.
	AccessTokenTTL time.Duration `json:"access_token_ttl,omitempty" yaml:"access_token_ttl,omitempty"`

	// AllowedPKCEMethods narrows the PKCE challenge methods this
	// client may use. RFC 7636 mandates support for "S256" and
	// tolerates "plain" for legacy clients; production deployments
	// SHOULD reject "plain" for new clients (it offers no protection
	// against a stolen authorization code on a non-private channel).
	// Empty = legacy "any RFC-defined method accepted" behavior.
	// When non-empty, every PKCE-bearing request from this client
	// MUST have code_challenge_method in this list; mismatches
	// fail with invalid_pkce_method.
	AllowedPKCEMethods []string `json:"allowed_pkce_methods,omitempty" yaml:"allowed_pkce_methods,omitempty"`

	// RequirePAR forces every authorization request for THIS client
	// to be pushed via /par BEFORE redirecting the user agent (RFC
	// 9126 §2.1). When true, a direct /auth/login call without
	// `request_uri` is rejected with invalid_request — the spec's
	// closest-fit error for "client must push the request first".
	// Useful for high-security clients where the full authorization
	// request must be authenticated server-to-server up front.
	// When false (default), direct authorization is still allowed —
	// PAR remains an optional shortcut.
	RequirePAR bool `json:"require_par,omitempty" yaml:"require_par,omitempty"`

	// AllowedRequestURIs is the RFC 9101 §5.2.2 allowlist of URLs
	// the AS will fetch a JAR request object from when the RP
	// passes `request_uri=<URL>` on /auth/login. Each entry MUST
	// be an exact-match HTTPS URL — wildcards would defeat the
	// SSRF defense. Empty list = JAR URL-fetch is disabled for
	// this client (PAR's `urn:` prefix still works regardless).
	// Operators wiring `WithJARFetcher` SHOULD also set this on
	// every JAR-using client so a compromised request_uri can't
	// be redirected to an internal IP.
	AllowedRequestURIs []string `json:"allowed_request_uris,omitempty" yaml:"allowed_request_uris,omitempty"`

	// UserinfoSignedResponseAlg is the OIDC Core §5.3.2 client
	// metadata that names the JWS algorithm the AS uses when
	// signing the /userinfo response (instead of returning plain
	// JSON). Empty = JSON response (the default). When set to
	// a non-empty value, /userinfo returns
	// `Content-Type: application/jwt` and a signed JWT whose
	// payload is the userinfo claim set. Today only "EdDSA" is
	// supported (matches the access-token signing alg); other
	// values are rejected at request time. Useful when downstream
	// services want to verify the claims independently of the
	// access token's signature.
	UserinfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty" yaml:"userinfo_signed_response_alg,omitempty"`

	// BackchannelLogoutURI is the OIDC Back-Channel Logout 1.0
	// §2.5 endpoint the AS POSTs a signed logout_token to when
	// the user logs out of the SSO server. Empty = back-channel
	// logout is disabled for this client (the RP must rely on
	// access-token expiry or a polling check).
	BackchannelLogoutURI string `json:"backchannel_logout_uri,omitempty" yaml:"backchannel_logout_uri,omitempty"`

	// FrontchannelLogoutURI is the OIDC Front-Channel Logout 1.0
	// §2 endpoint embedded in a hidden iframe on /end_session's
	// HTML response when this client is logged out. The browser
	// loads the URI, the RP responds by clearing its own session
	// cookies. Complements (not replaces) BackchannelLogoutURI:
	// FCL works without an RP backend reachable to the AS but
	// requires a live user agent; BCL works without a live user
	// agent but requires the RP to be network-reachable. Empty =
	// /end_session falls through to the legacy 302/204 behavior.
	FrontchannelLogoutURI string `json:"frontchannel_logout_uri,omitempty" yaml:"frontchannel_logout_uri,omitempty"`

	// JWKS holds the client's public verification keys for RFC
	// 9101 JWT-Secured Authorization Requests. When non-empty,
	// the client may send signed request objects via the
	// `request` parameter on /auth/login; the server picks the
	// key by `kid` from the JWT header and verifies the
	// signature. Empty = JAR disabled for this client; presented
	// request parameters return invalid_request_object.
	JWKS []JWK `json:"jwks,omitempty" yaml:"jwks,omitempty"`
}

// IsRedirectURIValid checks if the given redirect URI is registered.
func (c *Client) IsRedirectURIValid(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

// IsPostLogoutRedirectURIValid checks the post-logout redirect
// URI allowlist for RP-Initiated Logout.
func (c *Client) IsPostLogoutRedirectURIValid(uri string) bool {
	return slices.Contains(c.PostLogoutRedirectURIs, uri)
}

// AreResourcesAllowed reports whether every requested resource
// indicator is permitted for this client. Empty allowlist = no
// enforcement (legacy compat); empty requested = always allowed.
func (c *Client) AreResourcesAllowed(requested []string) bool {
	if len(requested) == 0 || len(c.AllowedResources) == 0 {
		return true
	}
	for _, r := range requested {
		if !slices.Contains(c.AllowedResources, r) {
			return false
		}
	}
	return true
}

// IsAuthenticatorAllowed reports whether the named authenticator may be used
// to log into this app. An empty AllowedAuthenticators list means "any".
func (c *Client) IsAuthenticatorAllowed(name string) bool {
	if len(c.AllowedAuthenticators) == 0 {
		return true
	}
	return slices.Contains(c.AllowedAuthenticators, name)
}

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

	// Actor is the validated RFC 8693 §4.1 `act` claim, populated
	// when the token carries delegation provenance. Nil when the
	// token represents direct subject access (no delegation in
	// flight).
	Actor *ActorClaim `json:"act,omitempty"`
}

// Session represents an active user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
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

	// Actor (RFC 8693 §4.1) names the party acting on behalf of
	// the Subject for delegation chains. When set, the issued
	// access token carries an `act` claim — a nested object
	// with at least the actor's `sub`. Today's token-exchange
	// grant populates this when called with `actor_token`;
	// other grants leave it nil. Nested act-in-act (multi-hop
	// delegation) is NOT YET wired — when a subject token
	// already has `act`, the exchange overwrites with the new
	// actor; future extension can prepend the chain instead.
	Actor *ActorClaim
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
}

// CallbackState holds the state for a callback (OIDC/OAuth flow).
type CallbackState struct {
	Code     string
	State    string
	Redirect *url.URL
	ClientID string
	Scope    []string
}
