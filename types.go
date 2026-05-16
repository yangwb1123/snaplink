package sso

import (
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
}

// IsRedirectURIValid checks if the given redirect URI is registered.
func (c *Client) IsRedirectURIValid(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
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
type TokenClaims struct {
	Subject   string            `json:"sub"`
	Issuer    string            `json:"iss"`
	Audience  []string          `json:"aud"`
	Scopes    []string          `json:"scopes"`
	ExpiresAt time.Time         `json:"exp"`
	NotBefore time.Time         `json:"nbf"`
	IssuedAt  time.Time         `json:"iat"`
	Extra     map[string]string `json:"extra,omitempty"`
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
type Subject struct {
	ID       string
	Provider string
	Claims   map[string]string
}

// AuthRequest holds the input for an authentication attempt.
type AuthRequest struct {
	Provider   string
	Credential map[string]string // username/password, code, assertion, etc.
	Redirect   *url.URL
	ClientID   string
	Scope      []string
	State      string
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
