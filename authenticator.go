package sso

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
