package sso_test

// Example_additionalWiring demonstrates common configuration patterns
// for specific use cases. These complement the production and minimal
// examples by showing how to wire specific features.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/security"
)

// Example_minimumViable constructs the smallest server that can complete a
// full OAuth 2.0 authorization_code + OIDC flow: the three mandatory SPIs
// (UserProvider, ClientStore, SessionManager), one token issuer used for
// both the access token and the ID token, and an AuthCodeStore to turn on
// the authorization_code grant. See the root README's "30-second tour" for
// the runnable end-to-end version (docs/examples/quickstart).
func Example_minimumViable() {
	issuer := defaultimpl.NewEd25519JWTIssuer()

	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 0),
	)

	// srv.Handler() implements http.Handler — wire it into any net/http
	// listener: http.ListenAndServe(":8080", srv.Handler())
	_ = srv
}

// Example_productionWiring layers the hardening + operability options a
// production deployment typically wants on top of Example_minimumViable:
// refresh-token rotation, Pushed Authorization Requests (PAR), account
// lockout, audit recording, the security-headers framework, OAuth 2.1
// strict mode, and a per-user session cap. Every piece is opt-in via its
// own With* option — omit any one of them and the corresponding
// endpoint/behavior is simply not enabled; nothing here is required to
// reach Example_minimumViable's baseline flow.
func Example_productionWiring() {
	issuer := defaultimpl.NewEd25519JWTIssuer()
	auditor := audit.New(audit.NewMemorySink(1000))

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example.com"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 0),

		// Refresh tokens with family-rotation reuse detection (a replayed
		// post-rotation token kills the whole family, per RFC 6819 §5.2.2.3).
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), 30*24*time.Hour),

		// Pushed Authorization Requests — required by FAPI 2.0 / Open
		// Banking profiles, recommended for every confidential client.
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), 90*time.Second),

		// Lock an account out after repeated failed logins. Swap the
		// in-process default for a shared backend across replicas.
		sso.WithAccountLockout(security.NewMemoryAccountLockout()),

		// Ship login/logout/token-lifecycle events to an audit sink.
		sso.WithAuditRecorder(auditor),

		// HSTS, CSP with a per-request nonce, X-Frame-Options, etc. on
		// every response.
		sso.WithSecurityHeaders(),

		// Reject non-PKCE, non-S256, non-code-only flows.
		sso.WithOAuth21StrictMode(true),

		// Cap concurrent sessions per user (0 = unlimited).
		sso.WithMaxSessionsPerUser(5),
	)

	_ = srv
}

// ExampleServer_withPasswordAuthenticator shows how to configure a
// password authenticator with custom verification logic. This is the
// most common authenticator for username/password authentication.
func ExampleServer_withPasswordAuthenticator() {
	// Create a password authenticator with custom verification logic.
	// In production, this would verify against your user database.
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(
			func(ctx context.Context, username, password string) (*sso.AuthResult, error) {
				// Verify credentials against your user store.
				// Return AuthResult with UserID, AuthMethods, and AchievedACR.
				if username == "alice" && password == "secret" {
					return &sso.AuthResult{
						UserID:      "user-alice-123",
						AuthMethods: []string{"pwd"},
						AchievedACR: "urn:mace:incommon:iap:silver",
					}, nil
				}
				// Return an error for invalid credentials.
				return nil, errors.New(sso.ErrInvalidCredentials)
			},
		),
	)

	srv := sso.NewServer(
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),

		// Register the password authenticator.
		sso.WithAuthenticator(pw),
	)

	_ = srv
}

// ExampleServer_withTokenStrategies demonstrates configuring multiple
// token strategies (JWT, opaque) and selecting the default. Clients
// can override the default via client.TokenStrategy.
func ExampleServer_withTokenStrategies() {
	jwtIssuer := defaultimpl.NewEd25519JWTIssuer()

	srv := sso.NewServer(
		sso.WithIssuer("sso-server"),

		// Register multiple token issuers for different algorithms.
		sso.WithTokenIssuer("jwt", jwtIssuer),
		sso.WithTokenIssuer("jwt-rsa", defaultimpl.NewRSAJWTIssuer()),

		// Set the default token strategy. Clients can override this
		// via their Client.TokenStrategy field.
		sso.WithDefaultTokenStrategy("jwt"),

		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
	)

	_ = srv
}

// ExampleServer_withSessionManagement shows how to configure session
// lifetimes, idle timeouts, and concurrent session limits.
func ExampleServer_withSessionManagement() {
	sessionMgr := defaultimpl.NewMemorySessionManager()

	srv := sso.NewServer(
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),

		// Configure session management.
		sso.WithSessionManager(sessionMgr),

		// Limit concurrent sessions per user (0 = unlimited).
		sso.WithMaxSessionsPerUser(5),
	)

	_ = srv
}

// ExampleServer_withSecurityHeaders demonstrates enabling the security-headers
// framework (HSTS, CSP with a per-request nonce, Permissions-Policy,
// X-Frame-Options, etc.) for all responses — including the opt-in SPA bundles
// and Clear-Site-Data on logout/account-erasure.
func ExampleServer_withSecurityHeaders() {
	srv := sso.NewServer(
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),

		// Enable security headers for all responses. Use
		// WithSecurityHeadersPolicy instead to override the CSP directives /
		// Permissions-Policy.
		sso.WithSecurityHeaders(),
	)

	// All responses now include:
	// - Strict-Transport-Security (HSTS, TLS only)
	// - X-Content-Type-Options: nosniff
	// - X-Frame-Options: DENY
	// - Content-Security-Policy (with a fresh script-src nonce per request)
	// - Permissions-Policy
	// - Referrer-Policy
	//
	// POST /logout and a non-dry-run POST /me/account/erase additionally get
	// Clear-Site-Data, since both are a definitive end to the session.
	_ = srv
}

// ExampleServer_withCustomHTTPHandler shows how to wrap the SSO server's
// HTTP handler with additional middleware or mount it on a subpath.
func ExampleServer_withCustomHTTPHandler() {
	srv := sso.NewServer(
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
	)

	// Get the base handler.
	baseHandler := srv.Handler()

	// Wrap with custom middleware.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add custom logging, metrics, or other middleware here.
		// Then call the base handler.
		baseHandler.ServeHTTP(w, r)
	})

	// Mount on a subpath if needed.
	mux := http.NewServeMux()
	mux.Handle("/sso/", http.StripPrefix("/sso", handler))

	// http.ListenAndServe(":8080", mux)
	_ = handler
}
