package sso_test

// Example_additionalWiring demonstrates common configuration patterns
// for specific use cases. These complement the production and minimal
// examples by showing how to wire specific features.

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// ExampleServer_withHostedLogin demonstrates mounting the hosted login
// UI from an embedded filesystem. The login SPA is served at /auth/login
// and handles the full authentication flow including MFA, consent, and
// home-realm discovery.
func ExampleServer_withHostedLogin() {
	//go:embed static/login
	var loginFS embed.FS

	// Extract the subdirectory containing the login SPA assets.
	loginSubFS, _ := fs.Sub(loginFS, "static/login")

	srv := sso.NewServer(
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),

		// Mount the hosted login UI. The SPA is served at /auth/login
		// and handles the full OAuth 2.0 / OIDC authentication flow.
		sso.WithHostedLoginFS(loginSubFS),
	)

	// srv.Handler() now serves the login UI at /auth/login
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
				return nil, authenticators.ErrInvalidCredentials
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

		// Session lifetime and idle timeout.
		sso.WithSessionLifetimes(
			24*time.Hour,  // Absolute session lifetime
			1*time.Hour,   // Idle timeout (no activity)
		),

		// Limit concurrent sessions per user (0 = unlimited).
		sso.WithMaxSessionsPerUser(5),
	)

	_ = srv
}

// ExampleServer_withSecurityHeaders demonstrates enabling security
// headers (HSTS, CSP, X-Frame-Options, etc.) for all responses.
func ExampleServer_withSecurityHeaders() {
	srv := sso.NewServer(
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),

		// Enable security headers for all responses.
		sso.WithSecurityHeaders(),
	)

	// All responses now include:
	// - Strict-Transport-Security (HSTS)
	// - X-Content-Type-Options: nosniff
	// - X-Frame-Options: DENY
	// - Content-Security-Policy
	// - Referrer-Policy
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
