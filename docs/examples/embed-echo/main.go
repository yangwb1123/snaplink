// Command embed-echo demonstrates the real echo embedding shape: the
// embedder owns an echo.Echo, the adapter wraps it, and the SSO server
// mounts on the SAME engine alongside embedder business routes.
//
// Run with:
//
//	go run ./docs/examples/embed-echo
//	curl http://localhost:8084/hello
//
// The SSO endpoints (/auth/login, /token, /.well-known/...) are served from
// the same listener; the embedder's routes coexist without touching the SSO
// middleware stack.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	echoadapter "github.com/yangwb1123/snaplink/interfaces/adapters/echo"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	issuerName   = "embed-sso"
	clientID     = "embed-client"
	clientSecret = "embed-secret"
	redirectURI  = "http://localhost:9999/callback"
	addr         = ":8084"
)

// newApp assembles the embedding: engine -> adapter -> SSO server, plus the
// embedder's own routes. main calls it; the smoke test exercises the SAME
// wiring.
func newApp() http.Handler {
	srv := newSSOServer(newAdapter(newEmbeddedEngine()))
	return srv.Handler() // probe mux + SDK middleware chain + adapter
}

// newEmbeddedEngine builds the embedder-owned engine with its business
// routes. echo.New() attaches no framework middleware, so a panic unwinds to
// the SDK's outermost wrapPanicRecovery, which writes the normalized JSON 500
// on every backend — an embedder who attaches echo's own recovery first
// would own the panic bytes instead.
func newEmbeddedEngine() *echo.Echo {
	engine := echo.New()
	engine.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello from the embedder")
	})
	engine.GET("/boom", func(c echo.Context) error {
		panic("embedder panic — recovered by the SDK, not echo")
	})
	return engine
}

// newAdapter wraps the embedder-owned engine. The three delivery semantics
// demonstrated here are the adapter contract (docs/adapters.md §1-§5):
//
//  1. 404 normalization: NewEchoRouter installs a RouteNotFound("/*")
//     catch-all answering http.NotFound's exact bytes (echo never
//     auto-redirects trailing slashes), so sso.WithRouter(adapter) is
//     wire-interchangeable with NewStdRouter(). Replacing
//     engine.HTTPErrorHandler (or registering routes on the engine) AFTER
//     construction overrides the normalization — the embedder then owns
//     the unmatched bytes and the byte-identity guarantee is gone.
//  2. RegisterGated: a gate registered through the adapter runs BEFORE any
//     SSO middleware, and a gated-off route is byte-identical to a
//     never-registered one. The gate returns a swallowed sentinel that the
//     constructor-installed delegating HTTPErrorHandler ignores (the 404
//     is already written).
//  3. Middleware split: adapter-level Use() snapshots at registration (a
//     later Use() does not affect already-registered routes), while
//     engine-level middleware (engine.Use) applies to everything including
//     SSO routes.
func newAdapter(engine *echo.Echo) sso.Router {
	return echoadapter.NewEchoRouter(engine)
}

// newSSOServer wires the minimal protocol surface and mounts it on the
// adapter.
func newSSOServer(adapter sso.Router) *sso.Server {
	users, clients, pw, issuer := seedIdentity()
	return sso.NewServer(
		sso.WithRouter(adapter), // SSO mounts onto the SAME engine
		sso.WithIssuer(issuerName),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
	)
}

// seedIdentity builds the demo user, client, password authenticator, and
// signing issuer.
func seedIdentity() (*defaultimpl.MemoryUserProvider, *defaultimpl.MemoryClientStore, *authenticators.PasswordAuthenticator, *defaultimpl.Ed25519JWTIssuer) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    clientID,
		Secret:                clientSecret,
		RedirectURIs:          []string{redirectURI},
		AllowedScopes:         []string{"openid"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
			if user == "alice" && pass == "wonderland" {
				return &sso.AuthResult{UserID: "alice", Provider: "password"}, nil
			}
			return nil, errors.New("bad credentials")
		}),
	)
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(issuerName),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	return users, clients, pw, issuer
}

func main() {
	log.Printf("embed-echo listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, newApp()))
}
