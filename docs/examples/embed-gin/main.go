// Command embed-gin demonstrates the real gin embedding shape: the embedder
// owns a gin.Engine, the adapter wraps it, and the SSO server mounts on the
// SAME engine alongside embedder business routes.
//
// Run with:
//
//	go run ./docs/examples/embed-gin
//	curl http://localhost:8083/hello
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

	"github.com/gin-gonic/gin"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	ginadapter "github.com/yangwb1123/snaplink/interfaces/adapters/gin"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	issuerName   = "embed-sso"
	clientID     = "embed-client"
	clientSecret = "embed-secret"
	redirectURI  = "http://localhost:9999/callback"
	addr         = ":8083"
)

// newApp assembles the embedding: engine -> adapter -> SSO server, plus the
// embedder's own routes. main calls it; the smoke test exercises the SAME
// wiring.
func newApp() http.Handler {
	srv := newSSOServer(newAdapter(newEmbeddedEngine()))
	return srv.Handler() // probe mux + SDK middleware chain + adapter
}

// newAdapter wraps the embedder-owned engine. The three delivery semantics
// demonstrated here are the adapter contract (docs/adapters.md §1-§5):
//
//  1. 404 normalization: NewGinRouter pins HandleMethodNotAllowed and
//     RedirectTrailingSlash off and installs a NoRoute handler answering
//     http.NotFound's exact bytes, so sso.WithRouter(adapter) is
//     wire-interchangeable with NewStdRouter(). Assigning engine.NoRoute /
//     engine.HandleMethodNotAllowed AFTER construction replaces the
//     normalization — the embedder then owns the unmatched bytes and the
//     byte-identity guarantee is gone.
//  2. RegisterGated: a gate registered through the adapter runs BEFORE any
//     SSO middleware, and a gated-off route is byte-identical to a
//     never-registered one (no header leaks). gin's c.Abort() inside the
//     gate is mandatory — without it gin's Next() loop would run the
//     wrapped handler anyway.
//  3. Middleware split: adapter-level Use() snapshots at registration (a
//     later Use() does not affect already-registered routes), while
//     engine-level middleware (engine.Use) applies to everything including
//     SSO routes.
func newAdapter(engine *gin.Engine) sso.Router {
	return ginadapter.NewGinRouter(engine)
}

// newEmbeddedEngine builds the embedder-owned engine with its business
// routes. gin.New() is deliberate: gin.Default() attaches Recovery, whose
// deferred handler sits INNERMOST (defer LIFO) and would catch panics from
// SSO handlers first, writing gin's plain-text 500 instead of the SDK's
// normalized JSON. With gin.New() the panic unwinds to the SDK's outermost
// wrapPanicRecovery, so every backend answers a panic identically. Set
// GIN_MODE=release to silence debug-mode route printing in production.
func newEmbeddedEngine() *gin.Engine {
	engine := gin.New()
	engine.GET("/hello", func(c *gin.Context) {
		c.String(http.StatusOK, "hello from the embedder")
	})
	engine.GET("/boom", func(c *gin.Context) {
		panic("embedder panic — recovered by the SDK, not gin")
	})
	return engine
}

// newSSOServer wires the minimal protocol surface and mounts it on the
// adapter. The contract comments below are the adapter delivery semantics
// (see docs/adapters.md).
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
	log.Printf("embed-gin listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, newApp()))
}
