// Command playground starts a fully-wired demo SSO server and serves a
// single-page, zero-dependency Web UI that lists every feature and lets
// you fire real requests against the live endpoints from the browser.
//
//	go run ./examples/playground            # then open http://localhost:8090
//
// Everything is in-memory and seeded with a demo user (alice / secret)
// and a demo client (playground-client / playground-secret). Nothing here
// is production wiring — it is a learning/▶try-it surface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "embed"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

//go:embed index.html
var indexHTML []byte

const (
	demoUser     = "alice"
	demoPassword = "secret"
	demoClient   = "playground-client"
	demoSecret   = "playground-secret"
)

func main() {
	listen := flag.String("listen", ":8090", "HTTP listen address")
	flag.Parse()

	issuerName := "http://localhost" + *listen

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID: demoUser, Name: "Alice Example", Email: "alice@example.com",
	})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    demoClient,
		Secret:                demoSecret,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         sso.TokenStrategyJWT,
		AllowedScopes:         []string{"openid", "profile", "email", "offline_access"},
		RedirectURIs:          []string{"http://localhost" + *listen + "/callback"},
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, username, password string) (*sso.AuthResult, error) {
			if username == demoUser && password == demoPassword {
				return &sso.AuthResult{UserID: demoUser, Provider: "password"}, nil
			}
			return nil, errors.New("invalid credentials")
		},
	))

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(issuerName),
		defaultimpl.WithEd25519TokenTTL(10*time.Minute),
	)

	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithIssuer(issuerName),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer(sso.TokenStrategyJWT, issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy(sso.TokenStrategyJWT),
		// OAuth/OIDC stores so the matching endpoints are live.
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 10*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), 24*time.Hour),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), 10*time.Minute, 5*time.Second, ""),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), 60*time.Second),
		sso.WithAuditRecorder(audit.New(audit.NewMemorySink(500))),
	)

	ssoHandler := srv.Handler()

	// Serve the playground page at / and /playground; everything else is
	// the live SSO handler. The page calls the same-origin endpoints.
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "/" || p == "/playground" || p == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(indexHTML)
			return
		}
		ssoHandler.ServeHTTP(w, r)
	})

	banner(*listen, issuerName)
	log.Fatal(http.ListenAndServe(*listen, root))
}

func banner(listen, issuer string) {
	url := "http://localhost" + listen
	fmt.Println(strings.Repeat("─", 64))
	fmt.Println("  SSO Playground")
	fmt.Printf("  Open:    %s\n", url)
	fmt.Printf("  Issuer:  %s\n", issuer)
	fmt.Printf("  Demo user:   %s / %s\n", demoUser, demoPassword)
	fmt.Printf("  Demo client: %s / %s\n", demoClient, demoSecret)
	fmt.Println(strings.Repeat("─", 64))
}
