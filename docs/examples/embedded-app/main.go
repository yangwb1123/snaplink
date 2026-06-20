// embedded-app demonstrates running with ssoclient/local — the App embeds
// the SDK in-process and owns its own user / permission / audit state.
// No external SSO server is required.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/snaplink/sso/docs/examples/appcore"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/interfaces/ssoclient/local"
	"github.com/snaplink/sso/platform/audit"
)

func main() {
	listen := flag.String("listen", ":7070", "HTTP listen address")
	flag.Parse()

	// 1. SDK building blocks — these live entirely inside this process.
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("embedded-app"))
	sessions := defaultimpl.NewMemorySessionManager()
	recorder := audit.New(
		audit.NewMemorySink(1000),
		audit.WithErrorHandler(func(err error) { log.Printf("audit: %v", err) }),
	)

	// 2. Permission data: in-memory roles, menus, and assignments.
	// We register under clientID="" because the demo token below has no
	// `aud` claim, and appcore.Handler reads aud[0] — so the role MUST be
	// findable under "" for this self-contained demo. A real App would
	// either set aud at issue-time or pass its known client_id explicitly.
	const appClientID = ""
	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(context.Background(), appClientID, permissions.Role{
		Code:        "viewer",
		Permissions: []string{"items:read"},
	})
	_ = prov.AssignRoles(context.Background(), "user-demo", appClientID, []string{"viewer"})

	// 3. Wire the ssoclient layer — all LOCAL implementations.
	handler := &appcore.Handler{
		Auth:  local.NewAuthClient(issuer, local.WithSessionManager(sessions)),
		Authz: local.NewAuthzClient(prov),
		Audit: local.NewAuditClient(recorder),
	}

	// 4. Mint a demo token so this can be smoke-tested in isolation.
	tok, err := issuer.Issue(context.Background(), &sso.Subject{ID: "user-demo"}, []string{"read"})
	if err != nil {
		log.Fatalf("issue demo token: %v", err)
	}
	fmt.Println("---")
	fmt.Println("embedded-app (local mode) — no external SSO server needed")
	fmt.Printf("listen:        %s\n", *listen)
	fmt.Printf("demo bearer:   %s\n", tok.AccessToken)
	fmt.Printf("try: curl -H 'Authorization: Bearer <token>' http://localhost%s/items\n", *listen)
	fmt.Println("---")

	mux := http.NewServeMux()
	mux.HandleFunc("/items", handler.ListItems)
	if err := http.ListenAndServe(*listen, mux); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}
