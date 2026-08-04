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

	"github.com/yangwb1123/snaplink/docs/examples/appcore"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/local"
	"github.com/yangwb1123/snaplink/platform/audit"
)

func main() {
	listen := flag.String("listen", ":7070", "HTTP listen address")
	flag.Parse()
	handler, token, err := buildDemo()
	if err != nil {
		log.Fatalf("issue demo token: %v", err)
	}
	printInstructions(*listen, token)
	mux := http.NewServeMux()
	mux.HandleFunc("/items", handler.ListItems)
	if err := http.ListenAndServe(*listen, mux); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}

func buildDemo() (*appcore.Handler, string, error) {
	// 1. SDK building blocks — these live entirely inside this process.
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("embedded-app"))
	sessions := defaultimpl.NewMemorySessionManager()
	recorder := audit.New(
		audit.NewMemorySink(1000),
		audit.WithErrorHandler(func(err error) { log.Printf("audit: %v", err) }),
	)

	// 2. Permission data: in-memory roles, menus, and assignments. The demo
	// token is minted WITH an `aud` claim (RFC 8707 resource indicators →
	// the defaultimpl aud path; single element → compact string form), and
	// appcore.Handler reads aud[0] for the authz client resolution — so
	// permissions are registered under the real client ID, and
	// local.WithExpectedAud proves the audience gate end-to-end.
	const appClientID = "embedded-app"
	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(context.Background(), appClientID, permissions.Role{
		Code:        "viewer",
		Permissions: []string{"items:read"},
	})
	_ = prov.AssignRoles(context.Background(), "user-demo", appClientID, []string{"viewer"})

	// 3. Wire the ssoclient layer — all LOCAL implementations.
	handler := &appcore.Handler{
		Auth: local.NewAuthClient(issuer,
			local.WithSessionManager(sessions),
			local.WithExpectedAud(appClientID)),
		Authz: local.NewAuthzClient(prov),
		Audit: local.NewAuditClient(recorder),
	}

	// 4. Mint a demo token so this can be smoke-tested in isolation. The
	// Resources field is the RFC 8707 resource-indicator path — the mint
	// path that stamps `aud` on access tokens.
	tok, err := issuer.Issue(context.Background(), &sso.Subject{
		ID:        "user-demo",
		Resources: []string{appClientID},
	}, []string{"read"})
	if err != nil {
		return nil, "", err
	}
	return handler, tok.AccessToken, nil
}

func printInstructions(listen, token string) {
	fmt.Println("---")
	fmt.Println("embedded-app (local mode) — no external SSO server needed")
	fmt.Printf("listen:        %s\n", listen)
	fmt.Printf("demo bearer:   %s\n", token)
	fmt.Printf("try: curl -H 'Authorization: Bearer <token>' http://localhost%s/items\n", listen)
	fmt.Println("---")
}
