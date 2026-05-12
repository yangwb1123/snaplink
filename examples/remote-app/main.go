// remote-app demonstrates running with ssoclient/remote — the App calls a
// central SSO server for everything. Run cmd/sso-server first.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/snaplink/sso/examples/appcore"
	"github.com/snaplink/sso/ssoclient/remote"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	listen := flag.String("listen", ":7070", "HTTP listen address")
	jwksURL := flag.String("jwks", "http://localhost:8080/.well-known/jwks.json", "SSO server JWKS endpoint")
	grpcAddr := flag.String("grpc", "localhost:8081", "SSO server gRPC address")
	flag.Parse()

	// 1. Open ONE gRPC connection; authz + audit share it.
	conn, err := grpc.NewClient(*grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("grpc dial: %v", err)
	}
	defer conn.Close()

	// 2. JWKS cache fetches the SSO server's public keys, refreshed periodically.
	jwks := remote.NewJWKSCache(*jwksURL)
	defer jwks.Close()

	// 3. Wire the ssoclient layer — all REMOTE implementations.
	// IMPORTANT: appcore.Handler is identical to embedded-app's; only this
	// wiring differs.
	handler := &appcore.Handler{
		Auth:  remote.NewAuthClient(jwks),
		Authz: remote.NewAuthzClient(conn),
		Audit: remote.NewAuditClient(conn),
	}

	fmt.Println("---")
	fmt.Println("remote-app (remote mode) — depends on running cmd/sso-server")
	fmt.Printf("listen:        %s\n", *listen)
	fmt.Printf("jwks:          %s\n", *jwksURL)
	fmt.Printf("grpc:          %s\n", *grpcAddr)
	fmt.Printf("login first via SSO server's POST /auth/login, then:\n")
	fmt.Printf("  curl -H 'Authorization: Bearer <token>' http://localhost%s/items\n", *listen)
	fmt.Println("---")

	mux := http.NewServeMux()
	mux.HandleFunc("/items", handler.ListItems)
	if err := http.ListenAndServe(*listen, mux); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}
