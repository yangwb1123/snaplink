// Command healthcheck is the distroless-runtime health probe for the OIDC
// conformance harness (test/oidc-conformance): it GETs the server's /health
// endpoint and exits 0 only on HTTP 200. Built fully static (CGO_ENABLED=0)
// so it runs on gcr.io/distroless/static with no shell, wget or libc. Used
// as the docker-compose healthcheck for the sso-server container.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

const healthURL = "http://127.0.0.1:8080/health"

func main() {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		os.Exit(1)
	}
	os.Exit(0)
}
