package security

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"
)

// UpstreamClientConfig controls how the SSO server talks to external
// upstream services (OIDC providers, SAML IdPs, CAEP receivers, MDS
// endpoints, federation fetch). Every upstream call in the codebase
// should use [NewUpstreamClient] instead of raw &http.Client{} so
// timeouts, retries, and rate limits are consistent and auditable.
type UpstreamClientConfig struct {
	// Timeout is the per-request deadline. 0 = default (30s).
	Timeout time.Duration

	// MaxIdleConns controls the connection pool size. 0 = default (5).
	MaxIdleConns int

	// IdleConnTimeout is how long an idle connection stays in the
	// pool. 0 = default (90s).
	IdleConnTimeout time.Duration

	// SkipTLSVerify disables TLS certificate verification (DEV ONLY).
	SkipTLSVerify bool
}

// DefaultUpstreamTimeout is the default per-request timeout for
// external HTTP calls. 30 seconds is generous enough for any
// OIDC/SAML/CAEP round-trip but prevents a hanging upstream from
// pinning a goroutine indefinitely.
const DefaultUpstreamTimeout = 30 * time.Second

// NewUpstreamClient builds an http.Client pre-configured for talking
// to external upstream services. The client has:
//
//   - A configurable per-request timeout (default 30s)
//   - A shared connection pool (default 5 idle conns, 90s idle TTL)
//   - Optional TLS verification skip (DEV ONLY)
//
// Every HTTP call to an external service in the SSO codebase should
// use this factory instead of raw &http.Client{} so operators get
// consistent timeout and connection-pool behavior.
func NewUpstreamClient(cfg UpstreamClientConfig) *http.Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultUpstreamTimeout
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 5
	}
	idleTimeout := cfg.IdleConnTimeout
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = maxIdle
	transport.IdleConnTimeout = idleTimeout
	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// UpstreamDo executes an HTTP request with the given client, wrapping
// the call with context-based cancellation propagation. Returns the
// response, or an error wrapping context.DeadlineExceeded when the
// upstream didn't respond in time.
func UpstreamDo(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	return client.Do(req)
}
