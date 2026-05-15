// Package http is a releases.HealthProbe that GETs a URL and treats
// any 2xx response as healthy. Useful behind an /-/health or /readyz
// endpoint the freshly-pinned backend exposes.
//
// The probe is fully synchronous and uses a per-attempt timeout
// (defaults to 5s when Client is nil). The Registry handles the
// retry loop + backoff — implementations only see a single attempt.
package http

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"time"

	"github.com/snaplink/sso/releases"
)

const defaultTimeout = 5 * time.Second

// Probe is a releases.HealthProbe backed by an HTTP GET.
type Probe struct {
	URL    string         // the URL to GET; required
	Client *nethttp.Client // optional; when nil a fresh client with defaultTimeout is used
}

// New constructs a Probe targeting url.
func New(url string) *Probe { return &Probe{URL: url} }

func (p *Probe) Probe(ctx context.Context, _ *releases.Release) error {
	if p.URL == "" {
		return errors.New("releases/probe/http: URL required")
	}
	client := p.Client
	if client == nil {
		client = &nethttp.Client{Timeout: defaultTimeout}
	}
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, p.URL, nil)
	if err != nil {
		return fmt.Errorf("releases/probe/http: req: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("releases/probe/http: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("releases/probe/http: status %d", resp.StatusCode)
	}
	return nil
}

// Compile-time interface check.
var _ releases.HealthProbe = (*Probe)(nil)
