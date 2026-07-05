package securityverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// HTTP JWKS fetching, shared by every cloud workload-identity preset (GCP
// today; AWS/Azure when added — see workload_identity.go's package doc) so
// none of them hand-roll an HTTP client + cache. Split out of
// workload_identity.go to keep that file focused on the verify-and-map core.

// DefaultJWKSCacheTTL bounds how long a fetched JWKS is reused before a
// re-fetch is attempted. Cloud IdPs rotate signing keys on the order of
// days/weeks with an overlap window (Google publishes several concurrently
// valid keys), so an hour of caching is well inside that overlap.
const DefaultJWKSCacheTTL = time.Hour

// DefaultJWKSMaxStaleAge bounds fail-open reuse of a cached JWKS when the
// cloud endpoint is unreachable — long enough to ride out a real outage,
// short enough that a permanently-down endpoint eventually fails closed
// (an unbounded stale-forever cache would silently keep trusting a key set
// the operator can no longer see or rotate away from).
const DefaultJWKSMaxStaleAge = 24 * time.Hour

const (
	defaultJWKSFetchTimeout = 10 * time.Second
	// maxJWKSResponseBytes bounds the read: a real JWKS document is a few
	// KB; this just stops a misbehaving/compromised endpoint from
	// streaming an unbounded body at the verifier.
	maxJWKSResponseBytes = 1 << 20
)

// HTTPJWKSSource fetches a JWKS document over HTTPS and caches it, so every
// /token request doesn't pay a network round trip to the cloud provider.
// Implements JWKSSource — the SAME interface the SPIFFE trust-bundle path
// uses — so it plugs in anywhere a JWKSSource is accepted.
type HTTPJWKSSource struct {
	url         string
	client      *http.Client
	cacheTTL    time.Duration
	maxStaleAge time.Duration

	mu        sync.Mutex
	cached    []core.JWK
	fetchedAt time.Time
}

// HTTPJWKSSourceOption tunes an HTTPJWKSSource.
type HTTPJWKSSourceOption func(*HTTPJWKSSource)

// WithJWKSCacheTTL overrides DefaultJWKSCacheTTL.
func WithJWKSCacheTTL(ttl time.Duration) HTTPJWKSSourceOption {
	return func(h *HTTPJWKSSource) {
		if ttl > 0 {
			h.cacheTTL = ttl
		}
	}
}

// WithJWKSMaxStaleAge overrides DefaultJWKSMaxStaleAge.
func WithJWKSMaxStaleAge(age time.Duration) HTTPJWKSSourceOption {
	return func(h *HTTPJWKSSource) {
		if age > 0 {
			h.maxStaleAge = age
		}
	}
}

// WithJWKSHTTPClient overrides the default HTTP client (tests point this at
// an httptest server; production callers can tune TLS/proxy settings).
func WithJWKSHTTPClient(client *http.Client) HTTPJWKSSourceOption {
	return func(h *HTTPJWKSSource) {
		if client != nil {
			h.client = client
		}
	}
}

// NewHTTPJWKSSource builds a caching HTTPS JWKS fetcher for url.
func NewHTTPJWKSSource(url string, opts ...HTTPJWKSSourceOption) *HTTPJWKSSource {
	h := &HTTPJWKSSource{
		url:         url,
		client:      &http.Client{Timeout: defaultJWKSFetchTimeout},
		cacheTTL:    DefaultJWKSCacheTTL,
		maxStaleAge: DefaultJWKSMaxStaleAge,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// GetJWKS returns the cached key set when still fresh; otherwise attempts a
// re-fetch. A re-fetch failure falls back to a cached-but-stale set (bounded
// by maxStaleAge) rather than failing every in-flight request the instant
// the cloud endpoint hiccups — the same "peer-key adoption... decode
// failure OPEN" resilience trade-off signingkeys/ makes for JWKS-shaped
// trust material. Only when there is NO usable cache (first fetch, or the
// cache has exceeded maxStaleAge) does a fetch error propagate and fail the
// request closed.
func (h *HTTPJWKSSource) GetJWKS(ctx context.Context) ([]core.JWK, error) {
	cached, fresh, usable := h.snapshot()
	if fresh {
		return cached, nil
	}

	keys, err := h.fetch(ctx)
	if err != nil {
		if usable {
			return cached, nil
		}
		return nil, err
	}

	h.mu.Lock()
	h.cached = keys
	h.fetchedAt = time.Now()
	h.mu.Unlock()
	return append([]core.JWK(nil), keys...), nil
}

// snapshot reads the cache under lock, reporting whether it is still fresh
// (skip a fetch entirely) and whether it is at least usable as a stale
// fallback (within maxStaleAge) should the fetch below fail.
func (h *HTTPJWKSSource) snapshot() (cached []core.JWK, fresh, usable bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached == nil {
		return nil, false, false
	}
	age := time.Since(h.fetchedAt)
	cached = append([]core.JWK(nil), h.cached...)
	return cached, age < h.cacheTTL, age < h.maxStaleAge
}

func (h *HTTPJWKSSource) fetch(ctx context.Context) ([]core.JWK, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, fmt.Errorf("workload_identity: build jwks request: %w", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("workload_identity: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("workload_identity: jwks endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("workload_identity: read jwks response: %w", err)
	}
	var doc struct {
		Keys []core.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("workload_identity: parse jwks: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("workload_identity: jwks response has no keys")
	}
	return doc.Keys, nil
}

var _ JWKSSource = (*HTTPJWKSSource)(nil)
