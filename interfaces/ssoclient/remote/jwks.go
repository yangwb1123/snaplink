package remote

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/snaplink/sso/shared/core"
)

// minForcedFetchInterval is the minimum time between on-demand (cache-miss)
// JWKS fetches. Prevents amplification attacks where many requests with
// distinct unknown kids trigger sequential upstream fetches.
const minForcedFetchInterval = 10 * time.Second

// DefaultJWKSRefreshInterval is how often the cache re-fetches by default.
// Short enough that key rotation propagates promptly; long enough to dodge
// noisy reloads under load.
const DefaultJWKSRefreshInterval = 60 * time.Second

// JWKSCache fetches and caches an SSO server's JWKS document. Thread-safe.
// Background refresh runs until Close is called or the supplied context is
// canceled. First Get triggers a synchronous fetch so callers don't see a
// transient empty key set on startup.
//
// The cache stores the raw asymmetric JWKs (OKP/EC/RSA) keyed by kid; the
// per-kid TYPE (and thus the verification algorithm) is resolved at validate
// time by security.VerifyCompactJWS, so a server that signs with ES256/RS256/
// PS256 (the FAPI choice, or any AWS/Azure-KMS key that cannot be Ed25519) is
// verified exactly like the EdDSA default.
type JWKSCache struct {
	url    string
	client *http.Client

	mu              sync.RWMutex
	keys            map[string]core.JWK
	loaded          bool
	lastForcedFetch time.Time // debounce: tracks last on-demand miss fetch

	refreshInterval time.Duration
	closeOnce       sync.Once
	done            chan struct{}

	// sfg deduplicates concurrent on-demand fetches: N simultaneous requests
	// for unknown kids collapse to one upstream call (singleflight).
	sfg singleflight.Group
}

type JWKSOption func(*JWKSCache)

// WithJWKSHTTPClient lets callers inject a tuned *http.Client (timeouts,
// proxy, mTLS) for the JWKS fetch path.
func WithJWKSHTTPClient(c *http.Client) JWKSOption {
	return func(j *JWKSCache) {
		if c != nil {
			j.client = c
		}
	}
}

// WithJWKSRefreshInterval overrides DefaultJWKSRefreshInterval.
func WithJWKSRefreshInterval(d time.Duration) JWKSOption {
	return func(j *JWKSCache) { j.refreshInterval = d }
}

// NewJWKSCache constructs the cache and starts the background refresher.
// url is typically "<sso-server>/.well-known/jwks.json".
func NewJWKSCache(url string, opts ...JWKSOption) *JWKSCache {
	j := &JWKSCache{
		url:             url,
		client:          &http.Client{Timeout: 5 * time.Second},
		keys:            make(map[string]core.JWK),
		refreshInterval: DefaultJWKSRefreshInterval,
		done:            make(chan struct{}),
	}
	for _, opt := range opts {
		opt(j)
	}
	go j.refreshLoop()
	return j
}

// Get returns the Ed25519 public key for kid. It is retained for backward
// compatibility with callers built before the cache went multi-algorithm; it
// resolves ONLY OKP/Ed25519 keys and errors for EC/RSA kids. The in-package
// ValidateToken path instead uses getJWK + security.VerifyCompactJWS, which
// verifies the full asymmetric alg set the server can emit.
//
// On first call (or cache miss), fetches the JWKS synchronously so callers
// don't race the background refresher.
func (j *JWKSCache) Get(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	jwk, err := j.getJWK(ctx, kid)
	if err != nil {
		return nil, err
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("ssoclient/remote: kid %q is not an Ed25519 key", kid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ssoclient/remote: kid %q malformed Ed25519 key", kid)
	}
	return ed25519.PublicKey(raw), nil
}

// getJWK returns the raw JWK for kid, fetching on first call or cache miss.
// Two defenses against amplification from attacker-controlled kids:
//   - singleflight: N concurrent miss requests collapse to one upstream call
//   - debounce: successive misses are rate-limited to one re-fetch per
//     minForcedFetchInterval (prevents sequential bursts of distinct unknown
//     kids each triggering their own upstream request)
func (j *JWKSCache) getJWK(ctx context.Context, kid string) (core.JWK, error) {
	j.mu.RLock()
	loaded := j.loaded
	if loaded {
		if k, ok := j.keys[kid]; ok {
			j.mu.RUnlock()
			return k, nil
		}
	}
	last := j.lastForcedFetch
	j.mu.RUnlock()

	// Debounce: if we fetched recently and the kid isn't there, don't re-fetch.
	// New legitimate keys propagate on the next background refresh tick instead.
	if loaded && time.Since(last) < minForcedFetchInterval {
		return core.JWK{}, fmt.Errorf("ssoclient/remote: kid %q not in JWKS", kid)
	}

	// Singleflight: collapse all concurrent on-demand fetches to one HTTP call.
	_, err, _ := j.sfg.Do("fetch", func() (any, error) {
		j.mu.Lock()
		j.lastForcedFetch = time.Now()
		j.mu.Unlock()
		return nil, j.fetch(ctx)
	})
	if err != nil {
		return core.JWK{}, err
	}

	j.mu.RLock()
	defer j.mu.RUnlock()
	k, ok := j.keys[kid]
	if !ok {
		return core.JWK{}, fmt.Errorf("ssoclient/remote: kid %q not in JWKS", kid)
	}
	return k, nil
}

// Close stops the background refresher. Safe to call more than once.
func (j *JWKSCache) Close() { j.closeOnce.Do(func() { close(j.done) }) }

func (j *JWKSCache) refreshLoop() {
	t := time.NewTicker(j.refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-j.done:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), j.client.Timeout)
			_ = j.fetch(ctx)
			cancel()
		}
	}
}

func (j *JWKSCache) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return err
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("ssoclient/remote: jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ssoclient/remote: jwks status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var doc struct {
		Keys []core.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("ssoclient/remote: jwks parse: %w", err)
	}
	keys := make(map[string]core.JWK, len(doc.Keys))
	for _, k := range doc.Keys {
		// Keep only asymmetric signing keys we can verify; the kty/crv↔alg
		// consistency check itself lives in security.VerifyCompactJWS. Drop
		// keys with no kid (the cache is kid-indexed) and the JWE encryption
		// keys the server also publishes (use:enc — never used to verify a
		// token signature).
		if k.Kid == "" || k.Use == "enc" {
			continue
		}
		switch k.Kty {
		case "OKP", "EC", "RSA":
			keys[k.Kid] = k
		}
	}
	if len(keys) == 0 {
		return errors.New("ssoclient/remote: jwks contained no usable asymmetric keys")
	}
	j.mu.Lock()
	j.keys = keys
	j.loaded = true
	j.mu.Unlock()
	return nil
}
