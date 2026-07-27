package remote

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/yangwb1123/snaplink/shared/core"
)

// minForcedFetchInterval is the minimum time between on-demand (cache-miss)
// JWKS fetches. Prevents amplification attacks where many requests with
// distinct unknown kids trigger sequential upstream fetches.
const minForcedFetchInterval = 10 * time.Second

// DefaultJWKSRefreshInterval is how often the cache re-fetches by default.
// Short enough that key rotation propagates promptly; long enough to dodge
// noisy reloads under load.
const DefaultJWKSRefreshInterval = 60 * time.Second

// defaultRefreshFetchTimeout bounds a background refresh tick when the
// configured *http.Client carries no Timeout of its own. net/http documents
// http.Client.Timeout == 0 as "no [client-side] timeout" — a legitimate,
// commonly-recommended configuration for a caller that instead bounds each
// call via its context. refreshLoop must NOT reuse that 0 verbatim as a
// context.WithTimeout duration: unlike http.Client.Timeout, a zero (or
// negative) context.WithTimeout duration means the deadline is already in
// the past, so the derived context is canceled before fetch ever runs —
// silently and permanently breaking every background refresh tick for the
// lifetime of the cache (see WithJWKSHTTPClient).
const defaultRefreshFetchTimeout = 10 * time.Second

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

	mu                  sync.RWMutex
	keys                map[string]core.JWK
	loaded              bool
	lastForcedFetch     time.Time // debounce: tracks last on-demand miss fetch
	forcedFetchInterval time.Duration
	// etag is the validator from the last 200 response; sent back as
	// If-None-Match so an unrotated key set costs a 304 with no body
	// (the JWKS doc can be tens of KB with several RSA keys published).
	etag string

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

// WithJWKSForcedFetchInterval overrides minForcedFetchInterval for testing.
// A zero value disables the debounce entirely (every cache miss triggers a
// fetch). This option is intended for tests only.
func WithJWKSForcedFetchInterval(d time.Duration) JWKSOption {
	return func(j *JWKSCache) { j.forcedFetchInterval = d }
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

// GetJWK returns the raw JWK for kid, fetching on first call or cache miss.
// It is the multi-algorithm accessor for callers (the rs resource-server SDK,
// this package's own ValidateToken) that verify via security.VerifyCompactJWS
// and therefore need the JWK itself, not a pre-decoded Ed25519 key.
func (j *JWKSCache) GetJWK(ctx context.Context, kid string) (core.JWK, error) {
	return j.getJWK(ctx, kid)
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
	debounce := minForcedFetchInterval
	if j.forcedFetchInterval > 0 {
		debounce = j.forcedFetchInterval
	}
	if loaded && time.Since(last) < debounce {
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

// StartRefresher ties the cache lifetime to ctx: when ctx is canceled the
// cache closes exactly as if Close had been called. The background refresher
// itself always starts inside NewJWKSCache — this is the optional hook for
// callers that manage lifecycles through contexts rather than explicit Close
// (e.g. an RS process shutting everything down off one root context).
func (j *JWKSCache) StartRefresher(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			j.Close()
		case <-j.done:
		}
	}()
}

func (j *JWKSCache) refreshLoop() {
	for {
		t := time.NewTimer(jitteredInterval(j.refreshInterval))
		select {
		case <-j.done:
			t.Stop()
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), j.refreshFetchTimeout())
			_ = j.fetch(ctx)
			cancel()
		}
	}
}

// refreshFetchTimeout bounds one background refresh tick. It defers to the
// configured client's own Timeout when the caller set one (matching the
// historical behavior for the common case), and falls back to
// defaultRefreshFetchTimeout when the client declares no timeout of its own
// (Timeout <= 0) — see WithJWKSHTTPClient and defaultRefreshFetchTimeout for
// why 0 cannot be passed straight through to context.WithTimeout.
func (j *JWKSCache) refreshFetchTimeout() time.Duration {
	if j.client.Timeout > 0 {
		return j.client.Timeout
	}
	return defaultRefreshFetchTimeout
}

// jitteredInterval spreads each refresh across +/-10% of the base interval so
// a fleet of replicas restarted together (a deploy) does not re-synchronize
// into a thundering herd against the JWKS endpoint on every tick.
func jitteredInterval(base time.Duration) time.Duration {
	spread := int64(base) / 10
	if spread <= 0 {
		return base
	}
	return base + time.Duration(rand.Int64N(2*spread+1)-spread)
}

func (j *JWKSCache) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return err
	}
	j.mu.RLock()
	etag, loaded := j.etag, j.loaded
	j.mu.RUnlock()
	// If-None-Match only once a key set is actually held: a 304 with no
	// cached keys would strand the cache empty forever.
	if etag != "" && loaded {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("ssoclient/remote: jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		return nil // validator matched — cached keys stay authoritative
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ssoclient/remote: jwks status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	keys, err := decodeJWKSKeys(body)
	if err != nil {
		return err
	}
	j.mu.Lock()
	j.keys = keys
	j.loaded = true
	j.etag = resp.Header.Get("ETag")
	j.mu.Unlock()
	return nil
}

// decodeJWKSKeys parses a JWKS document into the kid-indexed verify map.
func decodeJWKSKeys(body []byte) (map[string]core.JWK, error) {
	var doc struct {
		Keys []core.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("ssoclient/remote: jwks parse: %w", err)
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
		return nil, errors.New("ssoclient/remote: jwks contained no usable asymmetric keys")
	}
	return keys, nil
}
