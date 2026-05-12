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
)

// DefaultJWKSRefreshInterval is how often the cache re-fetches by default.
// Short enough that key rotation propagates promptly; long enough to dodge
// noisy reloads under load.
const DefaultJWKSRefreshInterval = 60 * time.Second

// jwk is the minimal JWK shape we need (Ed25519 only).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// JWKSCache fetches and caches an SSO server's JWKS document. Thread-safe.
// Background refresh runs until Close is called or the supplied context is
// canceled. First Get triggers a synchronous fetch so callers don't see a
// transient empty key set on startup.
type JWKSCache struct {
	url    string
	client *http.Client

	mu     sync.RWMutex
	keys   map[string]ed25519.PublicKey
	loaded bool

	refreshInterval time.Duration
	closeOnce       sync.Once
	done            chan struct{}
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
		keys:            make(map[string]ed25519.PublicKey),
		refreshInterval: DefaultJWKSRefreshInterval,
		done:            make(chan struct{}),
	}
	for _, opt := range opts {
		opt(j)
	}
	go j.refreshLoop()
	return j
}

// Get returns the key for kid. On first call (or cache miss), fetches the
// JWKS synchronously so callers don't race the background refresher.
func (j *JWKSCache) Get(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	j.mu.RLock()
	loaded := j.loaded
	if loaded {
		if k, ok := j.keys[kid]; ok {
			j.mu.RUnlock()
			return k, nil
		}
	}
	j.mu.RUnlock()

	// Miss or first call — fetch (also covers key rotation where kid is new).
	if err := j.fetch(ctx); err != nil {
		return nil, err
	}

	j.mu.RLock()
	defer j.mu.RUnlock()
	k, ok := j.keys[kid]
	if !ok {
		return nil, fmt.Errorf("ssoclient/remote: kid %q not in JWKS", kid)
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ssoclient/remote: jwks status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("ssoclient/remote: jwks parse: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.X == "" || k.Kid == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		if len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(keys) == 0 {
		return errors.New("ssoclient/remote: jwks contained no usable Ed25519 keys")
	}
	j.mu.Lock()
	j.keys = keys
	j.loaded = true
	j.mu.Unlock()
	return nil
}
