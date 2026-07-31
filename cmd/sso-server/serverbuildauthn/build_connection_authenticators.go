package serverbuildauthn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// DefaultConnectionAuthCacheSize bounds the per-process built-authenticator
// cache. Each entry is one tenant's upstream IdP connection — deployments
// with more live connections than this just rebuild on eviction (correctness
// is unaffected; the build is pure config translation, no network).
const DefaultConnectionAuthCacheSize = 256

// connectionAuthEntry pairs a built authenticator with the fingerprint of the
// Connection state it was built from. The Connection model carries no
// UpdatedAt/version, so the fingerprint IS the version signal: an admin
// config change produces a different fingerprint and forces a rebuild.
type connectionAuthEntry struct {
	fingerprint string
	auth        core.Authenticator
}

// ConnectionAuthenticatorFactory is the production
// connections.AuthenticatorFactory: it translates a resolved TypeOIDC
// Connection's Config into an OIDCFederationAuthenticator (the same
// construction path the static YAML oidc_federation providers use) and caches
// the result so the login hot path doesn't re-validate config per request.
//
// TypeSAML returns connections.ErrConnectionTypeUnsupported: the SAML stack
// is a nested Go module (infrastructure/saml) the core binary composes via
// its own handler registry, so a SAML connection cannot be represented as a
// core.Authenticator here — it routes through the SAML module's endpoints.
type ConnectionAuthenticatorFactory struct {
	auditor *audit.Recorder
	logger  spi.Logger
	linker  authenticators.UserLinker
	max     int

	mu    sync.Mutex
	cache map[string]connectionAuthEntry
}

// NewConnectionAuthenticatorFactory returns the production factory. auditor
// may be nil (build failures are then log-only); maxEntries <= 0 uses
// DefaultConnectionAuthCacheSize.
func NewConnectionAuthenticatorFactory(auditor *audit.Recorder, logger spi.Logger, maxEntries int) *ConnectionAuthenticatorFactory {
	return NewConnectionAuthenticatorFactoryWithLinker(auditor, logger, maxEntries, nil)
}

// NewConnectionAuthenticatorFactoryWithLinker additionally maps upstream
// subjects through the configured identity-link store.
func NewConnectionAuthenticatorFactoryWithLinker(auditor *audit.Recorder, logger spi.Logger, maxEntries int, linker authenticators.UserLinker) *ConnectionAuthenticatorFactory {
	if logger == nil {
		logger = spi.NopLogger{}
	}
	if maxEntries <= 0 {
		maxEntries = DefaultConnectionAuthCacheSize
	}
	return &ConnectionAuthenticatorFactory{
		auditor: auditor,
		logger:  logger,
		linker:  linker,
		max:     maxEntries,
		cache:   make(map[string]connectionAuthEntry),
	}
}

// AuthenticatorFor implements connections.AuthenticatorFactory.
func (f *ConnectionAuthenticatorFactory) AuthenticatorFor(ctx context.Context, c *connections.Connection) (core.Authenticator, error) {
	if c == nil {
		return nil, connections.ErrNoConnection
	}
	if c.Type != connections.TypeOIDC {
		return nil, connections.ErrConnectionTypeUnsupported
	}
	fp := connectionConfigFingerprint(c)
	if auth := f.cached(c.ID, fp); auth != nil {
		return auth, nil
	}
	auth, err := buildConnectionOIDCAuthenticator(c, f.linker)
	if err != nil {
		// Operator-visible misconfiguration signal; the caller's wire response
		// stays byte-identical to an unknown provider (anti-enumeration).
		f.logger.Error("connection authenticator build failed",
			"connection_id", c.ID, "tenant_id", c.TenantID, "error", err)
		audit.RecordConnectionAuthenticatorBuildFailed(f.auditor, ctx, c.ID, c.TenantID, err.Error())
		return nil, err
	}
	f.store(c.ID, fp, auth)
	return auth, nil
}

// cached returns the cached authenticator for id ONLY when the fingerprint
// still matches — a config change (different fingerprint) is a miss so the
// caller rebuilds against the current Config.
func (f *ConnectionAuthenticatorFactory) cached(id, fingerprint string) core.Authenticator {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.cache[id]; ok && e.fingerprint == fingerprint {
		return e.auth
	}
	return nil
}

// store inserts (or replaces) id's entry, evicting an arbitrary other entry
// first when the cache is at capacity. Random-victim eviction is deliberate:
// entries are cheap to rebuild and a strict LRU would put bookkeeping on the
// login hot path for no correctness gain.
func (f *ConnectionAuthenticatorFactory) store(id, fingerprint string, auth core.Authenticator) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.cache[id]; !exists && len(f.cache) >= f.max {
		for victim := range f.cache {
			delete(f.cache, victim)
			break
		}
	}
	f.cache[id] = connectionAuthEntry{fingerprint: fingerprint, auth: auth}
}

// connectionConfigFingerprint digests every authenticator-relevant input
// (type + the full Config map, sorted for determinism). Hashing the whole map
// rather than the known keys means a future key is automatically part of the
// version signal.
func connectionConfigFingerprint(c *connections.Connection) string {
	keys := make([]string, 0, len(c.Config))
	for k := range c.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(string(c.Type)))
	for _, k := range keys {
		// NUL separators prevent ambiguous concatenations ("a"+"bc" vs "ab"+"c").
		h.Write([]byte{0})
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(c.Config[k]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// buildConnectionOIDCAuthenticator maps Connection.Config onto the same
// OIDCFederationConfig the static YAML providers are built from. Name is the
// connection ID — the exact value /auth/login dispatches on (provider=<id>),
// so lockout keys, metrics labels, and audit trails all line up with the
// connection. NewOIDCFederationAuthenticator owns required-field validation.
func buildConnectionOIDCAuthenticator(c *connections.Connection, linker authenticators.UserLinker) (core.Authenticator, error) {
	return authenticators.NewOIDCFederationAuthenticator(authenticators.OIDCFederationConfig{
		Name:                  c.ID,
		AuthorizationEndpoint: strings.TrimSpace(c.Config[connections.ConfigKeyOIDCAuthorizationEndpoint]),
		TokenEndpoint:         strings.TrimSpace(c.Config[connections.ConfigKeyOIDCTokenEndpoint]),
		UserinfoEndpoint:      strings.TrimSpace(c.Config[connections.ConfigKeyOIDCUserinfoEndpoint]),
		ClientID:              strings.TrimSpace(c.Config[connections.ConfigKeyOIDCClientID]),
		ClientSecret:          c.Config[connections.ConfigKeyOIDCClientSecret],
		RedirectURI:           strings.TrimSpace(c.Config[connections.ConfigKeyOIDCRedirectURI]),
		Scopes:                strings.Fields(c.Config[connections.ConfigKeyOIDCScopes]),
		SubjectFieldOverride:  strings.TrimSpace(c.Config[connections.ConfigKeyOIDCSubjectField]),
	}, authenticators.WithUserLinker(linker))
}

// Interface guard (in the implementation package per convention).
var _ connections.AuthenticatorFactory = (*ConnectionAuthenticatorFactory)(nil)
