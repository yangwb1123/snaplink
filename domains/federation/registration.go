package federation

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// OpenID Federation 1.0 §12 (Automatic Registration) — where federation
// delivers VALUE. A remote RP that is a VALIDATED federation member (its
// Entity Statement resolves to a configured trust anchor per slice 2's
// ResolveTrustChain) becomes a usable OAuth client WITHOUT any out-of-band
// registration: the OP resolves the RP's trust chain ON-THE-FLY at the
// authorization endpoint and DERIVES a core.Client from the policy-applied
// openid_relying_party metadata.
//
// THE HOOK is a core.ClientStore DECORATOR (RegistrationClientStore). It wraps
// the operator's real ClientStore; on a Get MISS (and only then) it attempts
// federation resolution. This keeps the §2-critical authorization path
// UNTOUCHED — every s.clientStore.Get call site (/auth/login, prompt=none
// silent renewal, /token private_key_jwt assertion, JAR) transparently sees a
// derived federation client with no change to the handler logic, and a
// pre-registered client always wins (the wrapped store's hit short-circuits
// before any federation work).
//
// SECURITY — it ADMITS a token-getting client, so the gates are exhaustive:
//
//   - A federation client is admitted ONLY via a slice-2 VALIDATED chain
//     (rooted in a configured anchor, every hop signature-verified, exp/iat/
//     iss/sub/typ checked, metadata_policy applied). An invalid / forged /
//     unanchored / expired chain → resolution fails → the client_id stays
//     UNKNOWN (the decorator returns the wrapped store's original miss error,
//     byte-identical to any unknown client — no federation-internal detail on
//     the wire; the cause is logged inside the resolver).
//   - The derived metadata is the POLICY-CONSTRAINED result. The trust
//     anchor's metadata_policy bounds redirect_uris / response_types / scope:
//     a redirect_uri or response_type the policy disallows is simply NOT in
//     ResolvedRPMetadata → not on the derived Client → the normal authz
//     redirect_uri exact-match / response_type check rejects it. A federation
//     RP CANNOT exceed the federation policy.
//   - The derived Client carries JWKS = the chain-validated entity keys (the
//     openid_relying_party.jwks delivered INSIDE the signature-validated leaf
//     Entity Configuration, so it is chain-vouched, not a bare self-assertion
//     a MITM could swap) and NO Secret — it authenticates ASYMMETRICALLY via
//     private_key_jwt / signed request objects (both resolve the key from
//     Client.JWKS by kid). A shared client_secret would be an unauthenticated-
//     registration bypass, so a federation client never has one.
//   - Default-off byte-identical: a nil resolver (or a resolver with no
//     configured anchors) makes the decorator a TRANSPARENT pass-through —
//     every method forwards to the wrapped store and NO resolution is ever
//     attempted. The hook is nil-gated; an unwired build is unaffected.
//   - Cache: keyed by entity ID, bounded by the chain's earliest exp
//     (TrustChain.Expiry). A stale/expired entry is re-resolved (a client is
//     never served from an expired chain). Concurrency-safe.

// ErrFederationMetadataInvalid is the single coarse error every
// metadata-to-Client mapping failure collapses into (RP metadata that omits a
// usable redirect_uri, carries an unparseable jwks, etc.). Like
// ErrTrustChainInvalid it is oracle-reasonable: the decorator maps it back to
// the wrapped store's unknown-client miss, so a prober cannot tell "no such
// client" from "chain valid but metadata unusable". The specific cause is
// logged, never returned to the wire.
var ErrFederationMetadataInvalid = errors.New("federation: resolved RP metadata cannot form a client")

// federationClientEntry is one cached derived federation Client. expiresAt is
// the chain's earliest exp (TrustChain.Expiry) — past it the entry is stale
// and the next Get re-resolves. Immutable after publication.
type federationClientEntry struct {
	client    *core.Client
	expiresAt time.Time
}

// fresh reports whether the entry is still within the validated chain's
// lifetime. nil-safe.
func (e *federationClientEntry) fresh(now time.Time) bool {
	return e != nil && e.client != nil && now.Before(e.expiresAt)
}

// RegistrationClientStore decorates a core.ClientStore with on-the-fly OpenID
// Federation 1.0 automatic client registration. It is constructed by
// NewRegistrationClientStore and shared (concurrency-safe). A nil resolver (or
// a resolver with no configured anchors) makes it a transparent pass-through —
// the default-off, byte-identical posture.
type RegistrationClientStore struct {
	// inner is the operator's real ClientStore. Every method forwards here;
	// only Get adds the federation fallback (on a miss). Pre-registered clients
	// always win.
	inner core.ClientStore
	// resolver validates a remote RP's trust chain. nil OR !Enabled() ⇒ no
	// federation path (pure pass-through).
	resolver *TrustChainResolver
	// now is the clock the cache reads exp against (injected for tests).
	now func() time.Time
	// logError is the non-fatal log seam; the SPECIFIC resolution/mapping
	// failure goes here, never to the wire. Default no-op.
	logError func(msg string, args ...any)
	// defaultTenantID stamps the TenantID of every derived federation client.
	// Empty = no tenant affinity (serve from any tenant context). A
	// multi-tenant federation deployment sets this so federation RPs land in
	// the intended tenant.
	defaultTenantID string

	// cache holds derived clients keyed by entity ID, bounded by the chain
	// exp. sync.Map: reads (the hot path — a repeat authz from the same RP)
	// are lock-free; a single resolution per entity is funneled through a
	// per-key mutex so a burst of concurrent first-time requests for one RP
	// resolves once, not N times.
	cache       sync.Map // entityID(string) -> *federationClientEntry
	resolveLock keyedMutex

	// negCache is the short-TTL NEGATIVE (failure) cache. WHY: the resolution
	// trigger is UNAUTHENTICATED — an /auth/login with a fake-but-HTTPS
	// client_id that misses the wrapped store fires a full ResolveTrustChain.
	// Caching the FAILURE (keyed by entity ID, short TTL) blunts a repeated
	// fake-id flood without re-fetching, while the SHORT TTL means a legit RP
	// whose superior was transiently down re-attempts soon — never permanently
	// pinned out. It is a plain map + mutex (not the lock-free positive cache):
	// writes happen only on resolution FAILURE (already bounded by the
	// semaphore) and lookups sit on the miss/failure path, not the success hot
	// path — and a plain map gives clean size accounting + oldest-eviction for
	// the cap. negTTL/negMax bound it (lazy-expiry + a hard entry cap so the
	// negative cache cannot itself become an unbounded-memory DoS).
	negMu    sync.Mutex
	negCache map[string]time.Time // entityID -> negative-entry expiry
	negTTL   time.Duration
	negMax   int

	// resolveSem is the GLOBAL bounded-concurrency semaphore (a stdlib counting
	// semaphore — a buffered channel of capacity N). WHY: the per-entity
	// resolveLock only coalesces a burst for ONE id; it does nothing against an
	// attacker wielding MANY distinct fake ids, each forcing a fresh parallel
	// resolution. This caps DISTINCT-id parallelism so the outbound-fetch /
	// socket / goroutine fan-out is bounded regardless of distinct-id count. A
	// non-blocking acquire that FAILS CLOSED when saturated (returns the same
	// unknown-client error as any miss — oracle-safe; a legit RP simply
	// retries). nil ⇒ no bound (never constructed that way; defensive).
	resolveSem chan struct{}

	// trustMarks is the §7 trust-mark requirement gate (slice 4b): an EXTRA
	// admission requirement applied AFTER the trust chain validates and BEFORE
	// the client is derived. nil / inert ⇒ no trust-mark requirement (the
	// default-off, byte-identical slice-3 path). When live, an RP whose
	// validated leaf lacks a valid required mark is NOT admitted (the same
	// oracle-safe unknown-client outcome as a failed resolution).
	trustMarks *trustMarkRequirement
}

// compile-time proof the decorator satisfies the SPI it wraps.
var _ core.ClientStore = (*RegistrationClientStore)(nil)

// RegistrationOption configures a RegistrationClientStore.
type RegistrationOption func(*RegistrationClientStore)

// WithRegistrationClock injects the cache's exp clock (test seam). Default
// time.Now.
func WithRegistrationClock(now func() time.Time) RegistrationOption {
	return func(s *RegistrationClientStore) {
		if now != nil {
			s.now = now
		}
	}
}

// WithRegistrationLogger injects the non-fatal log seam (the SPECIFIC
// resolution/mapping failure goes here, never the wire). Default no-op.
func WithRegistrationLogger(logError func(msg string, args ...any)) RegistrationOption {
	return func(s *RegistrationClientStore) {
		if logError != nil {
			s.logError = logError
		}
	}
}

// WithRegistrationTenantID stamps the TenantID of every derived federation
// client. Empty (default) = no tenant affinity.
func WithRegistrationTenantID(tenantID string) RegistrationOption {
	return func(s *RegistrationClientStore) { s.defaultTenantID = tenantID }
}

// WithRegistrationNegativeCacheTTL sets how long a FAILED on-the-fly resolution
// is remembered so a repeated fake-but-HTTPS client_id does not re-trigger a
// fresh resolution. Kept short (it only DELAYS re-attempts). <=0 ⇒
// DefaultResolutionNegativeCacheTTL.
func WithRegistrationNegativeCacheTTL(ttl time.Duration) RegistrationOption {
	return func(s *RegistrationClientStore) {
		if ttl > 0 {
			s.negTTL = ttl
		}
	}
}

// WithRegistrationNegativeCacheMaxSize caps the negative cache's entry count so
// it cannot itself become an unbounded-memory DoS. <=0 ⇒
// DefaultResolutionNegativeCacheMaxSize.
func WithRegistrationNegativeCacheMaxSize(n int) RegistrationOption {
	return func(s *RegistrationClientStore) {
		if n > 0 {
			s.negMax = n
		}
	}
}

// WithRegistrationMaxConcurrency bounds the number of CONCURRENT in-flight
// trust-chain resolutions across all distinct entity IDs (fail-closed when
// saturated). <=0 ⇒ DefaultMaxConcurrentResolutions.
func WithRegistrationMaxConcurrency(n int) RegistrationOption {
	return func(s *RegistrationClientStore) {
		if n > 0 {
			s.resolveSem = make(chan struct{}, n)
		}
	}
}

// WithRegistrationTrustMarks wires the OpenID Federation 1.0 §7 trust-mark
// requirement gate (slice 4b, +slice-4c federation-resolved issuers) from the
// federation Config: an auto-registering RP must carry a valid Trust Mark (a
// signed conformance assertion from an AUTHORIZED Trust Mark Issuer) of EACH
// RequiredTrustMarkTypes, else it is NOT admitted. An empty
// RequiredTrustMarkTypes (or a nil cfg) is INERT — the gate is a no-op and the
// slice-3 path is byte-identical (the default-off posture). The requirement is
// compiled ONCE here and shared read-only; it is checked AFTER ResolveTrustChain
// succeeds and BEFORE the client is derived. A failed mark check is oracle-safe
// (the same unknown-client outcome as a failed resolution).
//
// The gate is handed the SAME resolver the decorator wraps (s.resolver, set in
// the struct literal before options run) so the OPT-IN federation-resolved
// issuer path (Config.AllowFederationResolvedTrustMarkIssuers) can discover a
// Trust Mark Issuer as a federation entity. When that flag is off (default), the
// resolver is unused by the gate and behavior is byte-identical to slice 4b
// (configured issuers only). MUST run after the resolver field is populated —
// it is (NewRegistrationClientStore sets resolver in the struct literal, then
// applies options).
func WithRegistrationTrustMarks(cfg *Config) RegistrationOption {
	return func(s *RegistrationClientStore) {
		s.trustMarks = newTrustMarkRequirement(cfg, s.resolver)
	}
}

// NewRegistrationClientStore wraps inner with federation automatic
// registration backed by resolver. A nil resolver (or one with no configured
// trust anchors) yields a TRANSPARENT pass-through — Get behaves exactly like
// inner.Get and no resolution is ever attempted (default-off byte-identical).
// A nil inner is a programming error (there is nothing to decorate); callers
// (the SDK option) guard it.
func NewRegistrationClientStore(inner core.ClientStore, resolver *TrustChainResolver, opts ...RegistrationOption) *RegistrationClientStore {
	s := &RegistrationClientStore{
		inner:    inner,
		resolver: resolver,
		now:      time.Now,
		logError: func(string, ...any) {},
		// Abuse-resistance defaults (overridable by the options below). These
		// only ever RUN when the resolver is active; an inert decorator is a
		// pure pass-through (the negative cache / semaphore are never touched),
		// so they cost nothing in a default-off build.
		negCache:   make(map[string]time.Time),
		negTTL:     DefaultResolutionNegativeCacheTTL,
		negMax:     DefaultResolutionNegativeCacheMaxSize,
		resolveSem: make(chan struct{}, DefaultMaxConcurrentResolutions),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// federationActive reports whether the federation fallback is live: a non-nil,
// anchor-configured resolver. When false the decorator is a pure pass-through.
func (s *RegistrationClientStore) federationActive() bool {
	return s != nil && s.resolver != nil && s.resolver.Enabled()
}

// Get resolves clientID: the wrapped store FIRST (a pre-registered client
// wins, byte-identical), and ONLY on a miss — with federation active and
// clientID a syntactically-valid HTTPS entity identifier — attempts trust-chain
// resolution to derive a federation client. On any resolution/mapping failure
// the ORIGINAL wrapped-store miss error is returned (oracle-safe: the wire sees
// the same unknown-client error as for any unknown client_id; the specific
// federation cause is logged, not leaked).
func (s *RegistrationClientStore) Get(ctx context.Context, clientID string) (*core.Client, error) {
	c, err := s.inner.Get(ctx, clientID)
	if err == nil {
		return c, nil
	}

	// Wrapped-store MISS. Only attempt federation when it is active AND the
	// client_id is a valid HTTPS entity identifier (the federation resolution
	// will itself fetch this URL — gate it the same way the resolver gates the
	// leaf id). A non-entity-id unknown client_id never triggers a fetch:
	// return the original miss unchanged. This preserves the default-off and
	// "non-entity-id unknown stays unknown, no resolution attempt" contracts.
	if !s.federationActive() {
		return nil, err
	}
	if vErr := validateFederationURL(clientID); vErr != nil {
		// Not a valid HTTPS entity id (or an internal/SSRF-y host) — not a
		// federation candidate. The original miss is the answer.
		return nil, err
	}

	derived, ok := s.resolveFederationClient(ctx, clientID)
	if !ok {
		// Resolution / mapping failed (invalid chain, no anchor reached, policy
		// violation, fetch/SSRF failure, unusable metadata). The cause is
		// already logged inside resolveFederationClient. The client stays
		// UNKNOWN — return the wrapped store's ORIGINAL error so the wire shape
		// is byte-identical to any unknown client_id (oracle-safe).
		return nil, err
	}
	return derived, nil
}

// resolveFederationClient returns a cached-or-freshly-resolved derived
// federation Client for entityID, or (nil,false) on any failure (logged). A
// fresh cache entry is served lock-free; otherwise a per-entity lock funnels
// concurrent first-time resolutions so the chain is resolved once.
//
// Abuse resistance (the resolution trigger is UNAUTHENTICATED): before any
// fetch it consults the short-TTL NEGATIVE cache (a recent failure for this id
// short-circuits without re-resolving — blunting a repeated fake-id flood) and,
// for a genuine miss, acquires the global concurrency semaphore (saturated ⇒
// fail-closed, no resolution). BOTH return (nil,false) — the caller maps that
// to the SAME unknown-client error as any miss (oracle-safe).
func (s *RegistrationClientStore) resolveFederationClient(ctx context.Context, entityID string) (*core.Client, bool) {
	now := s.now()
	if client, ok := s.cachedClient(entityID, now); ok {
		return client, true
	}

	// NEGATIVE-cache check BEFORE taking the per-entity lock or the semaphore:
	// a recently-failed id must not re-trigger a resolution (the cheap, hot
	// defense against a repeated fake-but-HTTPS client_id flood). A fresh
	// negative hit returns the oracle-safe miss with zero outbound work.
	if s.negativeCacheHit(entityID, now) {
		return nil, false
	}

	// Cache miss/stale: resolve under a per-entity lock so a burst of
	// concurrent first-time requests for the same RP resolves the chain ONCE.
	unlock := s.resolveLock.lock(entityID)
	defer unlock()

	// Re-check the positive cache under the lock — another goroutine may have
	// populated it while we waited (double-checked locking).
	now = s.now()
	if client, ok := s.cachedClient(entityID, now); ok {
		return client, true
	}
	// Re-check the negative cache under the lock too: a sibling goroutine for
	// THIS id may have just recorded a failure while we waited on the per-entity
	// lock — honor it rather than re-resolving immediately.
	if s.negativeCacheHit(entityID, now) {
		return nil, false
	}

	// GLOBAL concurrency bound: cap DISTINCT-id resolution parallelism (the
	// per-entity lock above only coalesces ONE id). Fail CLOSED when saturated —
	// do NOT attempt a resolution and do NOT poison the negative cache (this is
	// load-shedding, not an RP failure); the caller maps the (nil,false) to the
	// oracle-safe unknown-client error and a legit RP retries.
	if !s.acquireResolveSlot() {
		s.logError("federation: resolution concurrency limit reached; shedding (unknown-client)", "client_id", entityID)
		return nil, false
	}
	defer s.releaseResolveSlot()

	return s.resolveAndDeriveClient(ctx, entityID, now)
}

// chainJWKS extracts the RP's protocol keys from the policy-applied
// openid_relying_party metadata: the `jwks` member (an inline JWK Set). These
// are the keys the chain VOUCHES FOR (delivered inside the signature-validated
// leaf Entity Configuration), used for private_key_jwt / JAR. A jwks_uri (a
// reference rather than an inline set) is NOT dereferenced here — automatic
// registration admits an RP on its inline keys; an RP publishing only a
// jwks_uri is not given asymmetric client auth in this slice (it would need a
// separate SSRF-gated fetch). Returns nil when no usable inline jwks is
// present (the derived client then has no JWKS — private_key_jwt/JAR for it
// fail, which is correct: no vouched keys, no asymmetric auth).
func (s *RegistrationClientStore) chainJWKS(chain *TrustChain) []core.JWK {
	keys, err := parseRPJWKS(chain.ResolvedRPMetadata)
	if err != nil {
		// Malformed inline jwks → log + no keys (fail-soft on the KEY material,
		// not the whole client: a redirect-only public RP with a broken jwks
		// can still run PKCE-protected code flow; private_key_jwt just won't
		// work for it). MetadataToClient does not require keys.
		s.logError("federation: resolved RP jwks unparseable; deriving client without asymmetric keys", "client_id", chain.LeafEntityID, "error", err)
		return nil
	}
	return keys
}

// ValidateSecret forwards to the wrapped store. A DERIVED federation client is
// never persisted there and has NO secret, so secret-based auth for a
// federation client correctly fails at this layer — federation clients
// authenticate asymmetrically (private_key_jwt / JAR via Client.JWKS), never a
// shared secret.
func (s *RegistrationClientStore) ValidateSecret(ctx context.Context, clientID, clientSecret string) error {
	return s.inner.ValidateSecret(ctx, clientID, clientSecret)
}

// List forwards to the wrapped store. Derived federation clients are
// intentionally NOT listed — they are resolved on demand + cached, not stored,
// so the admin/discovery view shows only persisted clients (a federation RP is
// not a registered client and should not appear in client inventories or churn
// the discovery-doc scope union).
func (s *RegistrationClientStore) List(ctx context.Context) ([]*core.Client, error) {
	return s.inner.List(ctx)
}

// Add forwards to the wrapped store (operator/DCR provisioning is unchanged).
func (s *RegistrationClientStore) Add(ctx context.Context, c *core.Client) error {
	return s.inner.Add(ctx, c)
}

// Update forwards to the wrapped store.
func (s *RegistrationClientStore) Update(ctx context.Context, c *core.Client) error {
	return s.inner.Update(ctx, c)
}

// Delete forwards to the wrapped store.
func (s *RegistrationClientStore) Delete(ctx context.Context, clientID string) error {
	return s.inner.Delete(ctx, clientID)
}

// RotateSecret forwards to the wrapped store. A derived federation client has
// no secret to rotate (it is not in the wrapped store), so this only ever
// operates on persisted clients.
func (s *RegistrationClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	return s.inner.RotateSecret(ctx, clientID)
}
