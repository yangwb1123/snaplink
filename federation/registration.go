package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/snaplink/sso/core"
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

// MetadataToClient derives a core.Client from the POLICY-APPLIED
// openid_relying_party metadata of a validated trust chain. This is the
// federation analogue of the DCR metadata-to-Client mapping (oauth.Handle
// Register): the same RP parameters (redirect_uris, response_types,
// grant_types, scope, token_endpoint_auth_method, jwks/jwks_uri) map to the
// same Client fields — but SOURCED from the chain, not a self-service POST.
//
// entityID is the leaf RP's Entity Identifier (TrustChain.LeafEntityID); it
// becomes Client.ID so RFC 9068 ClientID + every audience/binding check keys
// off the federation identity. jwks is the chain-vouched key set used for
// private_key_jwt / JAR. tenantID stamps the client's tenant affinity (empty =
// any).
//
// Crux: rp is the POLICY-CONSTRAINED map (the trust anchor's metadata_policy
// already bounded it). This function only PROJECTS it — it adds nothing the
// policy didn't permit, so the federation can never exceed the trust anchor's
// constraints. A redirect_uri / response_type / scope the policy stripped is
// simply absent here and the derived Client doesn't carry it (the normal
// authz check then rejects a request for it).
func MetadataToClient(entityID string, rp map[string]any, jwks []core.JWK, tenantID string) (*core.Client, error) {
	if entityID == "" {
		return nil, fmt.Errorf("%w: empty entity id", ErrFederationMetadataInvalid)
	}

	redirectURIs := metaStringSlice(rp, "redirect_uris")
	// An authorization_code RP without a redirect_uri can never complete the
	// flow (the redirect_uri exact-match would always fail). Reject the
	// mapping so the client stays unknown rather than admitting a half-usable
	// client. (A pure client_credentials RP has no end-user redirect; but the
	// automatic-registration value is the interactive authorization_code flow,
	// and admitting a redirect-less client here would only ever fail downstream
	// — so we require at least one redirect_uri for a federation client.)
	if len(redirectURIs) == 0 {
		return nil, fmt.Errorf("%w: no redirect_uris in resolved metadata", ErrFederationMetadataInvalid)
	}

	client := &core.Client{
		ID:           entityID,
		Name:         metaString(rp, "client_name"),
		RedirectURIs: redirectURIs,
		// Scope authorization is bounded by the policy-constrained scope; an RP
		// can only request what the federation policy permitted into its
		// metadata. Empty = the server's default (unrestricted-by-this-source)
		// — but a federation deployment SHOULD pin scope via metadata_policy.
		AllowedScopes: splitScopeString(metaString(rp, "scope")),
		// Active immediately: validation IS the gate (the chain validated). An
		// inactive-by-default posture would defeat automatic registration (the
		// whole point is no human approval step) — the trust decision already
		// happened cryptographically.
		Active:   true,
		TenantID: tenantID,
		// JWKS = the chain-vouched entity keys → private_key_jwt + signed
		// request objects work with NO shared secret. Secret stays EMPTY: a
		// federation client authenticates asymmetrically only (a secret would
		// be an unauthenticated-registration bypass).
		JWKS:       jwks,
		Federation: true,
	}

	// token_endpoint_auth_method: a federation RP authenticates with its
	// chain-vouched keys (private_key_jwt) or, for public-style RPs, "none"
	// (PKCE-protected). Either way there is no secret. We do not reject other
	// declared methods here (the absence of a Secret means client_secret_*
	// simply cannot succeed at /token), but a public RP is marked RequirePKCE
	// so a code interception is mitigated — mirroring DCR's "public clients
	// always PKCE" rule.
	if metaString(rp, "token_endpoint_auth_method") == "none" {
		client.RequirePKCE = true
	}

	return client, nil
}

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
	if e, _ := s.cache.Load(entityID); e != nil {
		if entry, _ := e.(*federationClientEntry); entry.fresh(now) {
			return entry.client, true
		}
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
	if e, _ := s.cache.Load(entityID); e != nil {
		if entry, _ := e.(*federationClientEntry); entry.fresh(now) {
			return entry.client, true
		}
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

	chain, err := s.resolver.ResolveTrustChain(ctx, entityID)
	if err != nil {
		// ResolveTrustChain already collapsed + logged the specific cause to
		// ErrTrustChainInvalid (or returned ErrFederationResolverDisabled).
		// Record a SHORT-TTL negative entry so a repeated fake id doesn't
		// re-fetch — the short TTL means a legit RP whose superior was
		// transiently down re-attempts soon (it DELAYS, never permanently pins).
		s.recordNegative(entityID, s.now())
		s.logError("federation: trust chain resolution failed for client", "client_id", entityID, "error", err)
		return nil, false
	}

	client, err := MetadataToClient(entityID, chain.ResolvedRPMetadata, s.chainJWKS(chain), s.defaultTenantID)
	if err != nil {
		// A chain validated but its metadata can't form a client — equally an
		// unusable id; negative-cache it (short TTL) so it isn't re-resolved on
		// every probe.
		s.recordNegative(entityID, s.now())
		s.logError("federation: derive client from resolved metadata failed", "client_id", entityID, "error", err)
		return nil, false
	}

	// A successful resolution clears any lingering negative entry for this id
	// (e.g. a legit RP that just recovered from a transient superior outage) —
	// keeps the negative cache tidy; the positive cache is authoritative below.
	s.clearNegative(entityID)

	// Cache bounded by the chain's earliest exp — never serve a client from an
	// expired chain. A non-positive/zero expiry (which a validated chain never
	// produces) is treated as already-expired: cache nothing, just return the
	// derived client for THIS request so a defensive zero doesn't pin a stale
	// client.
	exp := chain.Expiry()
	if exp.After(now) {
		s.cache.Store(entityID, &federationClientEntry{client: client, expiresAt: exp})
	}
	return client, true
}

// ----- negative (failure) cache + concurrency semaphore -------------------
//
// The resolution trigger (an /auth/login miss for an HTTPS-shaped client_id) is
// UNAUTHENTICATED, so these blunt abuse: the negative cache stops a repeated
// fake id from re-fetching; the semaphore caps distinct-id parallelism. Both
// keep the wire shape unchanged (a blunted path yields the same unknown-client
// error) — they only DELAY/SHED, never admit or reject differently.

// negativeCacheHit reports whether entityID has a FRESH negative entry (a
// recent failure within negTTL). A stale entry is lazily evicted so the map
// self-trims on lookups for previously-failed ids.
func (s *RegistrationClientStore) negativeCacheHit(entityID string, now time.Time) bool {
	if s.negTTL <= 0 {
		return false
	}
	s.negMu.Lock()
	defer s.negMu.Unlock()
	exp, ok := s.negCache[entityID]
	if !ok {
		return false
	}
	if now.Before(exp) {
		return true
	}
	// Stale — lazy-expire.
	delete(s.negCache, entityID)
	return false
}

// recordNegative remembers a FAILED resolution for entityID with a short TTL.
// It enforces the entry cap so the negative cache cannot itself become an
// unbounded-memory DoS: at the cap it first sweeps expired entries, then evicts
// the soonest-to-expire entry to admit the new one.
func (s *RegistrationClientStore) recordNegative(entityID string, now time.Time) {
	if s.negTTL <= 0 {
		return
	}
	s.negMu.Lock()
	defer s.negMu.Unlock()
	if _, exists := s.negCache[entityID]; !exists && s.negMax > 0 && len(s.negCache) >= s.negMax {
		s.evictNegativeLocked(now)
	}
	s.negCache[entityID] = now.Add(s.negTTL)
}

// clearNegative drops any negative entry for entityID (called on a successful
// resolution). nil-safe via the mutex.
func (s *RegistrationClientStore) clearNegative(entityID string) {
	s.negMu.Lock()
	delete(s.negCache, entityID)
	s.negMu.Unlock()
}

// evictNegativeLocked makes room under the entry cap. Caller holds negMu. It
// first deletes every expired entry (cheap, bounded sweep — the map is capped);
// if that frees nothing (every entry still fresh under a sustained distinct-id
// flood), it evicts the entry with the EARLIEST expiry so a bounded amount of
// memory is reclaimed deterministically.
func (s *RegistrationClientStore) evictNegativeLocked(now time.Time) {
	freed := false
	for k, exp := range s.negCache {
		if !now.Before(exp) {
			delete(s.negCache, k)
			freed = true
		}
	}
	if freed {
		return
	}
	var oldestKey string
	var oldestExp time.Time
	first := true
	for k, exp := range s.negCache {
		if first || exp.Before(oldestExp) {
			oldestKey, oldestExp, first = k, exp, false
		}
	}
	if !first {
		delete(s.negCache, oldestKey)
	}
}

// acquireResolveSlot tries to take one of the bounded resolution slots WITHOUT
// blocking. true ⇒ a slot was acquired (the caller MUST releaseResolveSlot);
// false ⇒ the semaphore is saturated (fail-closed: the caller sheds the
// resolution and returns the oracle-safe unknown-client error). A nil semaphore
// (never constructed) is treated as unbounded — acquire always succeeds.
func (s *RegistrationClientStore) acquireResolveSlot() bool {
	if s.resolveSem == nil {
		return true
	}
	select {
	case s.resolveSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseResolveSlot returns a slot taken by acquireResolveSlot.
func (s *RegistrationClientStore) releaseResolveSlot() {
	if s.resolveSem == nil {
		return
	}
	<-s.resolveSem
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

// ----- resolved-metadata projection helpers -------------------------------
//
// The policy engine returns the openid_relying_party metadata as a
// map[string]any where list values are []any and scalars are typed (string,
// bool, ...). These helpers project that loosely-typed map onto the Client
// fields without panicking on an unexpected shape (a hostile/odd metadata
// value yields an empty/absent field, never a crash) — defense in depth atop
// the policy constraints.

// metaString reads a string-valued member, or "" when absent/non-string.
func metaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// metaStringSlice reads a string-list member as []string. Accepts the policy
// engine's []any (each element string-coerced) and a plain []string. Non-list
// or non-string elements are dropped. Returns nil when absent/empty.
func metaStringSlice(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

// splitScopeString splits an OAuth scope string ("openid profile email") into
// its members. Empty in ⇒ nil out (no scope constraint from this source). A
// local splitter so federation depends on neither oauth nor strings-helpers in
// root.
func splitScopeString(scope string) []string {
	var out []string
	start := -1
	for i := 0; i < len(scope); i++ {
		if scope[i] == ' ' || scope[i] == '\t' || scope[i] == '\n' {
			if start >= 0 {
				out = append(out, scope[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, scope[start:])
	}
	return out
}

// parseRPJWKS extracts the inline `jwks` JWK Set from the policy-applied RP
// metadata as []core.JWK. The member is a map[string]any of the RFC 7517 shape
// {"keys": [ {kty,...}, ... ]}; we re-marshal it and unmarshal into the typed
// EntityJWKS (so core.JWK's field tags govern the decode — no hand parsing of
// each key parameter). Returns (nil,nil) when no jwks member is present (an RP
// may legitimately publish only a jwks_uri, not dereferenced here). An error
// is returned only when a jwks member IS present but cannot decode to a
// non-empty key set.
func parseRPJWKS(rp map[string]any) ([]core.JWK, error) {
	if rp == nil {
		return nil, nil
	}
	raw, ok := rp["jwks"]
	if !ok || raw == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks member: %w", err)
	}
	var set EntityJWKS
	if err := json.Unmarshal(encoded, &set); err != nil {
		return nil, fmt.Errorf("decode jwks member: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwks member present but empty")
	}
	return set.Keys, nil
}

// ----- keyedMutex ---------------------------------------------------------

// keyedMutex serializes work per string key (here: per entity ID), so a burst
// of concurrent first-time resolutions for ONE federation RP resolves the
// chain once while DIFFERENT RPs resolve in parallel. Lazily allocates a
// *sync.Mutex per active key and reference-counts it so idle keys don't leak.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*kmEntry
}

type kmEntry struct {
	mu   sync.Mutex
	refs int
}

// lock acquires the per-key mutex and returns an unlock func that releases it
// and drops the (ref-counted) entry when no waiter remains.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*kmEntry)
	}
	e := k.m[key]
	if e == nil {
		e = &kmEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}
