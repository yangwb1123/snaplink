package sso

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/tokenanomaly"
	"github.com/snaplink/sso/domains/tokenpolicy"
	"github.com/snaplink/sso/domains/tokenusage"
	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/interfaces/sso/servercache"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/platform/lifecycle/degradation"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/signingkeys"
	"github.com/snaplink/sso/protocols/fapi"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// protocolState holds risk/MFA/anomaly/metrics/transport wiring and the OAuth/OIDC grant + discovery static configuration fields.
type protocolState struct {
	riskScorer         spi.RiskScorer
	mfaProvider        spi.MFAProvider
	mfaChallengeStore  spi.MFAChallengeStore
	mfaChallengeTTL    time.Duration
	anomalyRunner      *anomaly.Runner
	tokenUsageRecorder *tokenusage.Recorder
	// tokenPolicyStore holds the opt-in token-policy engine (WithTokenPolicy).
	// Nil = no policy layer: issuerForClient returns the raw issuer and
	// enforceTokenPolicy is a no-op, so issuance is byte-identical to today.
	tokenPolicyStore tokenpolicy.Store
	// tokenAnomalyDetector holds the opt-in token-behavior anomaly detector
	// (WithTokenAnomalyDetector), Phase 3 of token governance. Nil = no
	// detector: the suspicious-token admin route is not mounted and
	// RunTokenAnomalyDetection is a no-op, so behavior is byte-identical to a
	// build without the feature. Detection is off the request path and NEVER
	// feeds an auth decision.
	tokenAnomalyDetector *tokenanomaly.Detector
	// capStore + capEngine back the zero-trust conditional-access policy engine
	// (WithConditionalAccess). Both nil ⇒ the engine is unwired: the admin
	// governance route is not mounted and EvaluateConditionalAccess returns a
	// permissive allow — byte-identical to a build without the feature. The
	// engine is ADVISORY this wave (not wired into the live /auth/login flow).
	capStore  conditionalaccess.Store
	capEngine *conditionalaccess.Engine

	// sessionTrust holds the zero-trust session-trust-decay wiring
	// (WithSessionTrustDecay, Direction 3 Phase 3). Its zero value (decay
	// disabled) means: no trust stamped at session creation, no continuous-
	// verification agent, and RequireSessionTrust fail-opens — byte-identical
	// to a build without the feature.
	sessionTrust sessionTrustWiring

	metrics *metrics.Metrics

	// trustedProxies validates X-Forwarded-For chains when wired via
	// WithTrustedProxies. When non-nil its Middleware is inserted outermost
	// in Handler() (before rate limiting and every other middleware), so
	// downstream KeyByClientIP calls see the validated IP via RealClientIP
	// rather than the raw header. Nil = no XFF validation; every XFF
	// consumer trusts the raw header unconditionally — safe only behind an
	// edge that strips and re-adds XFF.
	trustedProxies         *middleware.TrustedProxies
	tenantMetricsAllowlist map[string]struct{} // nil/empty = per-tenant metrics off (§5)
	rateLimitPolicy        *ratelimit.Policy
	// degradation holds the DR degraded-service mode. Nil (default) ⇒ the
	// enforcement gate is not installed and no /admin/dr/mode route is mounted,
	// so a build without WithDegradationManager is byte-identical.
	degradation                    *degradation.Manager
	bodyLimit                      int64
	bodyLimitByPath                map[string]int64 // exact-prefix overrides; longest prefix wins
	readyChecks                    []namedReadyCheck
	tracingOperation               string
	corsPolicy                     *cors.Policy
	securityHeadersEnabled         bool
	issuer                         string
	authCodeStore                  oauth.AuthCodeStore
	authCodeTTL                    time.Duration
	refreshTokenStore              oauth.RefreshTokenStore
	refreshTokenTTL                time.Duration
	refreshGrace                   tokengrant.RefreshGraceStore
	idTokenIssuer                  oidc.IDTokenIssuer
	deviceCodeStore                oauth.DeviceCodeStore
	deviceCodeTTL                  time.Duration
	deviceCodeInterval             time.Duration
	deviceVerifyBaseURL            string
	parStore                       oauth.PARStore
	parTTL                         time.Duration
	deviceSecretStore              DeviceSecretStore
	deviceSecretTTL                time.Duration
	protectedResourceMetadata      *ProtectedResourceMetadata
	cibaStore                      oauth.CIBAStore
	cibaTransport                  oauth.CIBATransport
	cibaPingNotifier               oauth.CIBAPingNotifier
	cibaRequestTTL                 time.Duration
	cibaPollInterval               time.Duration
	dcrPolicy                      *oauth.DCRPolicy
	oauth21Strict                  bool
	fapiValidator                  *fapi.Validator
	logoutTokenIssuer              LogoutTokenIssuer
	logoutNotifier                 LogoutNotifier
	backchannelLogoutMaxConcurrent int
	customGrantHandlers            map[string]oauth.GrantHandler
	grantRateLimiters              map[string]*rateLimiterEntry
	accountLockout                 security.AccountLockout
	jtiReplayStore                 security.JTIReplayStore
	jtiReplayFailClosed            bool
	subjectClientIndex             security.SubjectClientIndex
	jarFetcher                     security.JARFetcher
	jarDecrypter                   security.JWEDecrypter
	jweResponseEncrypter           security.JWEEncrypter
	clientCertExtractor            ClientCertExtractor
	dpopNonceProvider              DPoPNonceProvider
	dpopProofMaxAge                time.Duration
	dpopProofClockSkew             time.Duration
	metadataSigner                 oidc.MetadataSigner
	jarmSigner                     oidc.JARMSigner
	jwksCacheTTL                   time.Duration
	supportedACRValues             []string
	opPolicyURI                    string
	opTosURI                       string
	serviceDocumentation           string
}

// clusterState holds cross-replica signing-key aggregation, invalidation-bus degradation, coordinated key-rotation, and cross-replica revocation fields.
type clusterState struct {
	// Opt-in leaderless multi-replica signing-key aggregation. When
	// signingKeyRegistry is wired (WithSharedSigningKeyRegistry), each
	// replica publishes its signing public keys and adopts its peers' keys
	// VERIFY-ONLY, so JWKS + Validate serve the union (see
	// signing_key_aggregation.go). Nil = the feature is entirely off:
	// behavior is byte-identical to a build without it.
	signingKeyRegistry signingkeys.Registry
	replicaID          string
	signingKeyLeaseTTL time.Duration
	// signingKeyAggDegraded is true while the aggregation subscriber is
	// between resubscribe attempts (the registry's Subscribe channel closed
	// while the run context was still live). True ⇒ this replica is no longer
	// adopting peers' newly-rotated keys, so SigningKeyAggregationReady reports
	// not-ready and sso_signing_key_aggregation_up reads 0. Set/cleared only by
	// the single subscriber goroutine; read by /readyz from another goroutine,
	// so it must be atomic. Always false (and never read by a registered check)
	// when no registry is wired.
	signingKeyAggDegraded atomic.Bool
	// signingKeyAggBackoffBase overrides the resubscribe backoff base for
	// tests only (0 ⇒ the production const). Lets a test exercise the
	// resubscribe loop without waiting real seconds. Never set in production.
	signingKeyAggBackoffBase time.Duration

	// invalidationBusDegraded is true while the cross-replica invalidation-bus
	// subscriber is between resubscribe attempts (the bus's Subscribe channel
	// closed while the run context was still live). True ⇒ this replica is no
	// longer APPLYING cross-replica invalidations (tenant suspension, client
	// cache, coordinated key rotation, token revocation), so InvalidationBusReady
	// reports not-ready and sso_invalidation_bus_up reads 0. Mirrors
	// signingKeyAggDegraded exactly: set/cleared only by the single subscriber
	// goroutine; read by /readyz from another goroutine, so it must be atomic.
	// Always false (and never read by a registered check) when no bus is wired.
	invalidationBusDegraded atomic.Bool
	// invalidationBusBackoffBase overrides the bus resubscribe backoff base for
	// tests only (0 ⇒ the production const). Mirrors signingKeyAggBackoffBase.
	// Never set in production.
	invalidationBusBackoffBase time.Duration
	// adoptedPeerKids tracks, per peer replicaID, the kids this replica has
	// adopted from it, so a KeysRemoved (or a shrinking KeysUpserted) drops
	// exactly the keys that replica owns. Guarded by adoptedPeerMu.
	adoptedPeerMu   sync.Mutex
	adoptedPeerKids map[string][]string
	// adoptedKidRefs refcounts each adopted kid by how many DISTINCT live
	// replicas currently announce it. Invariant: a kid is only DropVerifyKey'd
	// from the issuer when this count falls to 0, so dropping one replica
	// (KeysRemoved / shrinking announcement) never evicts a kid that another
	// live replica still announces (fingerprint collision / shared key /
	// misconfig). Guarded by adoptedPeerMu (same lock as adoptedPeerKids, so
	// the per-replica kid set and its refcounts mutate atomically together).
	adoptedKidRefs map[string]int
	// issuerAlgs caches each token issuer's signing alg (from its JWKS at
	// wiring time) so the event handler can route an announced key to the
	// matching-alg issuer without re-querying JWKS per event. Built lazily,
	// once, by ensureIssuerAlgs.
	issuerAlgsOnce sync.Once
	issuerAlgs     map[string]string

	// coordinatedKeyRotation opts this Server into deadline-coordinated
	// same-kid signing-key rotation cutover (WithCoordinatedKeyRotation). When
	// true AND an invalidation bus is wired, a local rotation PUBLISHES a
	// cluster.KindSigningKeyRotation Event (the demoted + new kid + a
	// now+GracePeriod retire deadline) and a received such Event DEFERS the
	// demoted kid's retirement to that deadline (only ever widening the verify
	// window — see deferSigningKeyRetire) while adopting the new kid verify-only
	// at once. False (the default) ⇒ the publish side is a no-op and a received
	// KindSigningKeyRotation Event is ignored, so behavior is byte-identical to
	// a build without the feature. The bus carries the Event regardless, but no
	// armed subscriber acts on it — safe for a mixed-armed cluster.
	coordinatedKeyRotation bool
	// pendingSigningRetires tracks the deferred-retire timers this replica has
	// scheduled in response to coordinated-rotation Events, keyed by the demoted
	// kid, so a clean shutdown (the subscriber ctx cancel) stops every pending
	// retire (no leaked goroutine) and a duplicate Event for the same kid never
	// stacks two timers. pendingSigningRetireDeadlines holds each timer's
	// currently-promised target instant so an EXTEND only ever pushes it LATER
	// (the fail-safe never-shorten rule). Both guarded by pendingSigningRetireMu.
	pendingSigningRetireMu        sync.Mutex
	pendingSigningRetires         map[string]*pendingRetire
	pendingSigningRetireDeadlines map[string]time.Time

	// crossReplicaRevocation opts this Server into cross-replica access-token
	// revocation propagation (WithCrossReplicaRevocation). When true AND an
	// invalidation bus is wired, a local /token/revoke that hit at least one
	// issuer PUBLISHES a cluster.KindTokenRevoked Event, and a received such
	// Event ADDS the carried token to this replica's per-issuer deny-set WITHOUT
	// re-publishing (the adopt path is local-only — no broadcast loop). False
	// (the default) ⇒ the publish side is a no-op and a received
	// KindTokenRevoked Event is ignored, so revocation stays per-process,
	// byte-identical to a build without the feature.
	crossReplicaRevocation bool
	// coordinatedRetireMinDeferralOverride / MaxOverride let tests shrink the
	// clamp floor/ceiling so the retire fires in milliseconds instead of the
	// 1-minute production floor. 0 ⇒ the production const. Never set in
	// production (no Option wires them — only the test seam does).
	coordinatedRetireMinDeferralOverride time.Duration
	coordinatedRetireMaxDeferralOverride time.Duration
}

// jwksCacheEntry holds a cached JWKS document body, its ETag, and expiry
// with jitter. Stored in cacheState.jwksBodyCache via sync.Map.
type jwksCacheEntry struct {
	body   []byte
	etag   string
	expiry time.Time
}

// Fresh reports whether the entry is still within its jittered TTL window.
func (e *jwksCacheEntry) Fresh() bool {
	return e != nil && time.Now().Before(e.expiry)
}

// jitterTTL returns base ± 20% random jitter. A zero or negative base
// is returned unchanged (cache disabled).
func jitterTTL(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	// Scale by [0.8, 1.2) so concurrent replicas don't all expire at
	// the same wall-clock instant — thundering-herd avoidance.
	f := 0.8 + 0.4*rand.Float64()
	return time.Duration(float64(base) * f)
}

// cacheState holds discovery/JWKS body caches, the JWKS single-flight, pairwise subject config, and the Server-level signing-alg allowlist.
type cacheState struct {
	// Discovery doc derivations from the client store (scopes union,
	// RequirePAR-any, RequireSignedRequestObject-all,
	// frontchannel_logout_supported, authorization_details types union).
	// Cached for `discoveryCacheTTL` so a high-QPS RP polling
	// `/.well-known/openid-configuration` doesn't pay 5× ClientStore.List
	// per request. Refresh is single-flight gated by discoveryCacheMu.
	discoveryCacheTTL time.Duration
	discoveryCache    atomic.Pointer[clientDiscoverySnapshot]
	discoveryCacheMu  sync.Mutex

	// Body cache: the marshaled discovery doc + ETag, keyed by base
	// URL (so multi-host SSO doesn't conflate). Reads are sync.Map-
	// served lock-free; misses fall through to the snapshot path.
	discoveryDocCacheTTL time.Duration
	discoveryDocCache    sync.Map

	// Authorization policy bundle body cache: the marshaled role-
	// DEFINITION bundle + ETag, keyed by "<clientID>\x00<baseURL>" so a
	// multi-host deployment doesn't conflate per-host renders. Reads are
	// sync.Map-served lock-free; misses re-render from the permissions
	// provider. Invalidated on any role/menu mutation (locally +, when a
	// bus is wired, across the cluster) so a sidecar's next pull sees the
	// change before the TTL elapses.
	authzPolicyBundleCacheTTL time.Duration
	authzPolicyBundleCache    sync.Map

	// Collapses concurrent /jwks.json document computations. The doc is
	// global (not per-host) and recomputing it on every poll — iterating
	// every issuer, marshaling, hashing — is wasted work under the
	// unknown-kid stampede many RPs emit right after a key rotation.
	// Deliberately TTL-free single-flight, not a time cache: only
	// genuinely concurrent calls share a result, so the next poll after
	// the in-flight one finishes recomputes — preserving the "JWKS
	// reflects the new key immediately" contract (no staleness window).
	jwksFlight servercache.JWKSSingleFlight

	// JWKS body cache: the pre-marshaled JWKS document + ETag, cached
	// for jwksCacheTTL with ±20% jitter so concurrent replicas don't
	// all expire at the same clock tick. Keyed by "default" (single
	// global doc). Lock-free reads via sync.Map; misses fall through to
	// jwksFlight + issuer-walk. Invalidated by InvalidateJWKSBodyCache
	// when the key set changes.
	jwksBodyCache sync.Map

	// OIDC Core §8 pairwise subject identifiers. Nil pairwiseStore
	// disables the feature entirely — every client receives a public
	// (local) sub regardless of subject_type. Salt mixes into the
	// hash; empty falls back to security.DefaultPairwiseSalt.
	pairwiseStore security.PairwiseSubjectStore
	pairwiseSalt  string

	// supportedSigningAlgs is the Server-level Validate-time alg
	// allowlist (defense-in-depth on top of each issuer's own
	// allowlist). When non-empty, validateAnyToken parses every
	// inbound compact JWS header and rejects — BEFORE handing the
	// token to any issuer — tokens whose `alg` isn't listed. This is
	// the critical anti-alg-confusion property (AGENTS.md §2): the
	// verification algorithm is fixed by the Server's wired signers,
	// never chosen by the RP via the token header. Empty = no extra
	// Server-level gate; each issuer still enforces its own allowlist.
	//
	// It does NOT relax per-issuer enforcement: even an allowlisted
	// alg must still match the key type of the kid the issuer
	// resolves, so an ES256-labelled token only verifies against an
	// ES256 key and an EdDSA-labelled token only against an EdDSA key.
	supportedSigningAlgs []string

	// introspectionCache is the optional best-effort token introspection
	// cache (WithIntrospectionCache). When nil (the default), every
	// /token/introspect call pays full JWT signature verification —
	// byte-identical to a build without caching support.
	introspectionCache oauth.IntrospectionCache
	// introspectionCacheTTL bounds how long a cached introspection
	// result stays valid. Defaults to DefaultIntrospectionCacheTTL (60s)
	// when the option is wired without an explicit TTL. The TTL must be
	// SHORTER than the token's remaining lifetime; 60s is safe for
	// typical access tokens with 5-60 minute lifetimes.
	introspectionCacheTTL time.Duration
}
