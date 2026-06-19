package sso

import "github.com/snaplink/sso/oidc"

import "github.com/snaplink/sso/spi"

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/caep"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/compliance"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/fapi"
	"github.com/snaplink/sso/federation"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/internal/auth/consent"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/metering"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/signingkeys"
	"github.com/snaplink/sso/tenant"
)

// Server is the core SSO orchestrator.
type Server struct {
	authenticators          map[string]Authenticator
	tokenIssuers            map[string]TokenIssuer // strategy name -> issuer
	defaultTokenStrategy    string
	tenantTokenStrategies   map[string]string // tenant id -> strategy (issuer) name
	userProvider            UserProvider
	clientStore             ClientStore
	sessionMgr              SessionManager
	router                  Router
	logger                  spi.Logger
	auditor                 *audit.Recorder
	caepTransmitter         *caep.Transmitter
	auditAPI                bool
	requestIDMW             bool
	permissions             permissions.Provider
	embedPermissions        bool
	netStore                netpolicy.Store
	netClassifier           *netpolicy.Classifier
	netAPI                  bool
	geoProvider             geo.Provider
	geoMiddlewareOpts       GeoMiddlewareOptions
	tenantStore             tenant.Store
	tenantMiddlewareOpts    TenantMiddlewareOptions
	tenantSuspensionEnabled bool
	tenantSuspensionCache   *suspensionCache
	tenantResidencyEnabled  bool
	tenantResidencyCache    *residencyCache
	regionResolver          region.Resolver
	regionMiddlewareOpts    region.MiddlewareOptions
	invalidationBus         cluster.Bus

	// clientStoreCacheTTL opts into the per-login ClientStore metadata
	// cache (WithClientStoreCache). > 0 ⇒ NewServer decorates s.clientStore
	// with clientStoreCache post-options (the same slot as the federation
	// registration decorator, so it composes order-independently and wraps
	// the federation store too). <= 0 (the default) ⇒ NO wrapper, every
	// s.clientStore.Get is byte-identical to a non-caching build. The cache
	// is metadata-only: ValidateSecret always bypasses it (§2). clientStoreCacheRef
	// is the constructed decorator (nil when unwired), retained so
	// InvalidateClientCache can evict locally without re-asserting the type.
	clientStoreCacheTTL time.Duration
	clientStoreCacheRef *clientStoreCache

	// SPIFFE JWT-SVID acceptance (cluster C1, mesh-native service-to-
	// service identity). When spiffeValidator is wired
	// (WithSPIFFEJWTSVID), a token-exchange subject_token_type=jwt whose
	// `sub` is a spiffe:// URI — and which is NOT a token this server's
	// own issuers can validate — is verified against the operator-
	// supplied SPIRE trust bundle (strict alg-allowlist + aud-binding +
	// trust-domain check) and mapped onto a Subject. Nil = the feature is
	// entirely off: a spiffe-sub subject_token is rejected byte-identically
	// to any other foreign/invalid subject_token (collapses to
	// invalid_grant). spiffeAudience is THIS server's identifier the SVID
	// `aud` MUST contain.
	spiffeValidator *security.SPIFFEValidator
	spiffeAudience  string

	// CAEP/SSF RECEIVER (the inbound half of OpenID Shared Signals — the
	// inverse of caepTransmitter). When caepReceiver is wired
	// (WithCAEPReceiver), the server mounts a push-delivery endpoint
	// (PathSSFReceive) that consumes signed Security Event Tokens from
	// CONFIGURED trusted upstream transmitters and, on a fully-validated
	// session-revoked / account-disabled / token-claims-change event for a
	// PRECISELY-mapped local subject, revokes that subject's local access
	// (sessions + refresh tokens). Validation is fail-closed (iss-allowlist
	// + VerifyCompactJWS signature + aud-binding + exp + jti-replay, all
	// alg=none-safe); an unmapped subject is acked but NOT acted on (no
	// wrongful revocation). Nil ⇒ the route is NOT mounted — byte-identical
	// to a build without it.
	caepReceiver *caep.Receiver

	// connectionStore holds per-organization enterprise connections for B2B
	// home-realm discovery (connections.Store). Nil ⇒ the /auth/home-realm
	// route is NOT mounted — byte-identical to a build without it.
	connectionStore connections.Store

	// Opt-in Envoy/Istio ext_authz HTTP-mode authorization endpoint
	// (cluster C1 mesh data-plane, the HTTP variant — the gRPC variant
	// needs the go-control-plane proto dep and lives in a separate
	// operator module). When meshExtAuthz is true (WithMeshExtAuthz), the
	// server mounts a per-request authorization endpoint at
	// meshExtAuthzPath: a mesh sidecar calls it, a 200 = ALLOW with
	// derived X-Auth-* identity headers the sidecar injects upstream, any
	// other status = DENY. False ⇒ the route is NOT mounted — behavior is
	// byte-identical to a build without it. meshExtAuthzPath empty ⇒
	// PathMeshExtAuthz.
	meshExtAuthz     bool
	meshExtAuthzPath string

	// Opt-in OpenID Federation 1.0 entity configuration. When
	// federationEntity is wired (WithFederationEntity), the server mounts
	// PathFederationEntityConfig serving the OP's self-signed Entity
	// Statement (iss == sub == issuer, signed by the OP's own JWKS key, typ
	// entity-statement+jwt) so the OP participates in a multilateral
	// federation as an ENTITY. Nil ⇒ the route is NOT mounted — behavior is
	// byte-identical to a build without it. This is the entity-publishing
	// slice only; trust-chain VALIDATION (the trust boundary) is a separate
	// slice.
	federationEntity *federation.EntityHandler

	// federationAutoRegister opts into OpenID Federation 1.0 AUTOMATIC client
	// registration (WithFederationAutoRegistration, slice 3): when true AND a
	// ClientStore is wired AND federationEntity carries a resolver with
	// configured trust anchors, NewServer decorates s.clientStore with
	// federation.RegistrationClientStore so an authorization-endpoint
	// ClientStore MISS for a valid HTTPS federation entity ID triggers an
	// on-the-fly trust-chain resolution that DERIVES the client from the
	// policy-constrained RP metadata (chain-vouched JWKS, no secret). The
	// decoration happens post-options (so order is irrelevant) and is INERT —
	// byte-identical to off — without all three preconditions. False ⇒ no
	// decoration; the authz/token flow is unchanged.
	federationAutoRegister bool

	// Opt-in per-store storage-health admin report (WithStorageHealth).
	// Each source describes one wired store: a Name, a Ping for
	// reachability, and an optional schema-version getter (a cmd-supplied
	// closure over the store's *sql.DB driving migrate.Status). Empty ⇒ the
	// /api/v1/admin/storage-health route is NOT mounted (byte-identical to a
	// build without it). The SDK doesn't own the store handles or their
	// *sql.DB — cmd collects these at the same point it gathers Ping-capable
	// stores for /readyz.
	storageHealthSources []StorageHealthSource

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

	riskScorer        spi.RiskScorer
	mfaProvider       spi.MFAProvider
	mfaChallengeStore spi.MFAChallengeStore
	mfaChallengeTTL   time.Duration
	anomalyRunner     *anomaly.Runner
	metrics           *metrics.Metrics
	// trustedProxies validates X-Forwarded-For chains when wired via
	// WithTrustedProxies. When non-nil its Middleware is inserted outermost
	// in Handler() (before rate limiting and every other middleware), so
	// downstream KeyByClientIP calls see the validated IP via RealClientIP
	// rather than the raw header. Nil = no XFF validation; every XFF
	// consumer trusts the raw header unconditionally — safe only behind an
	// edge that strips and re-adds XFF.
	trustedProxies                 *middleware.TrustedProxies
	tenantMetricsAllowlist         map[string]struct{} // nil/empty = per-tenant metrics off (§5)
	rateLimitPolicy                *ratelimit.Policy
	bodyLimit                      int64
	bodyLimitByPath                map[string]int64 // exact-prefix overrides; longest prefix wins
	readyChecks                    []namedReadyCheck
	tracingOperation               string
	corsPolicy                     *cors.Policy
	issuer                         string
	authCodeStore                  oauth.AuthCodeStore
	authCodeTTL                    time.Duration
	refreshTokenStore              oauth.RefreshTokenStore
	refreshTokenTTL                time.Duration
	refreshGrace                   *handler.RefreshGraceCache
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
	jwksFlight jwksSingleFlight

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

	// consentStore persists end-user consent decisions (WithConsentStore).
	// When nil all consent checks are skipped — behavior is byte-identical
	// to a build without the feature.
	consentStore ConsentStore

	// scopeDescriptions maps a scope name to an operator-defined human
	// description (WithScopeDescriptions). Surfaced in the consent_required
	// response so the consent UI can render meaningful text for custom scopes
	// instead of the raw name. Nil/empty ⇒ no descriptions emitted.
	scopeDescriptions map[string]string

	// tenantUserStore persists explicit B2B org membership (WithTenantUserStore).
	// Nil ⇒ the admin roster + self-service /me/organizations endpoints are NOT
	// mounted — byte-identical to a build without it.
	tenantUserStore TenantUserStore

	// jitMembership opts into auto-provisioning org membership on login
	// (WithJITMembership): a user logging in via a tenant-bound client who isn't
	// yet on that tenant's roster is added as a member. Requires tenantUserStore.
	jitMembership bool

	// invitationStore persists single-use org-invitation tokens
	// (WithInvitationStore); invitationSender delivers them (WithInvitationSender).
	// The send + list endpoints mount only with the store; accept also requires a
	// tenantUserStore (the redeemed invite grants membership). Nil ⇒ none mounted.
	invitationStore  InvitationStore
	invitationSender spi.InvitationSender

	// passwordCredentialStore backs POST /me/password (WithPasswordCredentialStore).
	// Nil ⇒ the route is NOT mounted — byte-identical to a build without it.
	passwordCredentialStore PasswordCredentialStore

	// Forgot-password / account-recovery flow (POST /auth/forgot-password +
	// /auth/reset-password). All wired via WithPasswordReset*; the routes mount
	// only when passwordResetStore AND passwordCredentialStore are both set —
	// byte-identical to a build without them.
	passwordResetStore            PasswordResetStore
	passwordResetTTL              time.Duration
	passwordResetResolver         spi.PasswordResetResolver
	passwordResetDeliveryResolver spi.PasswordResetDeliveryResolver
	passwordResetSender           spi.PasswordResetSender

	// dataExporter backs GET /me/data-export — GDPR Art. 15 self-service export
	// of the bearer's OWN data (WithSelfServiceDataExport). Nil ⇒ not mounted.
	dataExporter *compliance.Exporter

	// accountEraser backs POST /me/account/erase — GDPR Art. 17 self-service
	// erasure of the bearer's OWN account (WithSelfServiceAccountErasure).
	// Irreversible; nil ⇒ not mounted (default-off — self-deletion is a
	// deliberate operator choice, not always desirable for managed accounts).
	accountEraser *compliance.Eraser

	// Verified email change (POST /me/email/change + /me/email/verify). Mounts
	// only when the store + sender + a UserProvider are all wired.
	emailChangeStore  EmailChangeStore
	emailChangeTTL    time.Duration
	emailChangeSender spi.EmailChangeSender

	// signupEnabled gates POST /auth/register (opt-in self-service signup).
	// Mounts only when also a UserProvider + PasswordCredentialStore are wired
	// (signup creates the user + sets the password). Default-off.
	signupEnabled bool

	// mfaEnrollmentStore backs GET/DELETE /me/mfa (WithMFAEnrollmentStore).
	// Nil ⇒ the routes are NOT mounted — byte-identical to a build without it.
	mfaEnrollmentStore MFAEnrollmentStore

	// totpEnroller backs POST /me/mfa/totp/{begin,confirm} (WithTOTPEnroller).
	// The enrollment routes mount only when this AND an mfaEnrollmentStore that
	// implements TOTPEnrollmentWriter are both wired — byte-identical off.
	totpEnroller TOTPEnroller

	// webauthnRegistrar backs POST /me/mfa/webauthn/{begin,finish} (authenticated
	// self-service passkey registration, WithWebAuthnRegistrar). Nil ⇒ routes
	// not mounted (byte-identical off).
	webauthnRegistrar WebAuthnRegistrar

	// selfEditableAttrs is the operator allowlist of User.Attributes keys a
	// user MAY change via PATCH /me (WithSelfEditableProfileAttributes). Empty
	// (the default) ⇒ PATCH /me may edit the display name only; any attributes
	// in the request are ignored. The allowlist is the escalation guard: it
	// keeps users from writing authz-relevant attribute keys (roles, tenant,
	// risk flags) the operator stores alongside presentation data.
	selfEditableAttrs map[string]struct{}

	// consentChallenges holds server-issued single-use consent challenge tokens.
	// Each entry is bound to (UserID, ClientID, Scopes) and expires after
	// consent.ChallengeTTL. Thread-safe via consent.ChallengeStore.
	consentChallenges *consent.ChallengeStore

	// usageAggregator backs GET /api/v1/admin/tenants/:id/usage
	// (WithTenantUsageAggregator). Nil ⇒ the route is NOT mounted —
	// byte-identical to a build without it.
	usageAggregator metering.Aggregator

	// jwksBodyCache holds the pre-marshaled JWKS document, valid for
	// jwksCacheTTL. When jwksCacheTTL == 0 the cache is disabled and every
	// serial poll runs the full issuer-walk + marshal (concurrent bursts still
	// share one result via jwksFlight). Invalidated by InvalidateJWKSBodyCache
	// when the key set changes (local rotation, peer adoption, client DCR).
	// Thread-safe: reads hold jwksBodyMu RLock, writes hold it exclusively;
	// zero-value jwksBodyExp ensures an uninitialized cache is always expired.
	jwksBodyMu    sync.RWMutex
	jwksBodyCache []byte
	jwksBodyExp   time.Time

	// adminConsoleFS, when non-nil, serves the hosted admin console SPA from
	// an embedded or OS filesystem at /admin/. The console is a standalone
	// single-page app — it communicates with the server only via the standard
	// /api/v1/admin/* REST endpoints, which require a Bearer token with
	// admin:read or admin:write scope. Nil (the default) leaves /admin/
	// unmounted — byte-identical to a build without the console.
	adminConsoleFS fs.FS

	// hostedLoginFS, when non-nil, serves the hosted-login SPA from an
	// embedded or OS filesystem at /login/. The SPA calls /auth/login over
	// JSON — zero protocol changes to the OAuth/OIDC surface. Nil (the
	// default) leaves /login/ unmounted — byte-identical to a build without
	// it. Typically wired by the operator's cmd binary via go:embed.
	hostedLoginFS fs.FS

	// portalFS, when non-nil, serves the end-user self-service portal SPA from
	// an embedded or OS filesystem at /portal/. The portal is a standalone
	// browser client that calls /me, /sessions/me, /consents/me, /me/password
	// and /me/mfa with the end-user's own Bearer token. Nil (the default)
	// leaves /portal/ unmounted — byte-identical to a build without it.
	portalFS fs.FS
}

// jwksSingleFlight collapses concurrent JWKS document computations into a
// single one, reduced to one global key (the JWKS doc is not per-host).
// It is the classic single-flight pattern: callers that arrive while a
// computation is in flight block on it and share its result instead of
// each recomputing. Calls that arrive after the in-flight one completes
// recompute fresh — there is intentionally no result caching, so a key
// rotation is reflected on the very next poll.
type jwksSingleFlight struct {
	mu     sync.Mutex
	active *jwksCall
}

type jwksCall struct {
	wg   sync.WaitGroup
	body []byte
	err  error
}

// Do runs compute, collapsing any concurrent invocations onto the first
// caller's result. compute must be safe to skip for the followers — it
// is, since the JWKS doc derives only from the (rotation-guarded) issuer
// key set, identical for every concurrent caller.
func (f *jwksSingleFlight) Do(compute func() ([]byte, error)) ([]byte, error) {
	f.mu.Lock()
	if c := f.active; c != nil {
		f.mu.Unlock()
		c.wg.Wait()
		return c.body, c.err
	}
	c := &jwksCall{}
	c.wg.Add(1)
	f.active = c
	f.mu.Unlock()

	c.body, c.err = compute()

	f.mu.Lock()
	f.active = nil
	f.mu.Unlock()
	c.wg.Done()
	return c.body, c.err
}

// Option configures the Server.
type Option func(*Server)

// ReadyCheck is a named health-check function for /readyz.
type ReadyCheck func(ctx context.Context) error

type namedReadyCheck struct {
	Name    string
	Check   ReadyCheck
	Timeout time.Duration // 0 -> use the aggregate deadline
}

func NewServer(opts ...Option) *Server {
	s := &Server{
		authenticators:            make(map[string]Authenticator),
		tokenIssuers:              make(map[string]TokenIssuer),
		tenantTokenStrategies:     make(map[string]string),
		issuer:                    DefaultIssuer,
		logger:                    spi.NopLogger{},
		discoveryCacheTTL:         defaultDiscoveryCacheTTL,
		discoveryDocCacheTTL:      DefaultDiscoveryDocCacheTTL,
		authzPolicyBundleCacheTTL: DefaultAuthzPolicyBundleCacheTTL,
		consentChallenges:         consent.NewChallengeStore(),
	}
	for _, opt := range opts {
		opt(s)
	}
	// Tap the audit pipeline for the CAEP/SSF transmitter, if wired. Done
	// here (after every option ran, so order between WithAuditRecorder and
	// WithCAEPTransmitter doesn't matter) by fanning the recorder's sink
	// out to the transmitter. When the transmitter is unwired this branch
	// is skipped entirely, so a build without it is byte-identical.
	if s.caepTransmitter != nil && s.auditor != nil {
		s.auditor.AddSink(s.caepTransmitter)
	}
	// Per-tenant metrics (§5): register the opt-in vectors when BOTH a
	// tenant allowlist AND a metrics registry are wired. Done post-options
	// (order between WithMetrics and WithTenantMetricsAllowlist is
	// irrelevant); EnableTenantMetrics is idempotent. Without both, the
	// vectors stay nil and nothing is registered or emitted (byte-identical).
	if len(s.tenantMetricsAllowlist) > 0 && s.metrics != nil {
		s.metrics.EnableTenantMetrics()
	}
	// OpenID Federation 1.0 automatic client registration (slice 3). Decorate
	// the wired ClientStore so an authorization-endpoint Get MISS for a valid
	// HTTPS federation entity ID resolves the RP's trust chain on-the-fly and
	// derives a policy-constrained client. Done post-options (order between
	// WithClientStore / WithFederationEntity / WithFederationAutoRegistration is
	// irrelevant) and ONLY when all three preconditions hold: the opt-in flag,
	// a wired ClientStore, and a federation resolver with configured trust
	// anchors (Resolver().Enabled()). Absent any one, no decoration occurs and
	// every s.clientStore.Get is byte-identical to a non-federation build (the
	// decorator is never even constructed). The decorator forwards every other
	// method to the wrapped store; only Get adds the on-miss federation
	// fallback, and a pre-registered client always wins.
	if s.federationAutoRegister && s.clientStore != nil &&
		s.federationEntity != nil && s.federationEntity.Resolver().Enabled() {
		// Source the abuse-resistance knobs (negative-cache TTL + size, the
		// resolution concurrency cap) from the SAME federation Config the
		// resolver was built from. Zero/unset values pass through as the SDK
		// defaults (the With* options no-op on a non-positive arg). These bound
		// the UNAUTHENTICATED resolution-on-authz surface (a fake-but-HTTPS
		// client_id flood); see federation/doc.go for the operator rate-limit +
		// egress-policy that complete the defense.
		fedCfg := s.federationEntity.Config()
		s.clientStore = federation.NewRegistrationClientStore(
			s.clientStore,
			s.federationEntity.Resolver(),
			federation.WithRegistrationLogger(func(msg string, args ...any) {
				// A federation resolution/mapping miss is an EXPECTED,
				// oracle-safe outcome (an unknown client_id that resembles an
				// entity ID but doesn't validate), not a server error — log at
				// Info for operator visibility without alerting noise.
				s.logger.Info(msg, args...)
			}),
			federation.WithRegistrationNegativeCacheTTL(fedCfg.ResolutionNegativeCacheTTL),
			federation.WithRegistrationNegativeCacheMaxSize(fedCfg.ResolutionNegativeCacheMaxSize),
			federation.WithRegistrationMaxConcurrency(fedCfg.MaxConcurrentResolutions),
			// §7 trust-mark requirement (slice 4b): an EXTRA admission gate
			// sourced from the SAME federation Config. Empty
			// RequiredTrustMarkTypes ⇒ inert (byte-identical to the slice-3
			// path); when set, an auto-registering RP must carry a valid
			// configured-issuer-signed mark of each required type.
			federation.WithRegistrationTrustMarks(fedCfg),
		)
	}
	// Opt-in per-login ClientStore metadata cache (WithClientStoreCache).
	// Decorate LAST (after the federation registration decorator above) so
	// the cache is the OUTERMOST layer: a Get hit short-circuits before the
	// inner federation/operator store, and the cache transparently caches
	// the federation decorator's on-miss derived clients too. Done
	// post-options so order between WithClientStore / WithClientStoreCache /
	// WithFederationAutoRegistration is irrelevant. Only when a positive TTL
	// was requested AND a ClientStore is wired; otherwise no wrapper is
	// constructed and every s.clientStore.Get is byte-identical to a
	// non-caching build. ValidateSecret bypasses the cache (§2).
	if s.clientStoreCacheTTL > 0 && s.clientStore != nil {
		var onOutcome func(string)
		if s.metrics != nil {
			onOutcome = s.metrics.ObserveClientStoreCache
		}
		s.clientStoreCacheRef = newClientStoreCache(s.clientStore, s.clientStoreCacheTTL, onOutcome)
		s.clientStore = s.clientStoreCacheRef
	}
	return s
}

// WithRouter sets the HTTP router.
// RegisterAuthenticator adds an authenticator at runtime.
