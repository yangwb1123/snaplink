package sso

import (
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/interfaces/sso/servercache"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// wiringState holds core provider wiring plus tenant/region/geo/network and client-store-cache/SPIFFE fields.
type wiringState struct {
	authenticators          map[string]Authenticator
	tokenIssuers            map[string]TokenIssuer // strategy name -> issuer
	defaultTokenStrategy    string
	tenantTokenStrategies   map[string]string // tenant id -> strategy (issuer) name
	userProvider            UserProvider
	clientStore             ClientStore
	sessionMgr              SessionManager
	maxSessionsPerUser      int // 0 = unlimited (backward compatible)
	router                  Router
	logger                  spi.Logger
	auditor                 *audit.Recorder
	caepTransmitter         *caep.Transmitter
	auditAPI                bool
	requestIDMW             bool
	panicRecovery           bool
	compressionEnabled      bool
	debugRequestLogging     bool   // when set, logs request/response bodies at DEBUG level
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
	clientStoreCacheRef *servercache.ClientStoreCache

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

	// startedAt records when NewServer completed. Used by /api/v1/status
	// to compute uptime. Set automatically in NewServer; no option required.
	startedAt time.Time

	// jwtBearerValidator is the RFC 7523 JWT Bearer assertion validator
	// (nil = grant not supported). Wired via WithJWTBearerGrant.
	jwtBearerValidator tokengrant.JWTAssertionValidator

	// tenantQuotaStore enforces per-tenant resource limits (clients, users,
	// sessions). Nil = no quota enforcement (byte-identical to pre-quota build).
	tenantQuotaStore TenantQuotaStore
}
