package sso

import (
	"context"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/interfaces/sso/servercache"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/platform/sse"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// wiringState holds core provider wiring plus tenant/region/geo/network and client-store-cache/SPIFFE fields.
type wiringState struct {
	authenticators        map[string]Authenticator
	tokenIssuers          map[string]TokenIssuer // strategy name -> issuer
	defaultTokenStrategy  string
	tenantTokenStrategies map[string]string // tenant id -> strategy (issuer) name
	userProvider          UserProvider
	clientStore           ClientStore
	sessionMgr            SessionManager
	maxSessionsPerUser    int // 0 = unlimited (backward compatible)
	router                Router
	logger                spi.Logger
	auditor               *audit.Recorder
	caepTransmitter       *caep.Transmitter
	auditAPI              bool
	sseBroker             *sse.Broker
	sseHeartbeat          time.Duration
	requestIDMW           bool
	panicRecovery         bool
	compressionEnabled    bool
	debugRequestLogging   bool // when set, logs request/response bodies at DEBUG level

	// apiVersionSupported lists the version tokens (e.g. "v1", "v2alpha")
	// this deployment accepts via Accept-Version request-header negotiation
	// (WithAPIVersioning, ADR-0008). Nil/empty (the default) disables
	// negotiation entirely: a request — with or without the header — is
	// unaffected, additive by construction.
	apiVersionSupported []string
	// deprecationPolicy stamps RFC 8594 Sunset + the Deprecation response
	// header on EVERY response when set (WithAPIDeprecation). Nil (the
	// default) adds neither header to any response.
	deprecationPolicy *middleware.DeprecationPolicy
	// routeDeprecations stamps the same headers on individual endpoints or
	// path-prefix groups only, keyed by exact path or a "/"-suffixed prefix
	// (WithRouteDeprecation). Nil/empty (the default) leaves every route's
	// headers untouched.
	routeDeprecations map[string]middleware.DeprecationPolicy
	// apiV2AlphaPreview mounts the one-route ADR-0008 v2alpha proof-of-
	// mechanism endpoint, GET /api/v2alpha/version (WithAPIVersionPreview).
	// False (the default) ⇒ Mount() never registers it — byte-identical to
	// a build without this feature.
	apiV2AlphaPreview       bool
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

	// saml2BearerValidator is the RFC 7522 SAML 2.0 Bearer assertion validator
	// (nil = grant not supported). Wired via WithSAML2BearerGrant.
	saml2BearerValidator tokengrant.SAMLAssertionValidator

	// tenantQuotaStore enforces per-tenant resource limits (clients, users,
	// sessions). Nil = no quota enforcement (byte-identical to pre-quota build).
	tenantQuotaStore TenantQuotaStore

	// featureGates controls which optional protocol surfaces Mount()
	// registers routes for (attack-surface reduction). Zero value = every
	// gate unset ⇒ byte-identical to a pre-gate build (see FeatureGates).
	featureGates FeatureGates
	// configAuditStore persists runtime-configuration change history
	// (platform/configaudit). Nil = the change-capture hook + the
	// GET .../config/history admin endpoint are both off.
	configAuditStore configaudit.Store
	// configAppliedSnapshot is the redacted effective-config snapshot
	// captured ONCE at startup (WithConfigSnapshots). configRunningSnapshotFn
	// recomputes the CURRENT effective snapshot on demand for
	// GET .../config/running, GET .../config/diff, and the drift-digest
	// loop; nil falls back to configAppliedSnapshot in RunningConfigSnapshot
	// (correct: with no live snapshot source there is nothing to drift FROM,
	// so running == applied and the diff/digest endpoints report no change).
	configAppliedSnapshot   map[string]any
	configRunningSnapshotFn func(context.Context) (map[string]any, error)
	// configDriftInterval / configReplicaID configure the opt-in
	// cross-replica config-digest broadcast loop (WithConfigDriftDetection).
	// Zero interval (the default) means the feature is off.
	configDriftInterval time.Duration
	configReplicaID     string
}

// wrapPanicRecovery conditionally wraps the handler chain with panic
// recovery as the outermost layer — see server_routes.go's
// buildMiddlewareChain for the full ordering rationale. Relocated here (from
// server_routes.go, which sits at the line budget) to sit beside the
// panicRecovery field it reads.
func (s *Server) wrapPanicRecovery(inner http.Handler) http.Handler {
	if s.panicRecovery {
		return middleware.Recover(s.logger)(inner)
	}
	return inner
}

// wrapCompression conditionally wraps the handler chain with gzip response
// compression for large JSON payloads. Relocated here (from
// server_routes.go, which sits at the line budget) to sit beside the
// compressionEnabled field it reads.
func (s *Server) wrapCompression(inner http.Handler) http.Handler {
	if s.compressionEnabled {
		return middleware.Compress(inner)
	}
	return inner
}

// wrapAPIVersioning conditionally applies Accept-Version negotiation
// (rejects an unsupported requested version before body-limit/compression/
// CORS/security-headers ever run) and the Sunset/Deprecation response-header
// stamp (ADR-0008). Both sub-mechanisms are independently opt-in — a build
// that never calls WithAPIVersioning/WithAPIDeprecation/WithRouteDeprecation
// leaves inner completely untouched, so every existing route stays
// byte-identical. Placed beside the fields it reads for the same reason
// wrapPanicRecovery/wrapCompression live here rather than in
// server_routes.go (which is at the line budget).
func (s *Server) wrapAPIVersioning(inner http.Handler) http.Handler {
	if len(s.apiVersionSupported) > 0 {
		inner = middleware.AcceptVersion(middleware.AcceptVersionConfig{Supported: s.apiVersionSupported})(inner)
	}
	if s.deprecationPolicy != nil || len(s.routeDeprecations) > 0 {
		inner = middleware.Deprecation(middleware.DeprecationConfig{
			Global: s.deprecationPolicy,
			Routes: s.routeDeprecations,
		})(inner)
	}
	return inner
}
