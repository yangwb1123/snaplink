package sso

import (
	"context"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/sso/servercache"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/platform/sse"
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
	sseBroker               *sse.Broker
	sseHeartbeat            time.Duration
	requestIDMW             bool
	panicRecovery           bool
	compressionEnabled      bool
	debugRequestLogging     bool // when set, logs request/response bodies at DEBUG level
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

	// webhookEngine is the opt-in generic event/webhook egress engine
	// (WithWebhookEngine). Nil = no admin subscription/dead-letter routes,
	// no audit-sink tap — byte-identical to a build without the feature.
	webhookEngine *webhook.Engine

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

	// sessionManagementEnabled opts into OpenID Connect Session Management
	// 1.0 (WithOIDCSessionManagement): /auth/login stamps `session_state` +
	// a browser-state cookie, /end_session clears it, and discovery
	// advertises check_session_iframe. Default false — byte-identical to a
	// pre-feature build (no cookie, no session_state, no discovery field,
	// route unmounted).
	sessionManagementEnabled bool
}
