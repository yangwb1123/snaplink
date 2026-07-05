package sso

import (
	"context"
	"net/http"
	"net/url"
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
	"github.com/snaplink/sso/platform/lifecycle/sessionhub"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/platform/sse"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/shared/i18n"
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

	// sessionHub is the Cross-protocol Session Hub coordinator
	// (platform/lifecycle/sessionhub): given a global_sid it terminates every
	// linked protocol leg by composing the core-session destroy + OIDC
	// back-channel fan-out
	// (always wired here, in applySessionHub) and, optionally, the SAML SLO
	// fan-out (wired post-construction by infrastructure/saml's Deps.SessionHub
	// calling Coordinator.SetSAMLTrigger — a separate module, so it cannot be
	// a NewServer option without a wiring cycle). Never nil after NewServer;
	// the login flow populates it (one "core" leg per session) regardless of
	// whether anything ever reads it — see linkGlobalSession.
	sessionHub *sessionhub.Coordinator

	// localizer opts into error-response localization (WithLocalizer): when
	// set, authzErrorBody/authzErrorBodyDesc add an error_description_localized
	// field selected by the request's Accept-Language header (falling back to
	// the geo-resolved recommended_language). Nil (the default) is a
	// byte-identical no-op — see shared/i18n package doc.
	localizer i18n.Localizer

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

// newBackgroundHandlerContext adapts a plain context.Context into a
// HandlerContext for handler code (like fanOutBackchannelLogout, see
// Server.TriggerBackchannelLogout in accessors.go) that is normally only
// invoked from a real HTTP request but must also be reachable from a non-HTTP
// caller — the sessionhub.Coordinator. Audit/tenant/geo enrichment that reads
// request headers or ctx.Get simply finds nothing set — the SAME graceful
// "nothing to enrich" path a real request with those headers absent already
// takes; nothing panics or errors.
func newBackgroundHandlerContext(ctx context.Context) HandlerContext {
	req := (&http.Request{Header: make(http.Header), URL: &url.URL{}}).WithContext(ctx)
	return &backgroundHandlerContext{req: req}
}

// backgroundHandlerContext is the minimal HandlerContext implementation
// newBackgroundHandlerContext returns. Every method beyond Request/Set/Get is
// an inert no-op — the code paths driven through it (BCL fan-out) never write
// an HTTP response or read a route param/query/body.
type backgroundHandlerContext struct {
	req *http.Request
	kv  map[string]any
}

func (b *backgroundHandlerContext) Request() *http.Request { return b.req }
func (b *backgroundHandlerContext) ResponseWriter() http.ResponseWriter {
	return discardResponseWriter{}
}
func (b *backgroundHandlerContext) Param(string) string  { return "" }
func (b *backgroundHandlerContext) Query(string) string  { return "" }
func (b *backgroundHandlerContext) Bind(any) error       { return nil }
func (b *backgroundHandlerContext) JSON(int, any)        {}
func (b *backgroundHandlerContext) Redirect(int, string) {}
func (b *backgroundHandlerContext) Set(key string, val any) {
	if b.kv == nil {
		b.kv = make(map[string]any)
	}
	b.kv[key] = val
}
func (b *backgroundHandlerContext) Get(key string) any { return b.kv[key] }

// discardResponseWriter is the http.ResponseWriter backgroundHandlerContext
// hands out. A caller driving logic through it (the Coordinator path) never
// has a real response in flight, so nothing ever inspects the values written
// here — it exists only so ResponseWriter() has a non-nil value to return.
type discardResponseWriter struct{}

func (discardResponseWriter) Header() http.Header         { return http.Header{} }
func (discardResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (discardResponseWriter) WriteHeader(int)             {}

// SessionHub returns the cross-protocol session-hub coordinator (Cross-
// protocol Session Hub backlog item): given a global_sid, it terminates every
// linked protocol leg by composing the already-existing per-protocol
// mechanisms (core session destroy, OIDC back-channel logout fan-out, and —
// once infrastructure/saml's Deps.SessionHub is wired to this same value and
// calls Coordinator.SetSAMLTrigger — SAML IdP-initiated SLO fan-out). Never
// nil: constructed in NewServer regardless of which optional mechanisms end
// up wired, so it is always safe to call. Relocated from accessors.go to keep
// that file within the per-file line budget; belongs beside the sessionHub
// field and its background-context shim here.
func (s *Server) SessionHub() *sessionhub.Coordinator { return s.sessionHub }

// TriggerBackchannelLogout implements sessionhub.OIDCLogoutTrigger: it
// composes the existing OIDC Back-Channel Logout 1.0 fan-out
// (fanOutBackchannelLogout) for a caller that only has a plain
// context.Context — the Coordinator — rather than a full HandlerContext (an
// HTTP request/response pair). No new logout mechanism is implemented here;
// this only adapts the calling convention (newBackgroundHandlerContext,
// above). A nil originClient means the fan-out is driven purely off the
// subjectClientIndex (every RP the subject is known to, not just one) — the
// correct behavior for a Coordinator-driven logout, which isn't scoped to any
// single triggering client.
func (s *Server) TriggerBackchannelLogout(ctx context.Context, subject, sid string) {
	s.fanOutBackchannelLogout(newBackgroundHandlerContext(ctx), nil, subject, sid)
}
