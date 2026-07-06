package sso

import (
	"context"
	"net/http"
	"net/url"
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
	"github.com/snaplink/sso/platform/lifecycle/admingovernance"
	"github.com/snaplink/sso/platform/lifecycle/rebac"
	"github.com/snaplink/sso/platform/lifecycle/sessionhub"
	"github.com/snaplink/sso/platform/lifecycle/wasmauthz"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/platform/sse"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/i18n"
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

	// webhookEngine is the opt-in generic event/webhook egress engine
	// (WithWebhookEngine). Nil = no admin subscription/dead-letter routes,
	// no audit-sink tap — byte-identical to a build without the feature.
	webhookEngine *webhook.Engine

	// rebacEngine is the opt-in Zanzibar-style relationship-tuple Check
	// engine (WithRebacEngine, platform/lifecycle/rebac). Nil = no admin
	// debug route mounted — byte-identical to a build without the
	// feature. Unlike the other authorization layers wired on Server,
	// this engine is NOT consulted by any built-in gate (see the package
	// doc); the only Server-side use is the operational-debugging
	// endpoint below.
	rebacEngine *rebac.Engine

	// wasmAuthzEngine is the opt-in pluggable WASM authorization-decision
	// engine (WithWASMAuthzEngine, platform/lifecycle/wasmauthz). Nil = no
	// admin debug route mounted — byte-identical to a build without the
	// feature. Like rebacEngine, this is NOT consulted by any built-in
	// gate; the only Server-side use is the operational-debugging endpoint.
	wasmAuthzEngine *wasmauthz.Engine

	// scimProvisionSink is the opt-in outbound SCIM 2.0 provisioning push
	// (WithSCIMProvisioner; typically a *scimprovision.Sink from
	// protocols/scimprovision, typed here as audit.Sink — see
	// WithSCIMProvisioner's doc for why). Nil = no audit-sink tap —
	// byte-identical to a build without the feature (zero outbound SCIM
	// traffic).
	scimProvisionSink audit.Sink

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

	// Cloud workload-identity client authentication (AWS/GCP/Azure
	// analog of the SPIFFE path above, but as a /token client-
	// authentication method rather than a token-exchange subject_token).
	// Keyed by WorkloadIdentityProvider.Name() ("gcp", ...; wired via
	// WithWorkloadIdentityProviders). A Client opts in by setting
	// TokenEndpointAuthMethod to ClientAuthWorkloadIdentity plus both
	// Client.Attributes[security.AttrWorkloadIdentityProvider] (which key
	// of this map to use) and
	// Client.Attributes[security.AttrWorkloadIdentitySubject] (the
	// expected verified identity). Nil/empty map = the feature is
	// entirely off: no client can be configured with
	// ClientAuthWorkloadIdentity in a way that ever succeeds, since the
	// provider lookup always misses.
	workloadIdentityProviders map[string]security.WorkloadIdentityProvider

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

	// approvalStore + changeRegistry + approvalActionTypes back the generic
	// change-approval workflow (WithChangeApprovalStore). Nil store ⇒ the
	// /api/v1/admin/changes routes are NOT mounted — byte-identical to a
	// build without this feature.
	approvalStore       admingovernance.ApprovalStore
	changeRegistry      *admingovernance.Registry
	approvalActionTypes admingovernance.RequiredActionTypes
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

// localizeErrorBody enriches m in place with error_description_localized
// when WithLocalizer is configured AND it holds a translation for code in
// the request's preferred locale (Accept-Language, falling back to the geo
// recommended_language already resolved for this request). Byte-identical
// no-op — m untouched — with no Localizer wired, or when it has no entry
// for this (code, locale): see WithLocalizer. Relocated from
// server_helpers.go to keep that file within the per-file line budget;
// belongs beside the localizer field here.
func (s *Server) localizeErrorBody(ctx HandlerContext, m map[string]string, code string) {
	if s.localizer == nil {
		return
	}
	geoLang := ""
	if info, ok := GeoFromHandlerContext(ctx); ok {
		geoLang = info.RecommendedLanguage
	}
	locale := i18n.PreferredLocale(ctx.Request().Header.Get(core.HeaderAcceptLanguage), geoLang)
	if desc, ok := s.localizer.Localize(code, locale); ok {
		core.ErrorBodyWithLocalizedDesc(m, desc)
	}
}

// ApprovalStore / ChangeRegistry / ApprovalActionTypes back the generic
// change-approval workflow (domains/admingovernance). Satisfies admin.Deps.
// A nil ApprovalStore means the /api/v1/admin/changes routes are not
// mounted at all — byte-identical to a build without the feature. Relocated
// from accessors.go to keep that file within the per-file line budget;
// belongs beside the approvalStore/changeRegistry/approvalActionTypes
// fields here.
func (s *Server) ApprovalStore() admingovernance.ApprovalStore { return s.approvalStore }
func (s *Server) ChangeRegistry() *admingovernance.Registry    { return s.changeRegistry }
func (s *Server) ApprovalActionTypes() admingovernance.RequiredActionTypes {
	return s.approvalActionTypes
}

// IntrospectionBatchMaxSize returns the configured cap on batch
// /token/introspect requests, or 0 when the capability is disabled
// (WithIntrospectionBatch never called) — the default-off contract.
// Relocated from accessors.go to keep that file within the per-file line
// budget.
func (s *Server) IntrospectionBatchMaxSize() int {
	if !s.introspectionBatchEnabled {
		return 0
	}
	return s.introspectionBatchMaxSize
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

// ConfigAuditStore returns the wired runtime-configuration-audit store
// (WithConfigAuditStore), or nil when unwired. Relocated from accessors.go
// (which was at the line budget) — beside the rest of the config-audit
// wiring in this file.
func (s *Server) ConfigAuditStore() configaudit.Store { return s.configAuditStore }

// AppliedConfigSnapshot implements configaudit.HandlerDeps: the redacted
// effective-config snapshot captured once at startup (WithConfigSnapshots).
// Returns configaudit.ErrSnapshotUnavailable when no snapshot was ever
// wired, so the HTTP handler can answer 501 rather than a bare 500.
// Relocated from accessors.go (which was at the line budget).
func (s *Server) AppliedConfigSnapshot() (map[string]any, error) {
	if s.configAppliedSnapshot == nil {
		return nil, configaudit.ErrSnapshotUnavailable
	}
	return s.configAppliedSnapshot, nil
}

// RunningConfigSnapshot implements configaudit.HandlerDeps: the CURRENT
// effective-config snapshot. Falls back to AppliedConfigSnapshot when no
// live snapshot function was wired (WithConfigSnapshots without a
// runningFn) — correct, since with no live source there is nothing to
// drift FROM.
func (s *Server) RunningConfigSnapshot(ctx context.Context) (map[string]any, error) {
	if s.configRunningSnapshotFn != nil {
		return s.configRunningSnapshotFn(ctx)
	}
	return s.AppliedConfigSnapshot()
}

// ClientStore exposes the wired client store for the admin tenant-export
// handler (admin.Deps). Distinct from ClientStoreAccessor (accessors.go)
// only in name — that older accessor predates this Deps interface and
// callers elsewhere already depend on its name, so it stays rather than
// churn every call site; a method may share its name with the
// package-level ClientStore type alias (different namespace — see
// aliases.go) without conflict.
func (s *Server) ClientStore() core.ClientStore { return s.clientStore }

// applyConfigAuditWiring wires the config-audit change-capture hook (AGENTS.md
// "narrowest existing seam") post-options, in NewServer. Only when BOTH an
// auditor and a configaudit.Store are present, so a build without
// WithConfigAuditStore pays zero cost (the hook is never set, and
// Recorder.Record's nil-check short-circuits on every call).
func (s *Server) applyConfigAuditWiring() {
	if s.auditor != nil && s.configAuditStore != nil {
		s.auditor.SetConfigChangeHook(s.recordConfigHistoryFromAudit)
	}
}

// mountConfigAuditAPI registers the runtime-configuration-audit admin API
// (GET .../config/{running,applied,diff,history}). The snapshot endpoints
// mount only when a config-snapshot source is wired (WithConfigSnapshots);
// history additionally requires WithConfigAuditStore, so a deployment using
// only the change-capture hook (no snapshot wiring) still gets a history
// endpoint without the snapshot/diff routes erroring on every request.
func (s *Server) mountConfigAuditAPI(api Router) {
	if s.configAppliedSnapshot != nil || s.configRunningSnapshotFn != nil {
		api.GET(PathAdminConfigRunning, s.handleConfigRunning)
		api.GET(PathAdminConfigApplied, s.handleConfigApplied)
		api.GET(PathAdminConfigDiff, s.handleConfigDiff)
		api.POST(PathAdminConfigClusterDiff, s.handleConfigClusterDiff)
	}
	if s.configAuditStore != nil {
		api.GET(PathAdminConfigHistory, s.handleConfigHistory)
	}
}

func (s *Server) handleConfigRunning(ctx HandlerContext)     { configaudit.HandleRunning(s, ctx) }
func (s *Server) handleConfigApplied(ctx HandlerContext)     { configaudit.HandleApplied(s, ctx) }
func (s *Server) handleConfigDiff(ctx HandlerContext)        { configaudit.HandleDiff(s, ctx) }
func (s *Server) handleConfigClusterDiff(ctx HandlerContext) { configaudit.HandleClusterDiff(s, ctx) }
func (s *Server) handleConfigHistory(ctx HandlerContext)     { configaudit.HandleHistory(s, ctx) }

// The config-history change-capture helpers (configHistoryResourceByEventType,
// recordConfigHistoryFromAudit, RecordConfigChange) live in options_admin.go —
// relocated there beside the config-audit wiring options to hold this file
// under the 500-line maintainability budget.
