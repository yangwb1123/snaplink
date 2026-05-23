package sso

import "github.com/snaplink/sso/oidc"

import "github.com/snaplink/sso/spi"

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/tenant"
	"github.com/snaplink/sso/tracing"
)

// Server is the core SSO orchestrator.
type Server struct {
	authenticators                 map[string]Authenticator
	tokenIssuers                   map[string]TokenIssuer // strategy name -> issuer
	defaultTokenStrategy           string
	userProvider                   UserProvider
	clientStore                    ClientStore
	sessionMgr                     SessionManager
	router                         Router
	middleware                     []MiddlewareFunc
	logger                         spi.Logger
	auditor                        *audit.Recorder
	auditAPI                       bool
	requestIDMW                    bool
	permissions                    permissions.Provider
	embedPermissions               bool
	netStore                       netpolicy.Store
	netClassifier                  *netpolicy.Classifier
	netAPI                         bool
	geoProvider                    geo.Provider
	geoMiddlewareOpts              GeoMiddlewareOptions
	tenantStore                    tenant.Store
	tenantMiddlewareOpts           TenantMiddlewareOptions
	tenantSuspensionEnabled        bool
	tenantSuspensionCache          *suspensionCache
	riskScorer                     spi.RiskScorer
	mfaProvider                    spi.MFAProvider
	mfaChallengeStore              spi.MFAChallengeStore
	mfaChallengeTTL                time.Duration
	anomalyRunner                  *anomaly.Runner
	metrics                        *metrics.Metrics
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
	idTokenIssuer                  oidc.IDTokenIssuer
	deviceCodeStore                oauth.DeviceCodeStore
	deviceCodeTTL                  time.Duration
	deviceCodeInterval             time.Duration
	deviceVerifyBaseURL            string
	parStore                       oauth.PARStore
	parTTL                         time.Duration
	dcrPolicy                      *oauth.DCRPolicy
	oauth21Strict                  bool
	logoutTokenIssuer              LogoutTokenIssuer
	logoutNotifier                 LogoutNotifier
	backchannelLogoutMaxConcurrent int
	accountLockout                 security.AccountLockout
	jtiReplayStore                 security.JTIReplayStore
	subjectClientIndex             security.SubjectClientIndex
	jarFetcher                     security.JARFetcher
	jarDecrypter                   security.JWEDecrypter
	clientCertExtractor            ClientCertExtractor
	dpopNonceProvider              DPoPNonceProvider
	metadataSigner                 oidc.MetadataSigner
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

	// OIDC Core §8 pairwise subject identifiers. Nil pairwiseStore
	// disables the feature entirely — every client receives a public
	// (local) sub regardless of subject_type. Salt mixes into the
	// hash; empty falls back to DefaultPairwiseSalt.
	pairwiseStore PairwiseSubjectStore
	pairwiseSalt  string
}

// Option configures the Server.
type Option func(*Server)

// NewServer creates a new SSO server.
func NewServer(opts ...Option) *Server {
	s := &Server{
		authenticators:       make(map[string]Authenticator),
		tokenIssuers:         make(map[string]TokenIssuer),
		issuer:               DefaultIssuer,
		logger:               spi.NopLogger{},
		discoveryCacheTTL:    defaultDiscoveryCacheTTL,
		discoveryDocCacheTTL: DefaultDiscoveryDocCacheTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithRouter sets the HTTP router.
func WithRouter(r Router) Option {
	return func(s *Server) { s.router = r }
}

// WithAuthenticator registers an authentication method.
func WithAuthenticator(a Authenticator) Option {
	return func(s *Server) { s.authenticators[a.Name()] = a }
}

// WithTokenIssuer registers a TokenIssuer under the given strategy name.
// Clients select among registered strategies via Client.TokenStrategy.
// If no client-level strategy is set, the Server's default strategy is used.
func WithTokenIssuer(name string, ti TokenIssuer) Option {
	return func(s *Server) { s.tokenIssuers[name] = ti }
}

// WithAccountLockout wires a per-account brute-force defense.
// Complements `WithRateLimit` — rate limit catches IP-level
// volume; account lockout catches per-account targeting that
// stays under the IP threshold (the distributed credential
// stuffing case). Without this option, the per-account defense
// is absent and operators rely entirely on the IP rate limiter.
//
// `security.NewMemoryAccountLockout()` is the in-process default with
// conservative thresholds (5 failures / 1 hour window / 15 min
// lockout). Multi-replica deployments MUST swap for a shared
// backend so attackers can't slip through the per-replica fork.
func WithAccountLockout(a security.AccountLockout) Option {
	return func(s *Server) { s.accountLockout = a }
}

// WithBackchannelLogout wires the two SPIs that together enable
// OIDC Back-Channel Logout 1.0: a LogoutTokenIssuer (typically
// the same Ed25519JWTIssuer that mints access + ID tokens — one
// signing key serves all three) and a LogoutNotifier (the
// production default is `NewHTTPLogoutNotifier()`). Without
// both wired, /logout still revokes the local session + token
// but no RP notification fires.
//
// When wired, the discovery doc advertises
// backchannel_logout_supported: true.
func WithBackchannelLogout(issuer LogoutTokenIssuer, notifier LogoutNotifier) Option {
	return func(s *Server) {
		s.logoutTokenIssuer = issuer
		s.logoutNotifier = notifier
	}
}

// WithBackchannelLogoutMaxConcurrent overrides the fan-out
// parallelism cap when the security.SubjectClientIndex notifies multiple
// RPs at once. Defaults to DefaultBackchannelLogoutMaxConcurrent
// (8). Lower it to ease memory/connection pressure when each RP
// is on a slow upstream; raise it when N RPs is large and per-RP
// p99 is well under the timeout. A value <= 0 falls back to the
// default.
func WithBackchannelLogoutMaxConcurrent(n int) Option {
	return func(s *Server) { s.backchannelLogoutMaxConcurrent = n }
}

// WithOAuth21StrictMode toggles enforcement of the OAuth 2.1
// deviations from OAuth 2.0. When true:
//
//   - response_type=token (the implicit flow) is rejected with
//     unsupported_response_type on /auth/login. Empty
//     response_type (which defaulted to direct-mint = implicit
//     style) is treated the same — strict mode requires
//     response_type=code explicitly.
//   - Every authorization_code request MUST carry code_challenge
//     (PKCE), overriding any per-client RequirePKCE=false opt-out.
//   - redirect_uri MUST use scheme=https. Localhost (any port)
//     remains permitted for development.
//
// Recommended for new production deployments + FAPI 2.0 / Open
// Banking customers. Existing OAuth 2.0 callers continue to work
// when the option is omitted (default false) — no implicit
// breaking change.
func WithOAuth21StrictMode(enabled bool) Option {
	return func(s *Server) { s.oauth21Strict = enabled }
}

// WithDefaultTokenStrategy names the strategy used when a Client does not
// specify its own.
func WithDefaultTokenStrategy(name string) Option {
	return func(s *Server) { s.defaultTokenStrategy = name }
}

// WithUserProvider sets the user data store.
func WithUserProvider(up UserProvider) Option {
	return func(s *Server) { s.userProvider = up }
}

// WithClientStore sets the client application store.
func WithClientStore(cs ClientStore) Option {
	return func(s *Server) { s.clientStore = cs }
}

// WithSessionManager sets the session manager.
func WithSessionManager(sm SessionManager) Option {
	return func(s *Server) { s.sessionMgr = sm }
}

// WithLogger sets the logger.
func WithLogger(l spi.Logger) Option {
	return func(s *Server) { s.logger = l }
}

// WithIssuer sets the token issuer name.
func WithIssuer(issuer string) Option {
	return func(s *Server) { s.issuer = issuer }
}

// WithAuthCodeStore enables the OAuth 2.0 authorization_code grant on the
// /token endpoint. Without it, /auth/login with response_type=code
// returns 501 and POST /token grant_type=authorization_code returns the
// "no authorization code store configured" error.
//
// ttl is the lifetime of issued codes (per RFC 6749 §4.1.2 SHOULD be
// short — 10 minutes is typical). Pass <=0 to use [DefaultAuthCodeTTL].
func WithAuthCodeStore(store oauth.AuthCodeStore, ttl time.Duration) Option {
	return func(s *Server) {
		s.authCodeStore = store
		if ttl > 0 {
			s.authCodeTTL = ttl
		}
	}
}

// WithDeviceCodeStore enables the OAuth 2.0 device authorization
// grant (RFC 8628) for clients on devices that can't open a browser
// — CLIs, TVs, IoT, embedded shells. The new endpoints are
// /device/code (device-initiated) and /device/verify (user-facing
// approval) plus the grant_type=urn:ietf:params:oauth:grant-type:device_code
// branch on /token. Without this option, all three return 501.
//
// ttl is the device_code lifetime (RFC §3.2 typically 5-15 minutes).
// pollInterval is the minimum allowed poll interval — devices polling
// faster than this get slow_down. Pass <=0 for the defaults
// (DefaultDeviceCodeTTL = 10 min; DefaultDevicePollMin = 5s).
//
// verificationBaseURL is what the server tells devices to display
// (e.g. "https://sso.example.com/device"). Empty = derive from the
// request, same fallback as the discovery endpoint.
func WithDeviceCodeStore(store oauth.DeviceCodeStore, ttl, pollInterval time.Duration, verificationBaseURL string) Option {
	return func(s *Server) {
		s.deviceCodeStore = store
		if ttl > 0 {
			s.deviceCodeTTL = ttl
		}
		if pollInterval > 0 {
			s.deviceCodeInterval = pollInterval
		}
		s.deviceVerifyBaseURL = verificationBaseURL
	}
}

// WithDynamicClientRegistration enables RFC 7591 Dynamic Client
// Registration on POST /register. Without this option /register
// returns 501 and a relying party MUST be pre-registered by the
// operator.
//
// The registration endpoint is gated by the policy's
// InitialAccessToken (a pre-shared bearer the operator distributes
// to relying parties allowed to register) UNLESS
// AllowOpenRegistration is set — open registration is supported but
// strongly discouraged because every public registration endpoint in
// the wild eventually gets used for resource exhaustion / spam
// client creation.
//
// Discovery doc advertises `registration_endpoint` whenever this
// option is wired (regardless of the auth mode).
func WithDynamicClientRegistration(policy oauth.DCRPolicy) Option {
	return func(s *Server) { s.dcrPolicy = &policy }
}

// WithPARStore enables Pushed Authorization Requests (RFC 9126) on
// POST /par. Without it, /par returns 501 and the /auth/login handler
// ignores any inbound `request_uri` parameter — the legacy direct-
// parameter flow keeps working unchanged.
//
// When wired, confidential clients can push their authorization
// request parameters server-to-server (authenticated by client
// credentials) and receive back an opaque request_uri to redirect
// the user agent with. The /auth/login handler resolves the
// request_uri via store.Consume and merges the stored params into
// the in-flight request — request_uri values are SINGLE-USE per
// §2.2 (atomic delete on consume).
//
// ttl is the spec-recommended request_uri lifetime. Pass <=0 for
// [oauth.DefaultPARTTL] (90 seconds — generous floor that still rejects
// session-length replay windows).
func WithPARStore(store oauth.PARStore, ttl time.Duration) Option {
	return func(s *Server) {
		s.parStore = store
		if ttl > 0 {
			s.parTTL = ttl
		}
	}
}

// WithJTIReplayStore enables jti-based replay protection on every JWT
// the server consumes that carries a jti claim (today: RFC 9101 JAR
// request objects; future hooks: DPoP proofs, JWT bearer client
// assertions, token-exchange actor_tokens).
//
// Without it, JTI replay defense is OFF and every JAR JWT is accepted
// once per signature validation — the spec-correct fallback per
// RFC 9101 §10.8 ("SHOULD" not "MUST"). Production deployments
// exposed to network adversaries SHOULD wire it; the in-memory
// backend (defaultimpl.NewMemoryJTIReplayStore) is single-replica
// only and multi-replica deployments need a Redis-style shared
// store before the defense holds.
func WithJTIReplayStore(store security.JTIReplayStore) Option {
	return func(s *Server) { s.jtiReplayStore = store }
}

// WithSubjectClientIndex enables OIDC Back-Channel Logout multi-RP
// fan-out. Each successful token issuance records (subject, client_id)
// in the index; at /logout and /end_session the AS iterates every
// client the subject has been seen with and emits a logout_token to
// each (filtered to clients that declared a BackchannelLogoutURI).
//
// Without it, BCL only notifies the single client present in the
// bearer / id_token_hint at logout time — the original v1 behavior.
// With it wired, logging out of app A also logs the user out of
// apps B, C, ... — "true single sign-out" at the cost of one HTTP
// POST per signed-in RP.
//
// The default backend (defaultimpl.NewMemorySubjectClientIndex) is
// single-replica only; multi-replica deployments need a shared
// store (Redis, SQL) so a fan-out triggered on replica A reaches
// a client whose last issuance happened on replica B.
func WithSubjectClientIndex(idx security.SubjectClientIndex) Option {
	return func(s *Server) { s.subjectClientIndex = idx }
}

// WithJARFetcher enables the RFC 9101 §5.2.2 `request_uri` URL-fetch
// variant. Without it, /auth/login still accepts PAR's `urn:`
// request_uri prefix but rejects HTTPS URLs with invalid_request_uri.
// With it wired, RPs can host their signed authorization-request
// JWT at a URL and pass that URL on the wire.
//
// Per-client `AllowedRequestURIs` is the SSRF defense — only URLs
// explicitly registered on the client are fetched. Operators MUST
// set the allowlist on every JAR-using client; otherwise an
// attacker who steals client_id could pivot the AS into fetching
// arbitrary internal endpoints.
//
// The default fetcher (defaultimpl-less here: see NewHTTPJARFetcher)
// is HTTPS-only, no-redirects, 5s timeout, 16KB body cap.
func WithJARFetcher(fetcher security.JARFetcher) Option {
	return func(s *Server) { s.jarFetcher = fetcher }
}

// WithJARDecrypter enables RFC 9101 §6.4 encrypted JAR — the request
// object arrives JWE-wrapped (5 segments) instead of plain JWS
// (3 segments). The AS decrypts to plaintext, then validates the
// inner signed JAR via the existing verifyJAR pipeline.
//
// Wire shape:
//   - Without this option, JWE-shaped JAR payloads are rejected with
//     invalid_request_object (fail-closed; the AS can't validate
//     what it can't decrypt).
//   - With it wired, both plain JWS and JWE-wrapped JWS request
//     objects are accepted; the AS branches on segment count.
//
// The decrypter typically also implements [JWKSProvider] so its
// public encryption key shows up at /.well-known/jwks.json with
// `use: "enc"`. RPs introspect that to choose which kid to encrypt
// to. Default impl: [defaultimpl.RSAJWEDecrypter] (RSA-OAEP-256 +
// A256GCM).
//
// Discovery advertises supported alg + enc lists when this option
// is wired — see request_object_encryption_alg_values_supported +
// request_object_encryption_enc_values_supported.
func WithJARDecrypter(d security.JWEDecrypter) Option {
	return func(s *Server) { s.jarDecrypter = d }
}

// WithClientCertExtractor enables RFC 8705 §3 mTLS certificate-
// bound access tokens. When wired, every /token request whose
// extractor returns a non-nil cert has the issued access token
// stamped with `cnf.x5t#S256` — the cert's SHA-256 thumbprint.
// Discovery's `tls_client_certificate_bound_access_tokens` flag
// flips true.
//
// Pluggable so reverse-proxy-terminated TLS works: deployments
// where envoy / nginx forward client certs via
// `X-Forwarded-Client-Cert` supply a custom extractor that parses
// the header. Direct-TLS deployments wire
// [DefaultTLSPeerCertExtractor].
//
// mTLS-bound tokens still report `token_type: Bearer` per RFC
// 8705 §3 (the binding is implicit in the cnf claim, not a new
// type). Resource servers MUST check the cert on every protected
// request against the token's cnf — same architectural
// separation as DPoP.
func WithClientCertExtractor(ex ClientCertExtractor) Option {
	return func(s *Server) { s.clientCertExtractor = ex }
}

// WithSupportedACRValues declares the OIDC ACR values this server's
// authenticators can actually deliver. Surfaced as
// `acr_values_supported` in discovery so RPs that branch on ACR
// (step-up auth, FAPI 2.0 compliance) can introspect.
//
// Operators populate this with the full set of ACR strings their
// wired authenticators stamp into `result.AuthMethods` / `.ACR` —
// e.g. ["urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"].
// Empty / omitted leaves the field absent (legacy behavior, RP must
// infer capabilities out-of-band).
//
// Authenticators that compute ACR dynamically (e.g. MFA combiners)
// SHOULD list every possible output value here so RPs see the
// complete contract.
func WithSupportedACRValues(values ...string) Option {
	return func(s *Server) {
		out := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, v := range values {
			if v == "" {
				continue
			}
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
		s.supportedACRValues = out
	}
}

// WithOperatorMetadata registers the OIDC Discovery §3 `op_policy_uri`,
// `op_tos_uri`, and `service_documentation` advertisements. RPs
// surface these to their end users when displaying a consent screen
// ("by signing in you accept <op_policy_uri> ...") and integrators
// link to `service_documentation` for SDK reference. Empty values
// omit the corresponding discovery field (omitempty semantics).
func WithOperatorMetadata(policyURI, tosURI, docs string) Option {
	return func(s *Server) {
		s.opPolicyURI = policyURI
		s.opTosURI = tosURI
		s.serviceDocumentation = docs
	}
}

// WithIDTokenIssuer enables OpenID Connect ID Token emission alongside
// the access token whenever a login or token-exchange request carries
// the "openid" scope. Without it, the `id_token` field is omitted from
// every response — relying parties built against the access-token-only
// flows keep working unchanged.
//
// Pass the same Ed25519JWTIssuer as both WithTokenIssuer and
// WithIDTokenIssuer to share one signing key + one JWKS entry —
// that's the canonical wiring for a single-key OIDC deployment.
func WithIDTokenIssuer(issuer oidc.IDTokenIssuer) Option {
	return func(s *Server) { s.idTokenIssuer = issuer }
}

// WithRefreshTokenStore enables the OAuth 2.0 refresh_token grant on the
// /token endpoint and turns on server-managed refresh token issuance on
// every successful access-token mint (login direct flow + authorization_code
// exchange). Without it, POST /token grant_type=refresh_token returns
// 501 and the response_token field passes through whatever the underlying
// TokenIssuer returned (typically empty for stateless JWT).
//
// Rotation: tokens are single-use. Each successful refresh consumes the
// presented token and issues a new one. A presented-twice token always
// fails as invalid_grant (the second presentation can't tell whether
// the first was legitimate or a replay; rejection is the safe default).
//
// ttl is the lifetime of issued tokens (per RFC 6749 §6 typically days
// to weeks; mobile clients often keep them for months). Pass <=0 to use
// [DefaultRefreshTokenTTL] (30 days).
func WithRefreshTokenStore(store oauth.RefreshTokenStore, ttl time.Duration) Option {
	return func(s *Server) {
		s.refreshTokenStore = store
		if ttl > 0 {
			s.refreshTokenTTL = ttl
		}
	}
}

// WithSessionTTL is retained for source compatibility but has no effect.
// The Server delegates session lifetime to the configured [SessionManager];
// pass the desired TTL to that constructor instead, e.g.
// defaultimpl.NewMemorySessionManager(24*time.Hour).
//
// Deprecated: configure session lifetime on the SessionManager directly.
func WithSessionTTL(_ time.Duration) Option {
	return func(*Server) {}
}

// WithTokenTTL is retained for source compatibility but has no effect.
// The Server delegates token lifetime to the configured [TokenIssuer];
// pass the desired TTL to that constructor instead, e.g.
// defaultimpl.WithEd25519TokenTTL(time.Hour) when building the issuer.
//
// Deprecated: configure token lifetime on the TokenIssuer directly.
func WithTokenTTL(_ time.Duration) Option {
	return func(*Server) {}
}

// WithBaseURL is retained for source compatibility but has no effect.
// Absolute URLs (callback redirects, JWKS) are derived from incoming
// request headers + reverse-proxy hints, not from a configured constant.
//
// Deprecated: the value is no longer threaded through any handler.
func WithBaseURL(_ string) Option {
	return func(*Server) {}
}

// WithAuditRecorder enables audit-event recording. The Server will emit
// login/logout/code-send/etc. events to r. Without this option, audit calls
// are silent no-ops.
func WithAuditRecorder(r *audit.Recorder) Option {
	return func(s *Server) { s.auditor = r }
}

// WithAuditAPI mounts the audit query endpoints
// (GET /api/v1/audit/events, GET /api/v1/audit/events/:id). Requires a
// recorder to also be set. Endpoints are unauthenticated by default — gate
// them with middleware or a reverse proxy if exposed beyond localhost.
func WithAuditAPI() Option {
	return func(s *Server) { s.auditAPI = true }
}

// WithTracingMiddleware installs TracingMiddleware ahead of all routes.
// It propagates W3C Traceparent (trace_id + span chaining) and X-Request-Id
// (single-hop correlation) so audit events automatically pick them up.
func WithTracingMiddleware() Option {
	return func(s *Server) { s.requestIDMW = true }
}

// WithRequestIDMiddleware is a back-compat alias for WithTracingMiddleware.
// New code should call WithTracingMiddleware directly.
//
// Deprecated: use WithTracingMiddleware. The middleware was renamed once
// it grew W3C Traceparent propagation alongside the original X-Request-Id
// stamping; the name is kept here so existing call sites still compile.
func WithRequestIDMiddleware() Option { return WithTracingMiddleware() }

// WithPermissionProvider enables the per-user permission/role/menu lookup
// endpoints. Without this option, those endpoints respond 501.
func WithPermissionProvider(p permissions.Provider) Option {
	return func(s *Server) { s.permissions = p }
}

// WithEmbedPermissionsInLogin attaches a user's roles, permissions, and menu
// tree to the /auth/login response — convenient for SPAs that want the
// authorization surface immediately, instead of an extra round trip.
func WithEmbedPermissionsInLogin() Option {
	return func(s *Server) { s.embedPermissions = true }
}

// WithNetworkPolicy enables the network-classification control plane. store
// is required; classifier is optional — when nil, the /classify and
// /resolve-me endpoints respond 501.
//
// Pair with WithNetworkPolicyAPI() to expose the REST endpoints under
// /api/v1/netpolicy/...; otherwise only the Server's internal callers
// (Mount routes that need to know the request's network class) use it.
func WithNetworkPolicy(store netpolicy.Store, classifier *netpolicy.Classifier) Option {
	return func(s *Server) {
		s.netStore = store
		s.netClassifier = classifier
	}
}

// WithNetworkPolicyAPI mounts the netpolicy REST endpoints
// (GET/POST /api/v1/netpolicy/policies[/:name], DELETE on :name,
// GET /api/v1/netpolicy/classify + /resolve-me). Requires WithNetworkPolicy.
// The endpoints are unauthenticated by default — gate them with middleware
// or a reverse proxy if exposed beyond localhost.
func WithNetworkPolicyAPI() Option {
	return func(s *Server) { s.netAPI = true }
}

// WithGeoProvider enables IP → geo enrichment on the auth path.
// During Mount, the Server installs GeoMiddleware ahead of all
// routes so handlers (and through them, AuthResult) can read the
// recommended language + country code via GeoFromHandlerContext.
//
// A nil provider is a no-op so callers may pass the result of a
// disabled-by-config factory unconditionally.
func WithGeoProvider(p geo.Provider) Option {
	return func(s *Server) { s.geoProvider = p }
}

// WithGeoMiddlewareOptions tunes how the geo middleware extracts
// the client IP and bounds the lookup. Optional — the middleware
// has sane defaults (XFF first hop → X-Real-IP → RemoteAddr,
// 200ms timeout, no error reporter). Pass a custom Extractor when
// the deployment doesn't trust forwarded headers (no edge proxy).
func WithGeoMiddlewareOptions(opts GeoMiddlewareOptions) Option {
	return func(s *Server) { s.geoMiddlewareOpts = opts }
}

// WithTenantStore enables multi-tenant + multi-domain routing.
// During Mount, the Server installs TenantMiddleware ahead of all
// routes so handlers (and audit enrichment) can read the resolved
// *Tenant + *Domain via TenantFromHandlerContext. A nil store is
// a no-op so callers may pass the result of a disabled-by-config
// factory unconditionally.
func WithTenantStore(s tenant.Store) Option {
	return func(srv *Server) { srv.tenantStore = s }
}

// WithTenantMiddlewareOptions tunes how the tenant middleware
// extracts the request hostname and bounds the lookup. Optional
// — defaults are XFH first-hop → r.Host (port stripped),
// 100ms timeout, suspended tenants resolve to "no tenant" so
// handlers naturally degrade. Pass a custom HostExtractor when
// the deployment doesn't trust X-Forwarded-Host.
func WithTenantMiddlewareOptions(opts TenantMiddlewareOptions) Option {
	return func(s *Server) { s.tenantMiddlewareOpts = opts }
}

// WithRiskScorer plugs in a fraud / abuse evaluator that runs on every
// /auth/login attempt after credential validation but before token
// issuance. See [spi.RiskScorer] for the contract — fail-open on scorer
// errors, default [spi.DecisionAllow] when this option is not set.
func WithRiskScorer(r spi.RiskScorer) Option {
	return func(s *Server) { s.riskScorer = r }
}

// WithMFAProvider activates MFA orchestration: when the spi.RiskScorer
// returns [spi.DecisionRequireMFA] AND this option is set, /auth/login
// returns a pending mfa_required response (challenge ID + supported
// methods) instead of tokens. The client follows up with POST
// /auth/mfa carrying the challenge ID + factor proof. Without this
// option, RequireMFA decays to Allow — preserving the historical
// no-op behavior for callers wiring a scorer that may emit RequireMFA
// in advance of MFA orchestration shipping.
//
// Requires [WithMFAChallengeStore] (or sso panics at handler entry
// the first time a challenge would be issued — fail-loud, since a
// silent fallthrough to Allow would defeat the security control the
// scorer asked for).
func WithMFAProvider(p spi.MFAProvider) Option {
	return func(s *Server) { s.mfaProvider = p }
}

// WithAnomalyRunner wires an [anomaly.Runner] — the worker pool
// that fans LoginEvents (success + failure) out to registered
// [anomaly.Detector]s off the request hot path. The runner runs
// AFTER the login response is built; detectors surface anomalies
// via the configured [anomaly.Sink] (audit + optional webhook),
// NEVER back into the login decision.
//
// nil runner → no-op dispatch (zero overhead). Pre-call
// runner.Start() before passing here so workers are alive when the
// first event arrives.
func WithAnomalyRunner(r *anomaly.Runner) Option {
	return func(s *Server) { s.anomalyRunner = r }
}

// WithMFAChallengeStore persists in-flight MFA challenges (the state
// between /auth/login returning mfa_required and /auth/mfa completing
// the factor). ttl controls how long a challenge stays redeemable;
// pass 0 to inherit [spi.DefaultMFAChallengeTTL].
//
// Backends: [defaultimpl.MemoryMFAChallengeStore] for single-replica
// deploys, the SQLite peer for cluster-shared state. Required when
// [WithMFAProvider] is set.
func WithMFAChallengeStore(store spi.MFAChallengeStore, ttl time.Duration) Option {
	return func(s *Server) {
		s.mfaChallengeStore = store
		if ttl > 0 {
			s.mfaChallengeTTL = ttl
		}
	}
}

// WithMetrics enables Prometheus instrumentation on the HTTP layer +
// login / token / risk-scoring counters. The Server's Handler() will
// also expose /metrics for scraping the supplied registry. Omit the
// option for zero overhead (no middleware, no counters).
func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Server) { s.metrics = m }
}

// ReadyCheck reports whether a dependency / subsystem is ready to
// serve traffic. Implementations return nil when healthy, an error
// describing the problem when not. Run from /readyz on every probe.
type ReadyCheck func(ctx context.Context) error

type namedReadyCheck struct {
	Name    string
	Check   ReadyCheck
	Timeout time.Duration // 0 → use the aggregate deadline
}

// WithReadyCheck adds a named check to /readyz. Any check returning
// an error marks the server unready (503). Multiple checks aggregate.
// Empty check list = always ready (default).
//
// Example: ping the database, verify etcd reachable, confirm bootstrap
// completed. Cheap checks only — the readiness probe fires every few
// seconds in Kubernetes. The aggregate /readyz handler bounds every
// check by 3 seconds; per-check overrides go through
// [WithReadyCheckTimeout].
func WithReadyCheck(name string, check ReadyCheck) Option {
	return func(s *Server) {
		if check == nil || name == "" {
			return
		}
		// Merge into a pre-registered timeout placeholder when one
		// exists for this name — let operators wire the timeout
		// option BEFORE the check option in any order.
		for i := range s.readyChecks {
			if s.readyChecks[i].Name == name && s.readyChecks[i].Check == nil {
				s.readyChecks[i].Check = check
				return
			}
		}
		s.readyChecks = append(s.readyChecks, namedReadyCheck{Name: name, Check: check})
	}
}

// WithReadyCheckTimeout registers a per-check timeout that overrides
// the aggregate 3-second /readyz deadline. Useful for slow backends
// (etcd cross-region, large SQLite WAL recovery) where the global
// bound is too tight, while keeping fast checks (memory pings)
// snappy. Timeout MUST be > 0; non-positive values silently fall
// back to the aggregate deadline.
//
// Calling this for a check already registered via WithReadyCheck
// updates that check's timeout; otherwise it pre-registers the
// timeout for a check added later in the option chain.
func WithReadyCheckTimeout(name string, timeout time.Duration) Option {
	return func(s *Server) {
		if name == "" || timeout <= 0 {
			return
		}
		// If the check is already registered, update in place.
		for i := range s.readyChecks {
			if s.readyChecks[i].Name == name {
				s.readyChecks[i].Timeout = timeout
				return
			}
		}
		// Pre-register: store the timeout against a nil Check; the
		// later WithReadyCheck call will populate Check + leave the
		// Timeout the pre-registered value.
		s.readyChecks = append(s.readyChecks, namedReadyCheck{Name: name, Timeout: timeout})
	}
}

// WithCORS installs a CORS middleware sitting between bodyLimit and
// the router, so preflight 204s short-circuit before routing but
// still get counted in metrics + traced + rate-limited. Composes
// with [ratelimit.Middleware] / [metrics.Middleware] / [tracing] —
// each handles its own concern.
//
// Empty AllowedOrigins disables CORS (zero overhead). Use the
// modern [cors] package shape rather than the legacy router-level
// [CORS] MiddlewareFunc when you want credentials / exposed headers
// / preflight caching.
func WithCORS(policy cors.Policy) Option {
	return func(s *Server) { s.corsPolicy = &policy }
}

// WithTracing wraps every request in an OpenTelemetry HTTP span,
// honoring incoming W3C traceparent headers as the parent. operation
// is the root span name (defaults to "sso-server" when empty).
//
// Calling this option DOES NOT initialize the OTLP exporter — that's
// a separate call to [tracing.Init] (typically in cmd/sso-server/main.go
// at startup). The middleware uses the global TracerProvider, so a
// no-op provider (the SDK default when Init isn't called or its
// endpoint is unset) means zero overhead beyond the otelhttp wrap
// itself.
//
// /metrics, /livez, and /readyz are served OUTSIDE this middleware
// (alongside the metrics + rate-limit middlewares) so scrape /probe
// traffic doesn't fill traces with noise.
func WithTracing(operation string) Option {
	return func(s *Server) {
		if operation == "" {
			operation = "sso-server"
		}
		s.tracingOperation = operation
	}
}

// WithBodyLimit caps request body size at max bytes. Larger requests
// are rejected with 413 + ErrPayloadTooLarge before the handler runs.
// 0 (default) disables the limit. Typical value: 1 << 20 (1 MiB) —
// generous for any auth-flow payload but blocks gigabyte-class DoS.
//
// Defends against two failure modes the SSO server otherwise has no
// protection from: pathological JSON bombs that swallow process
// memory, and slow-loris reads where an attacker dribbles bytes
// forever.
//
// For endpoints that need a different cap (e.g. /par accepts JAR
// JWTs that legitimately exceed the global default), combine with
// WithBodyLimitForPath.
func WithBodyLimit(maxBytes int64) Option {
	return func(s *Server) { s.bodyLimit = maxBytes }
}

// WithBodyLimitForPath overrides the body cap for requests whose URL
// path matches the given prefix. Useful for /par (accepts a signed
// JAR JWT — encrypted JARs especially can run 8-32 KiB while the
// rest of the SSO surface stays under 4 KiB) or /scim/v2/Bulk
// (legitimately large). Longest-matching prefix wins; falls back to
// WithBodyLimit's global value (or unlimited when neither is set).
//
// Pass max == 0 to make a specific path unlimited even while the
// global limit is in effect (escape hatch — use sparingly).
//
// May be called multiple times to register several overrides; later
// calls for the same prefix replace earlier values.
func WithBodyLimitForPath(prefix string, maxBytes int64) Option {
	return func(s *Server) {
		if s.bodyLimitByPath == nil {
			s.bodyLimitByPath = map[string]int64{}
		}
		s.bodyLimitByPath[prefix] = maxBytes
	}
}

// WithRateLimit installs the ratelimit middleware in the server's
// Handler() chain. The middleware sits BETWEEN /metrics (which is
// never rate-limited so scrapers don't get 429s) and the metrics
// recorder (so 429 responses still show up in sso_http_requests_total
// with status_class="4xx"). When the option is omitted, no rate
// limiting is enforced.
//
// Common policy shape (10 logins/min/IP, 60 req/min/IP otherwise):
//
//	sso.WithRateLimit(ratelimit.Policy{
//	    Default: ratelimit.NewMemoryLimiter(1, 60),       // ~60/min, burst 60
//	    Prefixes: []ratelimit.PrefixRule{
//	        {Prefix: "/auth/login",     Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
//	        {Prefix: "/auth/send-code", Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
//	    },
//	})
func WithRateLimit(p ratelimit.Policy) Option {
	return func(s *Server) { s.rateLimitPolicy = &p }
}

// RegisterAuthenticator adds an authenticator at runtime.
func (s *Server) RegisterAuthenticator(a Authenticator) {
	s.authenticators[a.Name()] = a
}

// Handle mounts an extra route on the SSO router so embedders can
// serve extension endpoints (e.g. WebAuthn ceremony begin/finish
// handlers from authenticators/webauthn) from the same listener +
// middleware stack the built-in SSO endpoints use. Must be called
// after Mount or Handler — the router has to exist.
//
// method is one of GET/POST/PUT/DELETE (case-insensitive). Unknown
// methods return an error rather than silently routing.
func (s *Server) Handle(method, path string, handler http.HandlerFunc) error {
	if s.router == nil {
		return fmt.Errorf("sso: Mount() must be called before Handle()")
	}
	wrap := func(ctx HandlerContext) { handler(ctx.ResponseWriter(), ctx.Request()) }
	switch strings.ToUpper(method) {
	case http.MethodGet:
		s.router.GET(path, wrap)
	case http.MethodPost:
		s.router.POST(path, wrap)
	case http.MethodPut:
		s.router.PUT(path, wrap)
	case http.MethodDelete:
		s.router.DELETE(path, wrap)
	default:
		return fmt.Errorf("sso: unsupported method %q", method)
	}
	return nil
}

// Mount registers all SSO endpoints on the router.
func (s *Server) Mount() {
	if s.router == nil {
		s.router = NewStdRouter()
	}
	if s.requestIDMW {
		s.router.Use(TracingMiddleware())
	}
	if s.tenantStore != nil {
		// Tenant resolves before geo so the audit enrichment
		// pipeline sees both — geo enrichment doesn't need
		// tenant, but tenant enrichment doesn't need geo either,
		// and putting tenant first matches the conceptual
		// "which tenant am I serving" → "where is the user
		// coming from" reading order.
		s.router.Use(TenantMiddleware(s.tenantStore, s.tenantMiddlewareOpts))
	}
	if s.geoProvider != nil {
		s.router.Use(GeoMiddleware(s.geoProvider, s.geoMiddlewareOpts))
	}

	s.router.GET(PathHealth, s.handleHealth)
	s.router.GET(PathJWKS, s.handleJWKS)
	s.router.GET(PathOIDCDiscovery, s.handleOIDCDiscovery)
	s.router.POST(PathLogin, s.handleLogin)
	s.router.POST(PathMFAComplete, s.handleMFAComplete)
	s.router.POST(PathSendCode, s.handleSendCode)
	s.router.GET(PathCallback, s.handleCallback)
	s.router.POST(PathToken, s.handleToken)
	s.router.POST(PathIntrospect, s.handleIntrospect)
	s.router.POST(PathRevoke, s.handleRevoke)
	s.router.POST(PathRevokeAll, s.handleRevokeAll)
	s.router.POST(PathDeviceCode, s.handleDeviceCode)
	s.router.POST(PathDeviceVerify, s.handleDeviceVerify)
	s.router.POST(PathPAR, s.handlePAR)
	s.router.POST(oauth.PathRegister, s.handleRegister)
	s.router.GET(oauth.PathRegisterByID, s.handleRegistrationGet)
	s.router.PUT(oauth.PathRegisterByID, s.handleRegistrationPut)
	s.router.DELETE(oauth.PathRegisterByID, s.handleRegistrationDelete)
	s.router.GET(PathUserInfo, s.handleUserInfo)
	s.router.POST(PathLogout, s.handleLogout)
	s.router.GET(PathEndSession, s.handleEndSession)
	s.router.GET(PathMyPermissions, s.handleMyPermissions)
	s.router.GET(PathMyMenus, s.handleMyMenus)
	s.router.GET(PathMyRoles, s.handleMyRoles)

	api := s.router.Group(PathAPIPrefix)
	api.GET(PathClientByID, s.handleGetClient)
	if s.auditAPI && s.auditor != nil {
		api.GET(PathAuditEvents, s.handleAuditEvents)
		api.GET(PathAuditEventByID, s.handleAuditEventByID)
	}
	if s.netAPI && s.netStore != nil {
		api.GET(PathNetPolicies, s.handleListNetPolicies)
		api.GET(PathNetPolicyByName, s.handleGetNetPolicy)
		api.POST(PathNetPolicies, s.handleApplyNetPolicy)
		api.DELETE(PathNetPolicyByName, s.handleDeleteNetPolicy)
		api.GET(PathNetPolicyClassify, s.handleClassifyNetPolicy)
		api.GET(PathNetPolicyResolveMe, s.handleResolveMeNetPolicy)
	}
}

// Handler returns the http.Handler for the server.
//
// Middleware wiring (outermost → innermost):
//
//	metrics      record count + duration on every request (incl 429s)
//	  ratelimit    reject brute-force traffic before hitting the router
//	    bodylimit    cap request size before allocating buffers
//	      router       the SSO handler stack registered by Mount()
//
// Operational endpoints served OUTSIDE the entire middleware stack
// (never rate-limited, never counted in HTTP metrics, never body-
// capped):
//
//	/livez     process is alive — always 200 when the handler runs
//	/readyz    composite readiness — aggregates [WithReadyCheck]
//	/metrics   Prometheus scrape (when [WithMetrics] is set)
//
// Kubelet probes MUST hit /livez and /readyz, not /health. The
// /health route stays registered inside the router for backward
// compatibility but goes through middleware (including rate limiting),
// which is the wrong shape for cluster probes.
//
// Omitting all four optional middlewares + checks returns the bare
// router behind the mux — zero overhead inside, mux only routes
// /livez, /readyz, and `/` (so the mux cost is negligible).
func (s *Server) Handler() http.Handler {
	s.Mount()

	var inner http.Handler = s.router
	if s.corsPolicy != nil {
		// CORS sits innermost (just outside the router) so preflight
		// 204s don't traverse routing, but still get counted by metrics
		// and rate-limited like any other request — defensive against
		// preflight floods.
		inner = cors.Middleware(*s.corsPolicy)(inner)
	}
	if s.bodyLimit > 0 || len(s.bodyLimitByPath) > 0 {
		inner = bodyLimitMiddleware(s.bodyLimit, s.bodyLimitByPath)(inner)
	}
	if s.rateLimitPolicy != nil {
		inner = ratelimit.Middleware(*s.rateLimitPolicy)(inner)
	}
	if s.metrics != nil {
		inner = metrics.Middleware(s.metrics)(inner)
	}
	if s.tracingOperation != "" {
		// Tracing wraps outermost so the span covers the full request
		// lifecycle including time spent in metrics / ratelimit /
		// bodyLimit middlewares — useful when debugging "where did the
		// 200ms go" on a slow request.
		inner = tracing.Middleware(s.tracingOperation)(inner)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(PathLivez, s.handleLivez)
	mux.HandleFunc(PathReadyz, s.handleReadyz)
	if s.metrics != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}))
	}
	mux.Handle("/", inner)
	return mux
}

// handleLivez returns 200 unconditionally — the handler running at
// all is itself the liveness signal. Cheap; no allocations beyond
// the response.
func (s *Server) handleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"alive"}`))
}

// handleReadyz runs every registered [ReadyCheck] in parallel,
// aggregates results into `{name: "ok" | err.Error()}`, returns 200
// when all pass / 503 when any fail. Bounded by a 3-second context
// deadline so a hung check can't wedge the probe.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	aggregateCtx, cancelAgg := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancelAgg()

	results := make(map[string]string, len(s.readyChecks))
	allOK := true
	for _, c := range s.readyChecks {
		// Skip orphan timeout entries (WithReadyCheckTimeout
		// registered before any WithReadyCheck for that name) so
		// they don't surface as "ok" results — they're metadata, not
		// checks.
		if c.Check == nil {
			continue
		}
		ctx := aggregateCtx
		// Per-check timeout overrides the aggregate when set + smaller
		// (operators wiring 1s for a fast check). If the per-check
		// timeout is LARGER than what the aggregate has left, the
		// parent ctx still wins — no check can outlive /readyz's hard
		// upper bound (operators wanting longer probes raise the
		// kubelet-side timeoutSeconds).
		if c.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(aggregateCtx, c.Timeout)
			//nolint:gocritic // cancel called below in tight loop; declaring outside the loop wouldn't compose cleanly
			defer cancel()
		}
		if err := c.Check(ctx); err != nil {
			results[c.Name] = err.Error()
			allOK = false
		} else {
			results[c.Name] = "ok"
		}
	}

	status := "ready"
	code := http.StatusOK
	if !allOK {
		status = "unready"
		code = http.StatusServiceUnavailable
	}

	body, _ := json.Marshal(map[string]any{
		"status": status,
		"checks": results,
	})
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// bodyLimitMiddleware wraps r.Body with MaxBytesReader and pre-checks
// Content-Length when set so over-sized requests fail before allocating
// any buffers. Chunked requests fall back to MaxBytesReader's
// streaming guard.
//
// `byPath` overrides the global default per URL prefix (longest match
// wins). An override of 0 means "unlimited for this path" — escape
// hatch for endpoints that legitimately accept large bodies even
// while the global cap is in effect.
func bodyLimitMiddleware(defaultMax int64, byPath map[string]int64) func(http.Handler) http.Handler {
	// Pre-sort the override prefixes by descending length so the
	// hot path picks the longest match without re-sorting per
	// request.
	type prefixCap struct {
		prefix string
		max    int64
	}
	prefixes := make([]prefixCap, 0, len(byPath))
	for p, m := range byPath {
		prefixes = append(prefixes, prefixCap{prefix: p, max: m})
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i].prefix) > len(prefixes[j].prefix)
	})

	resolveMax := func(path string) int64 {
		for _, pc := range prefixes {
			if strings.HasPrefix(path, pc.prefix) {
				return pc.max
			}
		}
		return defaultMax
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			max := resolveMax(r.URL.Path)
			if max <= 0 {
				// Unlimited — either no global cap and no override,
				// or an explicit "0" override (escape hatch).
				next.ServeHTTP(w, r)
				return
			}
			if r.ContentLength > max {
				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write([]byte(`{"error":"` + ErrPayloadTooLarge + `"}`))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) getAuthenticator(name string) (Authenticator, error) {
	a, ok := s.authenticators[name]
	if !ok {
		return nil, fmt.Errorf("authenticator %q not registered", name)
	}
	return a, nil
}

// issuerForClient returns the TokenIssuer that should mint tokens for the
// given client. Resolution order: client.TokenStrategy → server default →
// (if exactly one issuer is registered) that one.
func (s *Server) issuerForClient(c *Client) (string, TokenIssuer, error) {
	name := ""
	if c != nil && c.TokenStrategy != "" {
		name = c.TokenStrategy
	} else if s.defaultTokenStrategy != "" {
		name = s.defaultTokenStrategy
	} else if len(s.tokenIssuers) == 1 {
		for n := range s.tokenIssuers {
			name = n
		}
	}
	if name == "" {
		return "", nil, fmt.Errorf("no token strategy resolvable for client")
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		return name, nil, fmt.Errorf("token strategy %q not registered", name)
	}
	return name, ti, nil
}

// ValidateToken is the public face of validateAnyToken — returns just the
// claims for callers (e.g. the admin middleware) that don't care which
// issuer accepted the token.
func (s *Server) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	claims, _, err := s.validateAnyToken(ctx, token)
	return claims, err
}

// validateAnyToken tries each registered issuer until one accepts the token.
// Returned issuerName lets callers correlate revocations or audit logs.
func (s *Server) validateAnyToken(ctx context.Context, token string) (*TokenClaims, string, error) {
	var lastErr error
	for name, ti := range s.tokenIssuers {
		// Skip issuers that explicitly opt out of this token's shape.
		// Saves an expensive base64 + signature attempt when a session
		// token reaches the JWT issuer or vice versa. Issuers without
		// a TokenFormatHinter are always tried (legacy behavior).
		if h, ok := ti.(TokenFormatHinter); ok && !h.AcceptsTokenFormat(token) {
			continue
		}
		claims, err := ti.Validate(ctx, token)
		if err == nil {
			// Post-validation tenant suspension gate.
			// No-op when WithTenantSuspensionCheck wasn't passed; otherwise
			// hard-fails tokens whose owning client belongs to a now-
			// suspended tenant so an admin's Suspended flip cuts off
			// already-issued bearers, not just future issuance.
			if tsErr := s.checkTenantNotSuspended(ctx, claims); tsErr != nil {
				return nil, "", tsErr
			}
			return claims, name, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no token issuers registered")
	}
	return nil, "", lastErr
}

// revokeAcrossIssuers asks every registered issuer to revoke the token.
// Revoke is expected to be tolerant of unknown tokens (the issuer that
// doesn't own the token returns ErrNoSuchToken or similar — that's a
// no-op, not a failure). Returns:
//
//   - revoked: names of issuers whose Revoke returned nil.
//   - failed: names of issuers whose Revoke returned a non-nil, non-
//     "unknown token" error — these are the ones where the bearer
//     may still work and the caller should audit
//     `partial_revoke_failure`.
//
// The split lets the caller distinguish "no issuer owned this token"
// (revoked empty, failed empty — benign) from "an issuer that DOES
// own this token failed to revoke" (revoked empty, failed non-empty
// — bug or infra issue that violates the logout-everywhere promise).
func (s *Server) revokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string) {
	for name, ti := range s.tokenIssuers {
		// Honor the same shape-skip the validate path uses. An
		// issuer whose TokenFormatHinter rejects the inbound token
		// can't possibly own it, so asking it to Revoke would either
		// (a) return a not-found error we ignore anyway, or (b)
		// return an infra error we'd misclassify as a partial
		// revoke failure. Skip cleanly.
		if h, ok := ti.(TokenFormatHinter); ok && !h.AcceptsTokenFormat(token) {
			continue
		}
		switch err := ti.Revoke(ctx, token); {
		case err == nil:
			revoked = append(revoked, name)
		case isUnknownTokenErr(err):
			// Issuer didn't own this token — expected when callers
			// sweep across N issuers. Not a failure.
		default:
			failed = append(failed, name)
		}
	}
	return revoked, failed
}

// isUnknownTokenErr heuristically classifies an issuer's Revoke
// error. The error surface across issuers is loose (each impl
// returns its own sentinel — Ed25519 issuer returns nil for
// stateless tokens; SessionTokenIssuer returns "session_issuer:
// token not found"). Treat the standard "not found" / "unknown"
// shapes as no-op; everything else is infra failure worth auditing.
// When an issuer adopts a typed sentinel (e.g. ErrUnknownToken), add
// it here.
func isUnknownTokenErr(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	for _, needle := range []string{"not found", "unknown", "no such"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func (s *Server) requireDeps(deps ...string) error {
	for _, d := range deps {
		switch d {
		case depTokenIssuer:
			if len(s.tokenIssuers) == 0 {
				return fmt.Errorf("at least one TokenIssuer is required")
			}
		case depUserProvider:
			if s.userProvider == nil {
				return fmt.Errorf("UserProvider is required")
			}
		case depClientStore:
			if s.clientStore == nil {
				return fmt.Errorf("ClientStore is required")
			}
		case depSessionMgr:
			if s.sessionMgr == nil {
				return fmt.Errorf("SessionManager is required")
			}
		}
	}
	return nil
}
