package sso

import (
	"github.com/snaplink/sso/protocols/fapi"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// DefaultIntrospectionCacheTTL is the default lifetime of a cached
// introspection result. 60 seconds is safe for typical access tokens
// with 5–60 minute lifetimes — the tradeoff is a short window of
// eventual consistency for revoked tokens in exchange for avoiding
// JWT signature verification on every introspection poll from a
// microservice mesh with 100+ services. The TTL must ALWAYS be
// shorter than the token's remaining lifetime; 60s satisfies that
// for any production token lifetime.
const DefaultIntrospectionCacheTTL = 60 * time.Second

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

// WithTenantTokenIssuer binds every client whose Client.TenantID equals
// tenantID to the already-registered issuer named issuerName, giving that
// tenant cryptographic isolation: its tokens are signed by that tenant's
// own signing key while sharing the one multi-issuer validation +
// aggregated-JWKS machinery.
//
// issuerName MUST also be registered via WithTokenIssuer — this option
// only routes selection at issuance; it does not register the issuer (so
// the issuer's public keys land in the aggregated JWKS exactly once, and
// validateAnyToken already tries it like any other). A token signed by a
// tenant issuer therefore validates with no further wiring: its header
// kid resolves to that issuer's verify key, and the per-issuer alg/typ
// allowlist + kid->alg gate keep alg-confusion structurally impossible
// across tenants (AGENTS.md §2).
//
// Resolution precedence at issuance (see issuerForClient): a tenant
// mapping wins over Client.TokenStrategy and the Server default. A client
// with an empty TenantID, or a TenantID without a mapping here, falls
// back to the existing strategy resolution unchanged — so the feature is
// pure backward-compat when unused.
func WithTenantTokenIssuer(tenantID, issuerName string) Option {
	return func(s *Server) {
		if s.tenantTokenStrategies == nil {
			s.tenantTokenStrategies = make(map[string]string)
		}
		s.tenantTokenStrategies[tenantID] = issuerName
	}
}

// WithSupportedSigningAlgs sets the Server-level Validate-time JWS `alg`
// allowlist. validateAnyToken parses every inbound compact-JWS bearer's
// header and rejects any token whose `alg` is not in this list BEFORE
// dispatching to any issuer — the critical anti-alg-confusion gate
// (AGENTS.md §2): the verification algorithm is dictated by the Server's
// wired signers, never selected by the relying party through the token
// header.
//
// Pass exactly the algorithms of the issuer(s) you wired, e.g.
// `WithSupportedSigningAlgs("EdDSA")` for an Ed25519-only deployment,
// `WithSupportedSigningAlgs("ES256")` for ECDSA-only, or both during a
// migration. This does NOT loosen per-issuer enforcement: each issuer
// independently rejects a token whose `alg` doesn't match the key type
// of the kid it resolves, so listing "ES256" can never make an
// EdDSA-signed token verify, and vice versa.
//
// Unset = no Server-level gate (each issuer still enforces its own
// allowlist; the multi-issuer dispatcher tries each in turn).
func WithSupportedSigningAlgs(algs ...string) Option {
	return func(s *Server) {
		s.supportedSigningAlgs = append([]string(nil), algs...)
	}
}

// WithMaxTokenBytes caps the byte length of an inbound bearer token
// validateAnyToken will attempt to parse/verify. A token longer than n is
// rejected immediately — before any base64/JSON header decode or issuer
// Validate call — with the same generic invalid_token/inactive response
// every other validation failure gets (oracle-safe: no new observable
// behavior, just an earlier exit). Defense-in-depth against a caller
// handing the server a deliberately huge "token" string to soak up parsing
// CPU ahead of the inevitable signature-verification failure.
//
// n <= 0 (default, unset) = unbounded — byte-identical to a build without
// this option.
func WithMaxTokenBytes(n int) Option {
	return func(s *Server) { s.maxTokenBytes = n }
}

// WithAuthorizationDetailsLimits bounds an RFC 9396 authorization_details
// payload's SHAPE (see oauth.RARLimits) before /auth/login and /par
// unmarshal it into typed values: maxBytes caps the raw serialized size,
// maxElements caps the top-level array's element count, maxDepth caps the
// deepest nesting level. Each argument's zero value disables that specific
// check; WithAuthorizationDetailsLimits(0, 0, 0) (or never calling this
// option) is byte-identical to a build without it — authorization_details
// stays bounded only by the generic WithBodyLimit on the whole request.
func WithAuthorizationDetailsLimits(maxBytes, maxElements, maxDepth int) Option {
	return func(s *Server) {
		s.rarLimits = oauth.RARLimits{MaxBytes: maxBytes, MaxElements: maxElements, MaxDepth: maxDepth}
	}
}

// WithMaxScopeCount caps the number of space-separated scopes accepted in a
// single request's `scope` parameter on /auth/login and /par, rejecting an
// over-cap request with the standard invalid_scope wire code. Composes
// with (does not replace) protocols/oauth's existing hardcoded MaxScopeLen
// BYTE cap — this is a token-COUNT cap, catching a request built from many
// short scope tokens that would slip under the byte ceiling.
//
// n <= 0 (default, unset) = unbounded — byte-identical to a build without
// this option.
func WithMaxScopeCount(n int) Option {
	return func(s *Server) { s.maxScopeCount = n }
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

// WithFAPIProfile enables the FAPI 2.0 Security Profile compliance
// layer in the given mode (fapi.ModeInspection or fapi.ModeEnforce;
// ModeOff / a nil validator is the default no-op).
//
// Inspection mode records every baseline violation as a
// fapi_compliance_violation audit event but lets requests proceed —
// the ramp-up path that hands operators a per-RP compliance-gap list
// without breaking traffic. Enforce mode rejects violating requests.
//
// The baseline rules (PAR-only, signed request object, S256 PKCE,
// code-only response type, sender-constrained tokens) are checked at
// /auth/login and /token against signals the server already computes;
// the underlying capabilities (PAR / JAR / DPoP / mTLS) must be wired
// for a client to actually pass enforcement.
func WithFAPIProfile(mode fapi.Mode) Option {
	return func(s *Server) {
		if mode == fapi.ModeOff {
			s.fapiValidator = nil
			return
		}
		s.fapiValidator = fapi.New(mode)
	}
}

// WithJARM enables JWT Secured Authorization Response Mode (JARM). The
// signer (an oidc.JARMSigner / oidc.MetadataSigner — the wired
// Ed25519JWTIssuer satisfies it) signs the authorization response into
// a JWT delivered as the single `response` parameter, defending the
// front-channel response against tampering and mix-up.
//
// Once wired, /auth/login accepts response_mode=jwt (and the dotted
// query.jwt / fragment.jwt / form_post.jwt variants) and discovery
// advertises the JARM response modes plus
// authorization_signing_alg_values_supported. Without a signer,
// response_mode=jwt fails closed with invalid_request.
func WithJARM(signer oidc.JARMSigner) Option {
	return func(s *Server) { s.jarmSigner = signer }
}

// WithIntrospectionSigning moved to options_grants.go, beside
// WithIntrospectionSigner (the other way to wire the same field).

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

// WithClientStoreCache opts into an OPTIONAL per-login TTL cache over the
// wired ClientStore. Every interactive login, /token grant, and
// tenant-bound request reads the client metadata via clientStore.Get; at
// high QPS with a SQLite/Redis backend that is a measurable per-request
// round-trip. This decorator caches successful Gets of EXISTING clients
// for ttl (default DefaultClientStoreCacheTTL when ttl <= 0), so the hot
// path skips the store read within the window.
//
// It is SECURITY-PRESERVING by construction (§2):
//
//   - ValidateSecret (the credential / HTTP-Basic decision) ALWAYS
//     bypasses the cache and hits the inner store — a stale cached secret
//     check is forbidden.
//   - MISSES are never cached: a just-created client is visible
//     immediately, and a deleted client reverts to the inner store's
//     unknown -> invalid_client behavior on the next Get.
//   - Returned clients are deep CLONES, so a caller mutating its result
//     can't corrupt the cached snapshot.
//   - Update/Delete/RotateSecret evict the affected entry; admin + DCR
//     mutation paths additionally call InvalidateClientCache, which evicts
//     locally AND publishes a cross-replica bus Event so peers converge
//     before their own TTL elapses.
//
// The accepted tradeoff (same as tenant.suspension_check.cache_ttl): a
// client deactivated, or whose metadata changed, mid-window keeps being
// served the prior value for at most ttl unless an explicit invalidation
// evicts it sooner.
//
// ttl <= 0 / option absent ⇒ NO wrapper is constructed (byte-identical to
// a non-caching build). Decoration happens post-options in NewServer, the
// SAME slot as the federation registration decorator, so it composes
// order-independently with WithClientStore / WithFederationAutoRegistration
// (the cache wraps the federation store, caching its on-miss derived
// clients too).
func WithClientStoreCache(ttl time.Duration) Option {
	return func(s *Server) { s.clientStoreCacheTTL = ttl }
}

// WithIntrospectionCache enables optional best-effort caching for token
// introspection results. Every /token/introspect call without caching
// does full JWT signature verification (asymmetric cryptography + claims
// validation + revocation check). In microservice mesh deployments with
// 100+ services polling this endpoint every few seconds, the CPU cost
// is significant.
//
// The cache wraps the existing handler — it does NOT replace it. On a
// CACHE HIT the result is returned immediately without any JWT signature
// verification. On a CACHE MISS the full verification runs and the result
// is stored (including negative results — {active: false} — so a flood of
// expired-token polls also skips verification).
//
// SECURITY CONSIDERATIONS:
//   - The cache key is SHA-256(token), not the raw token — an attacker who
//     dumps the cache sees only opaque digests.
//   - The cache TTL must be SHORTER than the token's remaining lifetime.
//     The 60s default is safe for typical access tokens with 5–60 minute
//     lifetimes.
//   - A revoked token might be served from cache for up to TTL seconds.
//     This is an INTENTIONAL tradeoff: revocation is not instant (eventual
//     consistency). The alternative (no cache) means every introspection
//     pays full signature verification cost.
//   - The cache is BEST-EFFORT: on store error (including a full cache),
//     verification proceeds normally (fail-open).
//
// Pass cache=nil or omit the option to disable caching entirely (every
// introspection pays full verification — byte-identical to a build without
// this feature). Pass a *handler.MemoryIntrospectionCache (from
// internal/handler) for single-replica deployments. Multi-replica
// deployments should provide a shared backend (e.g. Redis) via a custom
// oauth.IntrospectionCache implementation.
func WithIntrospectionCache(cache oauth.IntrospectionCache, ttl time.Duration) Option {
	return func(s *Server) {
		s.introspectionCache = cache
		if ttl > 0 {
			s.introspectionCacheTTL = ttl
		} else {
			s.introspectionCacheTTL = DefaultIntrospectionCacheTTL
		}
	}
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

// WithCIBA enables OpenID Connect CIBA Core 1.0 backchannel
// authentication in POLL delivery mode on POST
// /backchannel-authentication + grant_type=ciba on /token. Without it,
// /backchannel-authentication returns 501 and the CIBA grant is
// rejected as unsupported_grant_type.
//
// The flow mirrors Push MFA: the AS resolves the request's hint to a
// known user, persists a pending CIBARequest in store, and delivers
// the auth_req_id out of band via transport (typically an adapter over
// a defaultimpl.PushTransport — wrap one with
// oauth.CIBATransportFunc(pt.Send)). An operator-supplied device
// callback resolves the request via store.SetStatus(approved/denied);
// the client polls /token until it resolves.
//
// reqTTL is the auth_req_id lifetime (<=0 → oauth.DefaultCIBARequestTTL,
// 120s). interval is the minimum poll cadence enforced for slow_down
// (<=0 → oauth.DefaultCIBAPollInterval, 5s).
//
// store + transport are required; passing either nil leaves CIBA
// disabled (the handler's nil-store guard returns 501).
func WithCIBA(store oauth.CIBAStore, transport oauth.CIBATransport, reqTTL, interval time.Duration) Option {
	return func(s *Server) {
		s.cibaStore = store
		s.cibaTransport = transport
		if reqTTL > 0 {
			s.cibaRequestTTL = reqTTL
		}
		if interval > 0 {
			s.cibaPollInterval = interval
		}
	}
}

// WithCIBAPingNotifier upgrades CIBA from poll-only to ping delivery
// (CIBA Core §10.2). Requires WithCIBA. When wired, discovery advertises
// "ping" alongside "poll" in backchannel_token_delivery_modes_supported,
// a client may send client_notification_token on
// /backchannel-authentication, and ResolveBackchannelAuthRequest fires
// the notifier when a request resolves so the client knows to collect
// its tokens. The notifier is best-effort — a failed ping degrades to
// poll, never blocks resolution. nil (the default) keeps poll-only mode.
func WithCIBAPingNotifier(notifier oauth.CIBAPingNotifier) Option {
	return func(s *Server) { s.cibaPingNotifier = notifier }
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
