package sso

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/metering"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

const PathOIDCDiscovery = "/.well-known/openid-configuration"

// mountDiscovery registers the OIDC Discovery 1.0 endpoint plus its RFC 8414
// §3 alias. One handler serves both paths: the discovery document already
// carries every RFC 8414 field, and sharing the handler means both routes
// share the base-URL-keyed body cache, so responses are byte-identical.
// Extracted from mountCoreOAuthOIDC, which sits exactly at the 50-line
// function budget — the alias could not be added there.
func (s *Server) mountDiscovery() {
	s.router.GET(PathOIDCDiscovery, s.handleOIDCDiscovery)
	s.router.GET(PathOAuthAuthorizationServerMetadata, s.handleOIDCDiscovery)
}

// defaultJWKSCacheTTL is the freshness window for the JWKS body cache.
// 5 seconds balances key-rotation responsiveness against avoiding
// per-request recomputation. When 0, the cache is disabled entirely
// (legacy behavior).
const defaultJWKSCacheTTL = 5 * time.Second

// oidc.ProviderMetadata mirrors OpenID Connect Discovery 1.0 §3 +
// RFC 8414 §2 fields. Optional fields are omitempty so the wire stays
// minimal — relying parties branch on presence per the spec.

// JWK + JWKSProvider + PathJWKS + DefaultJWKSCacheMaxAge moved to core/jwks.go
// (data type / interface / wire constants).

// handleSilentRenewal implements OIDC Core §3.1.2.1's prompt=none flow.
// The RP loads /auth/login in a hidden iframe with prompt=none +
// id_token_hint to probe whether the End-User still has an active
// session — when yes, a freshly minted access (and id) token returns
// without any UI; when no, error login_required tells the iframe to
// fall back to the visible login flow.
//
// Spec checkpoints satisfied here:
//
//   - §3.1.2.1: prompt=none MUST NOT be combined with other prompt
//     values (caller validated this).
//   - §3.1.2.6: missing or unverifiable id_token_hint → login_required.
//   - §3.1.2.6: no active End-User session → login_required.
//   - §3.1.2.6: hint subject doesn't match the live session → login_required.
//   - The new ID token's `auth_time` MUST equal the original — no fresh
//     authentication event happened, so the factor freshness signal
//     downstream services see is preserved (RFC 9068 §2.2).
//
// Returns true when the silent flow handled the response (caller MUST
// bail). False on a non-prompt-none request (caller continues).
// handleSilentRenewal delegates to oidc.HandleSilentRenewal — see
// that file for the OIDC Core §3.1.2.1 prompt=none flow.
func (s *Server) handleSilentRenewal(ctx HandlerContext, prompts []string, req oidc.SilentRenewalRequest, client *Client) bool {
	return oidc.HandleSilentRenewal(s, ctx, prompts, req, client)
}

// defaultDiscoveryCacheTTL is the freshness window for client-store-
// derived discovery fields. 5 seconds is short enough that DCR /
// admin client edits visibly propagate (humans typically wait > 5s
// before refreshing the discovery doc) and long enough that a busy
// RP polling /.well-known/openid-configuration N times per second
// doesn't pay 5× ClientStore.List per request. When 0, the cache is
// disabled entirely (legacy behavior).
const defaultDiscoveryCacheTTL = 5 * time.Second

// clientDiscoverySnapshot memoizes the discovery-doc fields that
// derive from iterating the entire client store. Computing them
// requires one ClientStore.List + a pass per derivation; without
// caching, every /.well-known/openid-configuration hit pays 5×
// List + 5× iteration. With caching, the cost amortizes across the
// TTL window.
//
// IMPORTANT: every field here MUST be safe to read concurrently
// after the snapshot is published via atomic.Pointer. We copy slices
// at compute-time so downstream readers can't mutate the snapshot
// in place.
//
// fpValid/fpCount/fpHash carry the cheap client-set fingerprint
// (core.ClientStoreStats) captured when this snapshot's derived fields
// were last computed from a full List. On a would-be cache miss the
// refresh path re-reads the fingerprint and, when it still matches,
// reuses the derived fields verbatim instead of re-Listing every
// client — see discoverySnapshot. fpValid is false when the store
// doesn't implement ClientStoreStats or the Stats call failed, which
// forces the legacy full-List recompute.
type clientDiscoverySnapshot struct {
	requirePAR                 bool
	requireSignedRequestObject bool
	frontchannelLogout         bool
	scopes                     []string
	authorizationDetailTypes   []string
	expiresAt                  time.Time

	fpValid bool
	fpCount int
	fpHash  string
}

// WithDiscoveryCacheTTL overrides the freshness window for the
// client-store-derived discovery fields. Pass 0 to disable the
// cache (every request re-iterates the client store — useful when
// running in a hot-reload dev loop where DCR edits must reflect
// instantly). Defaults to defaultDiscoveryCacheTTL.
func (s *Server) writeDiscoveryDoc(ctx HandlerContext, entry *discoveryDocEntry) {
	oidc.WriteDoc(ctx, entry, s.discoveryDocCacheTTL)
}

// InvalidateAuthzPolicyBundleCache clears this replica's cached
// authorization policy bundle for clientID and, when an invalidation bus
// is wired, publishes a KindAuthzPolicyChange so every other replica does
// the same — closing the cross-replica window where a sidecar could pull
// a stale role-definition bundle from another node until that node's TTL
// elapses. Wire this into the admin role/menu mutation handlers (gRPC
// PermissionAdminService) via a callback so a role change converges before
// the bundle cache TTL.
//
// Safe to call unconditionally. Publish failures are logged, not
// propagated: the local invalidation already succeeded and peers fall back
// to their TTL, so a mutation must never fail because the bus is down
// (fail-open on publish, AGENTS.md §2).
func (s *Server) InvalidateAuthzPolicyBundleCache(clientID string) {
	s.invalidateAuthzPolicyBundleCacheLocal(clientID)
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindAuthzPolicyChange, Key: clientID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", clientID, "error", err)
		}
	}
}

// WithDiscoveryDocCacheTTL configures how long a rendered discovery
// document body may serve from cache. ttl <= 0 disables body caching
// (snapshot caching via [WithDiscoveryCacheTTL] continues independently).
// Default is [DefaultDiscoveryDocCacheTTL].
func WithDiscoveryDocCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.discoveryDocCacheTTL = ttl }
}

// DefaultAuthzPolicyBundleCacheTTL bounds how long a rendered
// authorization policy bundle may serve from this replica's body cache
// before it re-renders from the permissions provider. Role definitions
// change rarely and admin mutations invalidate the cache immediately
// (locally + cluster-wide via the bus), so this is just the backstop
// freshness window for a missed invalidation — set generously (minutes,
// not seconds) since a sidecar polls the bundle, not the hot request path.
const DefaultAuthzPolicyBundleCacheTTL = 5 * time.Minute

// WithAuthzPolicyBundleCacheTTL configures how long a rendered
// authorization policy bundle body may serve from cache. ttl <= 0
// disables body caching AND the response-side ETag / Cache-Control
// headers (every pull renders fresh, downstream caches told not to
// cache) — matching the discovery-doc cache contract. Default is
// [DefaultAuthzPolicyBundleCacheTTL].
func WithAuthzPolicyBundleCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.authzPolicyBundleCacheTTL = ttl }
}

// authzPolicyBundleCacheKey namespaces a cached bundle by (clientID,
// baseURL). The NUL byte can't appear in either component, so it is an
// unambiguous separator (no client_id/base-url pair can collide).
func authzPolicyBundleCacheKey(clientID, base string) string {
	return clientID + "\x00" + base
}

// lookupAuthzPolicyBundleCache returns a fresh cached entry for the
// (clientID, base) pair, or nil to signal "render fresh". Mirrors
// lookupDiscoveryDocCache: lock-free read, stale entries are dropped.
func (s *Server) lookupAuthzPolicyBundleCache(clientID, base string) *discoveryDocEntry {
	v, ok := s.authzPolicyBundleCache.Load(authzPolicyBundleCacheKey(clientID, base))
	if !ok {
		return nil
	}
	entry, _ := v.(*discoveryDocEntry)
	if entry.Fresh() {
		return entry
	}
	s.authzPolicyBundleCache.Delete(authzPolicyBundleCacheKey(clientID, base))
	return nil
}

func (s *Server) storeAuthzPolicyBundleCache(clientID, base string, entry *discoveryDocEntry) {
	s.authzPolicyBundleCache.Store(authzPolicyBundleCacheKey(clientID, base), entry)
}

// invalidateAuthzPolicyBundleCacheLocal drops every cached bundle render
// for clientID across all base URLs (a multi-host deployment caches one
// entry per host). Local-only; the publishing entry point is
// InvalidateAuthzPolicyBundleCache. The key is "<clientID>\x00<base>", so
// a prefix match on "<clientID>\x00" scopes the sweep to one client.
func (s *Server) invalidateAuthzPolicyBundleCacheLocal(clientID string) {
	prefix := clientID + "\x00"
	s.authzPolicyBundleCache.Range(func(k, _ any) bool {
		if ks, ok := k.(string); ok && strings.HasPrefix(ks, prefix) {
			s.authzPolicyBundleCache.Delete(k)
		}
		return true
	})
}

//
//   1. resolveIssuer + authzErrorBody* — RFC 9207 issuer-identification
//      stamping on every authorization-endpoint response.
//   2. renderFormPostResponse + helpers — OIDC Form Post Response Mode 1.0
//      auto-submit HTML for response_mode=form_post.
//   3. maybeSignUserInfo — OIDC userinfo signed-response (JWT) path.
//
// All three live on *Server because they reach into Server fields
// (issuer, idTokenIssuer, clientStore, logger).

// -----------------------------------------------------------------------------
// RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification.
//
// Defense against mix-up attacks: when a client is configured with
// multiple authorization servers, an attacker can attempt to trick the
// client into accepting an authorization response from one AS as if it
// came from another. Including the AS issuer identifier in every
// authorization response lets the client verify "this code/token came
// from the AS I expected" before redeeming the code at the token
// endpoint.
//
// RFC 9207 §2 is written for redirect-based responses (`?iss=...`
// query param on the redirect to the RP). This server's /auth/login is
// a BFF-shaped JSON endpoint rather than a 302-redirect endpoint; the
// adaptation is to include `iss` in the JSON response body alongside
// `code` / `state` / `error`. A client that builds the redirect URI
// on the SPA side can propagate the value into `iss=...` as the spec
// intends.

// resolveIssuer returns the issuer identifier this server stamps in
// authorization responses. Matches the value advertised in the OIDC
// discovery document: operator-configured `WithIssuer` value when set
// and not the default sentinel; otherwise the request's base URL.
//
// Critical invariant: the value returned here MUST equal
// `oidc.ProviderMetadata.Issuer` for the same request — RFC 9207 §2
// requires the `iss` parameter to be the same identifier the AS
// publishes via discovery, so a client comparing them detects mix-up.
func (s *Server) resolveIssuer(ctx HandlerContext) string {
	if s.issuer != "" && s.issuer != DefaultIssuer {
		return s.issuer
	}
	return requestBaseURL(ctx.Request())
}

// authzErrorBody returns the standard error envelope for an
// authorization endpoint response with `iss` stamped per RFC 9207 §2,
// plus trace_id (core.TraceIDFromContext) when the Tracing middleware
// populated one — omitted entirely otherwise, so this stays a strict
// superset of the pre-trace-id envelope. Use this in handleLogin (and
// any future authorization endpoint) — NOT in token / userinfo /
// callback handlers, which are not authorization responses.
func (s *Server) authzErrorBody(ctx HandlerContext, code string) map[string]string {
	m := map[string]string{
		KeyError: code,
		KeyIss:   s.resolveIssuer(ctx),
	}
	if traceID := core.TraceIDFromContext(ctx.Request().Context()); traceID != "" {
		m[core.KeyTraceID] = traceID
	}
	s.localizeErrorBody(ctx, m, code)
	return m
}

// authzErrorBodyDesc is authzErrorBody plus an error_description.
func (s *Server) authzErrorBodyDesc(ctx HandlerContext, code, desc string) map[string]string {
	m := s.authzErrorBody(ctx, code)
	m[KeyErrorDescription] = desc
	return m
}

// authzErrorBodyWithState returns the standard authorization error envelope
// with `iss` per RFC 9207 §2 AND `state` echoed back per RFC 6749 §4.1.2.1
// when non-empty. Use this in every /auth/login error path that has a
// login.Request — it ensures the client's CSRF state token is returned both
// on success AND on error, as the spec requires. Fall back to authzErrorBody
// when no login request is in scope (e.g. MFA-only handlers).
func (s *Server) authzErrorBodyWithState(ctx HandlerContext, code string, state string) map[string]string {
	m := s.authzErrorBody(ctx, code)
	if state != "" {
		m[KeyState] = state
	}
	return m
}

// -----------------------------------------------------------------------------
// OpenID Connect Form Post Response Mode 1.0.
//
// The RP requests `response_mode=form_post` when it wants the
// authorization response delivered as an HTML auto-submitted POST
// to its redirect_uri, rather than the default query-string redirect.
// Useful for RPs that handle POST bodies more naturally than parsing
// fragment / query parameters, and for delivering longer responses
// (id_token, etc.) without URL-length limits.
//
// Spec: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
//
// This implementation:
//   - Renders a minimal HTML document with a hidden form whose body
//     POSTs {code, state, iss} to redirect_uri.
//   - Auto-submits via a body onload handler — operators using strict
//     CSP that blocks inline event handlers should serve this
//     endpoint outside their CSP middleware OR allowlist a 'self'
//     script-src for /auth/login.
//   - Provides a manual submit button inside <noscript> so RPs that
//     disable JS still see a fallback (the user clicks once).
//   - All response values pass through html/template's
//     auto-escaping (URL context for action=, attribute context for
//     value=), so an attacker can't break out of the form fields.
//   - Hardens response headers: X-Frame-Options: DENY (clickjacking)
//     + Cache-Control: no-store + Referrer-Policy: no-referrer
//     (don't leak the AS's URL to the RP via Referer; the auth
//     response itself is what the RP needs).

// ResponseModeFormPost is the OIDC Form Post Response Mode 1.0
// magic string for the `response_mode` parameter.
const ResponseModeFormPost = "form_post"

// ResponseModeQuery is the default response_mode for response_type=code
// per OIDC Core §3.1.2.5: parameters appended to the redirect_uri's
// query string.
const ResponseModeQuery = "query"

// ResponseModeFragment is the default response_mode for token-bearing
// response types (implicit flow). Parameters delivered after `#`.
const ResponseModeFragment = "fragment"

// renderFormPostResponse delegates to oidc.RenderFormPostResponse —
// the template + escaping contract lives there.
func (s *Server) renderFormPostResponse(ctx HandlerContext, redirectURI, code, state string) {
	oidc.RenderFormPostResponse(ctx, redirectURI, code, state, s.resolveIssuer(ctx))
}

// isValidResponseMode reports whether mode is acceptable on this
// server. The plain modes (query / fragment / form_post) are always
// valid; the JARM modes (jwt / query.jwt / fragment.jwt /
// form_post.jwt) are valid only when a JARM signer is wired — without
// one they fail closed (invalid_request) rather than silently
// degrading to an unsigned response.
func (s *Server) isValidResponseMode(mode string) bool {
	if oidc.IsValidResponseMode(mode) {
		return true
	}
	return s.jarmSigner != nil && oidc.IsJARMResponseMode(mode)
}

// maybeSignUserInfo delegates to oidc.MaybeSignUserInfo — see that
// function for the EdDSA-only + UserinfoSigner type-assert gate.
func (s *Server) maybeSignUserInfo(ctx HandlerContext, clientID string, body map[string]any) bool {
	return oidc.MaybeSignUserInfo(s, ctx, clientID, body)
}

// Permission handlers (delegators — bodies in permissions/handlers.go).
func (s *Server) handleMyPermissions(ctx HandlerContext) { permissions.HandleMyPermissions(s, ctx) }
func (s *Server) handleMyRoles(ctx HandlerContext)       { permissions.HandleMyRoles(s, ctx) }
func (s *Server) handleMyMenus(ctx HandlerContext)       { permissions.HandleMyMenus(s, ctx) }

func (s *Server) resolvePermissionsForLogin(ctx context.Context, userID, clientID string) ([]permissions.Role, []permissions.Permission, permissions.MenuTree) {
	return permissions.ResolveForLogin(s.permissions, s.logger, ctx, userID, clientID)
}

// AuthenticatedSubject exposes authenticatedSubject for handlers/ subpackages
// (Deps interface needs it as an exported method).
func (s *Server) AuthenticatedSubject(ctx HandlerContext) (userID, clientID string, ok bool) {
	return s.authenticatedSubject(ctx)
}

// Audit handlers (delegators — bodies in audit/handlers.go).
func (s *Server) handleAuditEvents(ctx HandlerContext)    { audit.HandleEvents(s, ctx) }
func (s *Server) handleAuditEventByID(ctx HandlerContext) { audit.HandleEventByID(s, ctx) }
func (s *Server) handleAuditFacets(ctx HandlerContext)    { audit.HandleFacets(s, ctx) }

// JWKS handler (delegator — body in oidc/handlers.go).
func (s *Server) handleJWKS(ctx HandlerContext) { oidc.HandleJWKS(s, ctx) }

// parseUsageWindow parses the period/start query parameters shared by the
// usage/metering admin endpoints. On malformed input it writes the 400
// itself and returns ok=false.
func (s *Server) parseUsageWindow(ctx HandlerContext) (metering.UsagePeriod, time.Time, bool) {
	period := metering.UsagePeriod(ctx.Query("period"))
	if period == "" {
		period = metering.PeriodDay
	}
	if period != metering.PeriodDay && period != metering.PeriodMonth {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, core.ErrInvalidRequest))
		return "", time.Time{}, false
	}
	startStr := ctx.Query("start")
	if startStr == "" {
		return period, time.Now().UTC(), true
	}
	start, err := time.ParseInLocation("2006-01-02", startStr, time.UTC)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, core.ErrInvalidRequest))
		return "", time.Time{}, false
	}
	return period, start, true
}

// handleTenantUsage serves GET /api/v1/admin/tenants/:id/usage.
// Admin-gated (admin:read) by the /api/v1/admin/ prefix.
//
// Query parameters:
//
//	period=day|month   (default: day)
//	start=YYYY-MM-DD   (default: today UTC)
func (s *Server) handleTenantUsage(ctx HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, core.ErrInvalidRequest))
		return
	}

	period, start, ok := s.parseUsageWindow(ctx)
	if !ok {
		return
	}

	u, err := s.usageAggregator.Usage(ctx.Request().Context(), tenantID, period, start)
	if err != nil {
		s.logger.Error("tenant usage aggregation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, u)
}

// handleAdminTopTenants serves GET /api/v1/admin/usage/top-tenants.
// Admin-gated (admin:read) by the /api/v1/admin/ prefix.
//
// Query parameters:
//
//	period=day|month   (default: day)
//	start=YYYY-MM-DD   (default: today UTC)
//	limit=N            (default: 10; implementations clamp the maximum)
func (s *Server) handleAdminTopTenants(ctx HandlerContext) {
	period, start, ok := s.parseUsageWindow(ctx)
	if !ok {
		return
	}
	limit := 10
	if v := ctx.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			ctx.JSON(http.StatusBadRequest, errorBody(ctx, core.ErrInvalidRequest))
			return
		}
		limit = n
	}
	tops, err := s.usageAggregator.TopTenants(ctx.Request().Context(), period, start, limit)
	if err != nil {
		s.logger.Error("top-tenants usage aggregation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, core.ErrInternal))
		return
	}
	if tops == nil {
		tops = []*metering.TenantUsage{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus: StatusOK,
		"tenants": tops,
		"total":   len(tops),
	})
}

// meSubjectOrChallenge extracts the bearer subject for /sessions/me and
// /consents/me. Unlike authenticatedSubject, it stamps the RFC 6750 §3
// WWW-Authenticate challenge header BEFORE writing the 401 body, so these
// credential-adjacent endpoints conform to the same challenge contract as
// /userinfo. Returns (userID, true) on success; (_, false) when the 401 has
// already been written.
