package sso

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/internal/handler"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/trust"
)

func (s *Server) handleLogin(ctx HandlerContext) {
	// RFC 6749 §5.1: every /auth/login response — success AND error, including
	// the pre-bind CSRF/origin gates below — MUST carry Cache-Control: no-store
	// + Pragma: no-cache. Stamped here, before ANY response can be written, so
	// the 415/403 gates below aren't a cacheable exception to the credential-
	// endpoint rule (bootstrapLoginRequest also stamps this for the post-bind
	// path; both calls are idempotent header Sets).
	tokenNoStoreHeaders(ctx)
	if s.rejectNonJSONLogin(ctx) {
		return
	}
	if s.rejectDisallowedLoginOrigin(ctx) {
		return
	}
	cancel := s.armAuthzRequestTimeout(ctx)
	defer cancel()

	req, ok := s.bootstrapLoginRequest(ctx)
	if !ok {
		return
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return
	}
	if s.runPreAuthenticateHook(ctx, &req, nil) {
		return
	}
	if s.handleLoginContinuationOrPromptNone(ctx, req) {
		return
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return
	}

	authzCtx, client, handled := s.preAuthLoginGates(ctx, &req)
	if handled {
		return
	}
	ctx = authzCtx

	result, handled := s.credentialLoginStage(ctx, &req, client)
	if handled {
		return
	}

	nextCtx := s.wrapForLoginContinuation(ctx, result, req, client, false)
	s.finishLogin(nextCtx, result, req, client)
}

func (s *Server) directMintClaims(ctx HandlerContext, result *AuthResult, score trust.TrustScore, known bool) map[string]string {
	claims := result.Attributes
	if known {
		if name, value, ok := trust.TokenClaim(s.trustSerialization, score); ok {
			claims = cloneClaimsWithTrust(result.Attributes, name, value)
		}
	}
	dc := deviceCtxFrom(ctx)
	if dc == nil || dc.SecurityCtx == nil {
		return claims
	}
	if !dc.SecurityCtx.DeviceIsNew && !dc.SecurityCtx.LocationIsNew {
		return claims
	}
	if claims == nil {
		claims = make(map[string]string)
	}
	if dc.SecurityCtx.DeviceIsNew {
		claims["device_is_new"] = "true"
	}
	if dc.SecurityCtx.LocationIsNew {
		claims["location_is_new"] = "true"
	}
	return claims
}

// mintAccessToken resolves the per-client token strategy, applies the pairwise
// subject pseudonym, and issues the access token for the direct-mint branch. It
// returns the issued subject so the caller threads the SAME value into the
// id_token (it MUST NOT be recomputed). On any failure it has ALREADY written
// the exact 500 body (no_token_strategy / internal) and returns a non-nil error.
func (s *Server) mintAccessToken(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client, session *Session, trustScore trust.TrustScore, trustKnown bool) (string, *Token, string, error) {
	state := req.State
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrNoTokenStrategy, state))
		return "", nil, "", err
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, result.UserID)
	roles := s.mintRoles(ctx, client, result)
	ttl := client.AccessTokenTTL
	if dc := deviceCtxFrom(ctx); dc != nil {
		ttl = deviceAwareTTL(ttl, dc, 0)
	}
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:                   issuedSub,
		Provider:             result.Provider,
		Claims:               s.directMintClaims(ctx, result, trustScore, trustKnown),
		Resources:            append([]string(nil), req.Resource...),
		ClientID:             client.ID,
		TenantID:             client.TenantID,
		Roles:                roles,
		AuthTime:             time.Now(),
		AMR:                  handler.AmrForResult(result),
		ACR:                  result.AchievedACR,
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		SID:                  session.ID,
		ServingRegion:        servingRegionFrom(ctx),
		TTL:                  ttl,
		RequestedClaims:      oauth.CloneRawJSON(req.Claims),
	}, req.Scope)
	if err != nil {
		s.logger.Error("failed to issue token", "strategy", strategy, "error", err)
		if status, code, ok := core.AuthHookHTTPError(err); ok {
			ctx.JSON(status, s.authzErrorBodyWithState(ctx, code, state))
			return "", nil, "", err
		}
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, state))
		return "", nil, "", err
	}
	return strategy, token, issuedSub, nil
}

// mintRoles resolves the tenant-membership roles for the direct-mint token
// (fail-open, see subjectRoles) and records the role_resolution_failed audit
// event on an outage. Keyed on the LOCAL subject — never the pairwise
// pseudonym, which would fail open to empty (the store is keyed (TenantID,
// UserID)). The same vector is carried on AuthResult so the server-managed
// refresh token persists it for rotation re-stamping.
func (s *Server) mintRoles(ctx HandlerContext, client *Client, result *AuthResult) []string {
	roles, err := s.subjectRoles(ctx.Request().Context(),
		"access-token role resolution failed — roles claim omitted (fail-open)",
		client.TenantID, result.UserID)
	if err != nil {
		s.recordRoleResolutionFailure(ctx, client, result.UserID)
	}
	result.Roles = roles
	return roles
}

// rejectNonJSONLogin is the /auth/login CSRF gate: the login SPA sends
// application/json, so form-encoded submissions that a cross-origin <form>
// could forge are rejected with 415. Returns true when the response was
// written and the caller MUST return.
//
// Uses authzErrorBody (not the plain errorBody) so this response — like every
// other /auth/login response — carries `iss` per RFC 9207 §2: a client
// comparing it against discovery's issuer must be able to detect a mix-up
// even on this earliest pre-bind gate.
func (s *Server) rejectNonJSONLogin(ctx HandlerContext) bool {
	if ct := ctx.Request().Header.Get(core.HeaderContentType); ct != "" && !strings.HasPrefix(ct, "application/json") {
		ctx.JSON(http.StatusUnsupportedMediaType, s.authzErrorBody(ctx, core.ErrInvalidRequest))
		return true
	}
	return false
}

// rejectDisallowedLoginOrigin is defense-in-depth against cross-origin POST:
// the Origin header is validated against the CORS allowed origins even if an
// attacker can set Content-Type: application/json (e.g., via fetch API with
// CORS disabled). Returns true when the 403 was written and the caller MUST
// return.
//
// Uses authzErrorBody (not the plain errorBody) so this response carries
// `iss` per RFC 9207 §2, same as every other /auth/login response — see
// rejectNonJSONLogin.
func (s *Server) rejectDisallowedLoginOrigin(ctx HandlerContext) bool {
	origin := ctx.Request().Header.Get("Origin")
	if origin == "" || s.corsPolicy == nil {
		return false
	}
	if s.isOriginAllowed(origin) {
		return false
	}
	s.logger.Info("origin_blocked",
		"origin", origin,
		"path", ctx.Request().URL.Path,
		"method", ctx.Request().Method,
		"client_ip", ctx.Request().RemoteAddr,
		"user_agent", ctx.Request().UserAgent(),
	)
	ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, core.ErrInvalidRequest))
	return true
}

// armAuthzRequestTimeout applies the authorization-request wall-clock deadline
// (WithAuthorizeRequestTimeout). When the upstream IdP or user interaction
// takes longer than the configured timeout, the handler returns
// interaction_required instead of hanging the browser tab forever. 0 (default)
// means no server-enforced deadline. This is NOT a replacement for the OIDC
// max_age parameter — max_age gates the freshness of the auth_time, while this
// gates total wall-clock duration. The caller MUST defer the returned cancel.
func (s *Server) armAuthzRequestTimeout(ctx HandlerContext) context.CancelFunc {
	if s.authzRequestTimeout <= 0 {
		return func() {}
	}
	r := ctx.Request()
	timedCtx, cancel := context.WithTimeout(r.Context(), s.authzRequestTimeout)
	*r = *r.WithContext(timedCtx)
	return cancel
}

// preAuthLoginGates runs the pre-credential stages in their original order —
// provider listing / home-realm discovery, client existence + active + tenant
// + residency + PAR-JAR-required + allowlist gates, then the post PAR+JAR-merge
// authz-request validation (order JAR -> FAPI -> param shapes) — with the
// login deadline re-checked between stages. handled=true means a response was
// ALREADY written and the caller MUST return.
func (s *Server) preAuthLoginGates(ctx HandlerContext, req *login.Request) (HandlerContext, *Client, bool) {
	// No provider selected yet: home-realm discovery (B2B) or generic provider list.
	if s.respondLoginProviders(ctx, req) {
		return ctx, nil, true
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return ctx, nil, true
	}

	// Pre-authentication client gates (existence/active/tenant/residency/PAR-JAR-required/allowlist).
	client, handled := s.resolveAndValidateLoginClient(ctx, req)
	if handled {
		return ctx, nil, true
	}
	ctx = s.wrapAuthorizationResponse(ctx, req, client)
	if s.checkLoginDeadline(ctx, req.State) {
		return ctx, nil, true
	}

	// Post PAR+JAR-merge authz-request validation (order JAR -> FAPI -> param shapes).
	if s.runPostMergeAuthzValidation(ctx, req, client) {
		return ctx, nil, true
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return ctx, nil, true
	}
	return ctx, client, false
}

// credentialLoginStage resolves the authenticator, validates credentials
// (federated redirect, lockout gate, verify), then runs the post-credential
// gates (order ACR -> risk/step-up) — with the login deadline re-checked
// between stages, exactly as the stages ran inline in handleLogin.
// handled=true means a response was ALREADY written and the caller MUST
// return.
func (s *Server) credentialLoginStage(ctx HandlerContext, req *login.Request, client *Client) (*AuthResult, bool) {
	result, handled := s.authenticateUser(ctx, req, client)
	if handled {
		return nil, true
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return nil, true
	}
	if s.runPostAuthenticateHook(ctx, req, client, result) {
		return nil, true
	}

	if s.runPostCredentialGates(ctx, req, result, client) {
		return nil, true
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return nil, true
	}
	return result, false
}

// bootstrapLoginRequest performs the /auth/login prologue — identical in
// behavior and ORDER to the original inline opening — and returns the bound
// request plus ok=false the instant a guard wrote a response (the caller MUST
// return). Guards in order:
//   - RFC 6749 §5.1: stamps Cache-Control: no-store + Pragma: no-cache, because
//     /auth/login bodies carry access_token + refresh_token (and PKCE-flow code
//     values) an intermediary cache must not retain.
//   - Binds the request: GET reads query params (see bindLoginRequestFromQuery
//     — a real top-level browser navigation is the only way to deliver a
//     cross-origin 3xx redirect to a federated connection's authorize
//     endpoint; a fetch()/XHR POST can't do it, the browser won't follow a
//     cross-origin redirect out of a same-origin fetch), everything else
//     binds the JSON/form body exactly as before. A bind error writes 400
//     invalid_request.
//   - RFC 9126 §4: when request_uri is present, fetches the pushed authorization
//     parameters and merges them in (PAR holds AUTHORIZATION-SHAPED params —
//     response_type, redirect_uri, scope; credentials still arrive on THIS
//     request, so PAR can't bypass user authentication). The merge gives PAR
//     priority over caller-supplied so a tampered redirect can't override what
//     the client previously committed to. resolveLoginRequest writes the response
//     on a stale/missing request_uri.
func (s *Server) bootstrapLoginRequest(ctx HandlerContext) (login.Request, bool) {
	ctx.Set(ctxKeyLoginStart, time.Now())
	tokenNoStoreHeaders(ctx)
	var req login.Request
	var err error
	if ctx.Request().Method == http.MethodGet {
		req, err = bindLoginRequestFromQuery(ctx.Request())
	} else {
		err = ctx.Bind(&req)
	}
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, req.State))
		return req, false
	}
	if s.resolveLoginRequest(ctx, &req) {
		return req, false
	}
	return req, true
}

// --- Tenant suspension cache -----------------------------------------------
//
// Lives here (not a dedicated file) because interfaces/sso is at its frozen
// file-count ceiling (directory_fanout_test.go) — this is otherwise
// unrelated to the /auth/login pipeline above; it backs the tenant-status
// gate consulted during token validation.

// DefaultTenantSuspensionCacheTTL bounds how long a tenant's
// suspension state may be cached between lookups. Short enough that
// a Suspended → Active or Active → Suspended flip propagates
// promptly across the fleet; long enough that hot-path token
// validation doesn't hammer the tenant store on every request.
const DefaultTenantSuspensionCacheTTL = 30 * time.Second

// ErrTenantSuspended is returned by Validate when the token's
// owning client belongs to a tenant whose Status is Suspended.
// Resource paths map this to invalid_token; introspect maps it to
// inactive — same shape every other validation failure produces, so
// an attacker can't probe "is this tenant suspended?" by inspecting
// the error.
var ErrTenantSuspended = errors.New("sso: tenant suspended")

// suspensionCacheEntry pairs a tenant's suspended state with its
// freshness deadline. Caching the boolean lets the hot path skip the
// tenant.Store round-trip on every token validation.
type suspensionCacheEntry struct {
	suspended bool
	expiresAt time.Time
}

// suspensionCache is a tiny TTL map indexed by tenant ID. Sized for
// the typical tens-to-low-thousands of tenants; if you need more,
// swap to an LRU. Reads take RLock so they don't contend on the hot
// validate path.
type suspensionCache struct {
	mu      sync.RWMutex
	entries map[string]suspensionCacheEntry
	ttl     time.Duration
}

func newSuspensionCache(ttl time.Duration) *suspensionCache {
	return &suspensionCache{
		entries: make(map[string]suspensionCacheEntry),
		ttl:     ttl,
	}
}

func (c *suspensionCache) get(tenantID string) (suspended bool, fresh bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[tenantID]
	if !ok {
		return false, false
	}
	if time.Since(e.expiresAt) > 0 {
		return false, false
	}
	return e.suspended, true
}

func (c *suspensionCache) put(tenantID string, suspended bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tenantID] = suspensionCacheEntry{
		suspended: suspended,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *suspensionCache) invalidate(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenantID)
}

// flush drops every entry. Used by the invalidation-bus recovery re-seed: a
// KindTenantSuspension event lost during a bus outage names a tenant we can
// no longer identify, so every cached suspension state must re-fetch.
func (c *suspensionCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]suspensionCacheEntry)
}

// WithTenantSuspensionCheck enables a post-validation gate: every
// token whose owning client is bound to a tenant
// (Client.TenantID != "") has the tenant's Status looked up; tokens
// whose tenant is Suspended fail validation. Combined with the
// existing tenant_mismatch gate at issuance, this closes the gap
// where a token issued while the tenant was Active continues to
// work after suspension.
//
// Lookups are cached per tenant ID for ttl (default
// DefaultTenantSuspensionCacheTTL when ttl <= 0). A tenant store
// outage is treated as fail-open — the request proceeds with the
// cached value (or no check, if the cache hasn't seen this tenant
// yet) — because we'd rather serve stale-Active than 401 every
// request during a tenant store partition.
//
// No-op when no tenant store has been wired via [WithTenantStore].
func WithTenantSuspensionCheck(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl <= 0 {
			ttl = DefaultTenantSuspensionCacheTTL
		}
		s.tenantSuspensionEnabled = true
		s.tenantSuspensionCache = newSuspensionCache(ttl)
	}
}

// InvalidateTenantSuspensionCache clears the cached suspension state
// for tenantID. Wire this into admin SetStatus handlers so that an
// operator flipping Suspended → Active or Active → Suspended takes
// effect on the next validate, not after the TTL expires.
//
// When an invalidation bus is wired ([WithInvalidationBus]), this also
// publishes the change so every other replica clears its local cache
// too — closing the cross-replica window where a just-suspended tenant
// is still honored elsewhere until that node's TTL elapses. Publish
// failures are logged, not propagated: the local invalidation already
// succeeded and peers fall back to their TTL, matching the suspension
// check's fail-open design.
//
// Safe to call when no cache is configured (no-op).
func (s *Server) InvalidateTenantSuspensionCache(tenantID string) {
	if s.tenantSuspensionCache != nil {
		s.tenantSuspensionCache.invalidate(tenantID)
	}
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: tenantID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", tenantID, "error", err)
		}
	}
}

// upsertLoginUser provisions/refreshes the local user record from the
// authentication result when a UserProvider is wired. On a store failure it has
// ALREADY written the exact 500 internal body and returns halted=true; the
// caller must return immediately. No provider = no-op (halted=false).
func (s *Server) upsertLoginUser(ctx HandlerContext, result *AuthResult, state string) bool {
	if s.userProvider == nil {
		return false
	}
	// Preserve profile attributes when the authenticator returned none: a
	// login must not wipe claims another flow (signup, self-service, SCIM)
	// stored on the user record — the login is a refresh, not a reset.
	if result.Attributes == nil {
		if existing, err := s.userProvider.GetByID(ctx.Request().Context(), result.UserID); err == nil && existing != nil {
			result.Attributes = existing.Attributes
		}
	}
	user := &User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}
	if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
		s.logger.Error("failed to upsert user", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, state))
		return true
	}
	return false
}
