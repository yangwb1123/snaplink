package sso

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
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

	// OIDC Core §3.1.2.1 prompt=none silent-renewal contract; parsed before the
	// providers/credential paths so this branch can override them (see handlePromptNone).
	prompts := oidc.ParsePromptValues(req.Prompt)
	if oidc.PromptHasNone(prompts) {
		s.handlePromptNone(ctx, prompts, &req)
		return
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return
	}

	client, handled := s.preAuthLoginGates(ctx, &req)
	if handled {
		return
	}

	result, handled := s.credentialLoginStage(ctx, &req, client)
	if handled {
		return
	}

	s.finishLogin(ctx, result, req, client)
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
func (s *Server) preAuthLoginGates(ctx HandlerContext, req *login.Request) (*Client, bool) {
	// No provider selected yet: home-realm discovery (B2B) or generic provider list.
	if s.respondLoginProviders(ctx, req) {
		return nil, true
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return nil, true
	}

	// Pre-authentication client gates (existence/active/tenant/residency/PAR-JAR-required/allowlist).
	client, handled := s.resolveAndValidateLoginClient(ctx, req)
	if handled {
		return nil, true
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return nil, true
	}

	// Post PAR+JAR-merge authz-request validation (order JAR -> FAPI -> param shapes).
	if s.runPostMergeAuthzValidation(ctx, req, client) {
		return nil, true
	}
	if s.checkLoginDeadline(ctx, req.State) {
		return nil, true
	}
	return client, false
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
	if ctx.Request().Method == http.MethodGet {
		req = bindLoginRequestFromQuery(ctx.Request())
	} else if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, req.State))
		return req, false
	}
	if s.resolveLoginRequest(ctx, &req) {
		return req, false
	}
	return req, true
}

// bindLoginRequestFromQuery populates the authorization-request-shaped subset
// of login.Request from URL query parameters, for the ONLY case a bodyless
// GET reaches /auth/login: a "Sign in with <federated provider>" button
// doing a real page navigation. Credential/consent/PAR/JAR fields are
// deliberately NOT bound here — a GET can't carry a credential (it would
// leak into browser history / server access logs), so credentialLoginStage
// either dispatches to auth.LoginURL's redirect (the intended path) or, for
// a non-federated provider, fails closed the same way an empty credential
// always has.
func bindLoginRequestFromQuery(r *http.Request) login.Request {
	q := r.URL.Query()
	req := login.Request{
		Provider:            q.Get("provider"),
		ClientID:            q.Get("client_id"),
		State:               q.Get("state"),
		ResponseType:        q.Get("response_type"),
		RedirectURI:         q.Get("redirect_uri"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Prompt:              q.Get("prompt"),
		LoginHint:           q.Get("login_hint"),
		ResponseMode:        q.Get("response_mode"),
		ACRValues:           q.Get("acr_values"),
		UILocales:           q.Get("ui_locales"),
	}
	if scope := q.Get("scope"); scope != "" {
		req.Scope = strings.Fields(scope)
	}
	if resource := q.Get("resource"); resource != "" {
		req.Resource = strings.Fields(resource)
	}
	return req
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
