package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/cors"
	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// WithCORS installs a CORS middleware between bodyLimit and the router. That
// ordering lets preflight requests short-circuit before routing while still
// being traced, rate-limited, and counted by metrics. An empty AllowedOrigins
// list disables CORS without adding request-path work. This policy supports
// credentials, exposed headers, and preflight caching beyond the legacy
// router-level CORS MiddlewareFunc.
func WithCORS(policy cors.Policy) Option {
	return func(s *Server) { s.corsPolicy = &policy }
}

// The Key* re-exports below moved here from aliases.go to keep that
// generated file within the per-file line budget; this file otherwise has
// no relation to the wire-payload key constants.
// GatedRegistrar re-exports core.GatedRegistrar so SDK callers can
// type-assert a sso.Router backend's route-matching-level gating capability
// (and adapters can claim it) without importing shared/core. Placed here,
// not in aliases.go, which sits at the per-file line budget.
type GatedRegistrar = core.GatedRegistrar

// Admin keyset-pagination SPI re-exports (aliases.go is at its line budget;
// contracts in shared/core/pagination.go + domains/tenant/pagination.go).
type PageQuery = core.PageQuery
type PaginatedClientStore = core.PaginatedClientStore
type ClientExpiryLister = core.ClientExpiryLister
type PaginatedUserProvider = core.PaginatedUserProvider
type PaginatedSessionLister = core.PaginatedSessionLister
type PaginatedTenantStore = tenant.PaginatedTenantStore
type PaginatedDomainStore = tenant.PaginatedDomainStore

const KeyAccessToken = core.KeyAccessToken
const KeyACR = core.KeyACR
const KeyActive = core.KeyActive
const KeyAMR = core.KeyAMR
const KeyAud = core.KeyAud
const KeyAuthTime = core.KeyAuthTime
const KeyClientID = core.KeyClientID
const KeyTenantID = core.KeyTenantID
const KeyClientName = core.KeyClientName
const KeyScopes = core.KeyScopes
const KeyCode = core.KeyCode
const KeyCountryCode = core.KeyCountryCode
const KeyError = core.KeyError
const KeyErrorDescription = core.KeyErrorDescription
const KeyExp = core.KeyExp
const KeyExpiresIn = core.KeyExpiresIn
const KeyIat = core.KeyIat
const KeyIDToken = core.KeyIDToken
const KeyIss = core.KeyIss
const KeyIssuedTokenType = core.KeyIssuedTokenType
const KeyIssuer = core.KeyIssuer
const KeyJTI = core.KeyJTI
const KeyConsentChallengeID = core.KeyConsentChallengeID
const KeyMFAChallengeID = core.KeyMFAChallengeID
const KeyMFAMethod = core.KeyMFAMethod
const KeyMFAMethodData = core.KeyMFAMethodData
const KeyMFAMethods = core.KeyMFAMethods
const KeyNbf = core.KeyNbf
const KeyProviders = core.KeyProviders
const KeyClientContext = core.KeyClientContext
const KeyRecommendedLang = core.KeyRecommendedLang
const KeyRedirectURI = core.KeyRedirectURI
const KeyRefreshToken = core.KeyRefreshToken
const KeyRevoked = core.KeyRevoked
const KeyScope = core.KeyScope
const KeyServingRegion = core.KeyServingRegion
const KeySessionID = core.KeySessionID
const KeyState = core.KeyState
const KeyDevice = core.KeyDevice
const KeyLoginPageURI = core.KeyLoginPageURI
const KeyPreviousLogin = core.KeyPreviousLogin
const KeyBranding = core.KeyBranding
const KeyActiveDevices = core.KeyActiveDevices
const KeyDeviceLimitWarn = core.KeyDeviceLimitWarn
const KeySessionLimitWarn = core.KeySessionLimitWarn
const KeyStatus = core.KeyStatus
const KeyStrategy = core.KeyStrategy
const KeySub = core.KeySub
const KeySupportedGrants = core.KeySupportedGrants
const KeyTokenHint = core.KeyTokenHint
const KeyTokenStrategy = core.KeyTokenStrategy
const KeyTokenType = core.KeyTokenType
const KeyBuildTime = core.KeyBuildTime
const KeyVCSRevision = core.KeyVCSRevision
const KeyVCSTime = core.KeyVCSTime
const KeyVersion = core.KeyVersion

// authorizationResponseCtx attests the effective post-PAR/JAR delivery
// contract. Browser-visible request parameters are never authoritative here.
type authorizationResponseCtx struct {
	HandlerContext
	server *Server
	req    login.Request
	client *Client
}

func (s *Server) wrapAuthorizationResponse(ctx HandlerContext, req *login.Request, client *Client) HandlerContext {
	if req.RedirectURI == "" || !client.IsRedirectURIValid(req.RedirectURI) {
		return ctx
	}
	if s.oauth21Strict && !isSecureRedirectURI(req.RedirectURI) {
		return ctx
	}
	return &authorizationResponseCtx{HandlerContext: ctx, server: s, req: *req, client: client}
}

func (c *authorizationResponseCtx) JSON(code int, value any) {
	errorCode, description, isError := authorizationErrorFields(value)
	if isError && (errorCode == ErrMFARequired || errorCode == ErrConsentRequired) {
		c.HandlerContext.JSON(code, value)
		return
	}
	if isError && oidc.IsJARMResponseMode(c.req.ResponseMode) && c.writeJARMError(errorCode, description) {
		return
	}
	body := authorizationResponseMap(value)
	c.attestAuthorizationDelivery(body)
	c.HandlerContext.JSON(code, body)
}

func (c *authorizationResponseCtx) attestAuthorizationDelivery(body map[string]any) {
	body["redirect_uri_validated"] = true
	body[KeyRedirectURI] = c.req.RedirectURI
	body["response_mode"] = effectiveAuthorizationResponseMode(c.req)
	if oidc.IsJARMResponseMode(c.req.ResponseMode) {
		delete(body, KeyState)
		return
	}
	if c.req.State != "" {
		body[KeyState] = c.req.State
	} else {
		delete(body, KeyState)
	}
}

func effectiveAuthorizationResponseMode(req login.Request) string {
	if req.ResponseMode != "" {
		return req.ResponseMode
	}
	if req.ResponseType == "" || req.ResponseType == "token" {
		return ResponseModeFragment
	}
	return ResponseModeQuery
}

func (c *authorizationResponseCtx) writeJARMError(code, description string) bool {
	signer, ok := c.server.jarmSignerForClient(c.client)
	if !ok {
		return false
	}
	if c.req.ResponseMode != oidc.ResponseModeFormPostJWT && c.Request().Method != http.MethodGet {
		response, err := oidc.SignJARMErrorResponse(
			c.Request().Context(), signer, c.server.resolveIssuer(c), c.client.ID,
			code, description, c.req.State,
		)
		if err != nil {
			return false
		}
		body := map[string]any{oidc.KeyResponse: response}
		c.attestAuthorizationDelivery(body)
		c.HandlerContext.JSON(http.StatusOK, body)
		return true
	}
	return oidc.RenderJARMErrorResponse(
		c.HandlerContext, signer, c.req.ResponseMode, c.req.RedirectURI,
		c.server.resolveIssuer(c), c.client.ID, code, description, c.req.State,
	)
}

func authorizationErrorFields(value any) (string, string, bool) {
	switch body := value.(type) {
	case map[string]string:
		code := body[KeyError]
		return code, body[KeyErrorDescription], code != ""
	case map[string]any:
		code, _ := body[KeyError].(string)
		description, _ := body[KeyErrorDescription].(string)
		return code, description, code != ""
	default:
		return "", "", false
	}
}

func authorizationResponseMap(value any) map[string]any {
	result := map[string]any{}
	switch body := value.(type) {
	case map[string]string:
		for key, item := range body {
			result[key] = item
		}
	case map[string]any:
		for key, item := range body {
			result[key] = item
		}
	}
	return result
}

const federatedStateSeparator = ":slf."

type federatedAuthorizationState struct {
	Request  login.Request `json:"request"`
	Provider string        `json:"provider"`
}

func (s *Server) beginFederatedLogin(ctx HandlerContext, req *login.Request, client *Client, auth Authenticator) bool {
	id, err := newMFAChallengeID()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, req.State))
		return true
	}
	wireState := req.Provider + federatedStateSeparator + id
	location := auth.LoginURL(wireState)
	if location == "" {
		return false
	}
	if !validFederatedLoginPage(client.LoginPageURI) || s.loginTransactionStore == nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, req.State))
		return true
	}
	clean := *req
	clean.Credential, clean.DeviceToken = nil, ""
	clean.LoginTransactionID, clean.ConsentChallengeID, clean.ConsentDecision = "", "", ""
	blob, err := json.Marshal(&federatedAuthorizationState{Request: clean, Provider: req.Provider})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, req.State))
		return true
	}
	ttl := s.loginTransactionTTL
	if ttl <= 0 {
		ttl = spi.DefaultMFAChallengeTTL
	}
	now := time.Now()
	if err = s.loginTransactionStore.Put(ctx.Request().Context(), &spi.MFAChallenge{
		ID: wireState, SubjectID: req.Provider, ClientID: client.ID,
		CreatedAt: now, ExpiresAt: now.Add(ttl), RequestState: blob,
	}); err != nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrInternal, req.State))
		return true
	}
	ctx.Redirect(http.StatusFound, location)
	return true
}

func federatedProviderFromState(state string) (string, bool) {
	provider, opaque, ok := strings.Cut(state, federatedStateSeparator)
	return provider, ok && provider != "" && opaque != ""
}

func validFederatedLoginPage(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.IsAbs() && u.Host != "" && u.User == nil && isSecureRedirectURI(raw)
}

// IsFederatedLoginPageURIValid exposes the exact hosted-login validation used
// by federation kickoff so configuration and admin surfaces can fail early.
func IsFederatedLoginPageURIValid(raw string) bool {
	return validFederatedLoginPage(raw)
}

func (s *Server) federatedContinuationSupported(ctx HandlerContext, clientID string) bool {
	if clientID == "" || s.clientStore == nil {
		return false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	return err == nil && client != nil && client.Active && validFederatedLoginPage(client.LoginPageURI)
}

func (s *Server) consumeFederatedAuthorization(ctx HandlerContext, state string) (*federatedAuthorizationState, *Client, bool) {
	provider, marked := federatedProviderFromState(state)
	if !marked || s.loginTransactionStore == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return nil, nil, false
	}
	challenge, err := s.loginTransactionStore.Consume(ctx.Request().Context(), state)
	if err != nil || challenge == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return nil, nil, false
	}
	resume := &federatedAuthorizationState{}
	if json.Unmarshal(challenge.RequestState, resume) != nil ||
		!validFederatedResume(resume, provider, challenge.SubjectID, challenge.ClientID) ||
		s.clientStore == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return nil, nil, false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), challenge.ClientID)
	if err != nil || !validFederatedCallbackClient(ctx, client, resume, provider) {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return nil, nil, false
	}
	if s.residencyGateLogin(ctx, client.ID, provider, client.TenantID) {
		return nil, nil, false
	}
	return resume, client, true
}

func federatedContinuationURI(client *Client, req login.Request, transactionID string) (string, error) {
	u, err := url.Parse(client.LoginPageURI)
	if err != nil || !validFederatedLoginPage(client.LoginPageURI) {
		return "", errors.New("invalid federated login page")
	}
	q := u.Query()
	q.Set("client_id", req.ClientID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("response_type", req.ResponseType)
	if req.ResponseMode != "" {
		q.Set("response_mode", req.ResponseMode)
	}
	u.RawQuery = q.Encode()
	u.Fragment = url.Values{login.KeyLoginTransactionID: []string{transactionID}}.Encode()
	return u.String(), nil
}

type extensionHandlerContextKey struct{}

func requestWithHandlerContext(ctx HandlerContext) *http.Request {
	return ctx.Request().WithContext(context.WithValue(ctx.Request().Context(), extensionHandlerContextKey{}, ctx))
}

func handlerContextForRequest(w http.ResponseWriter, r *http.Request) HandlerContext {
	if ctx, ok := r.Context().Value(extensionHandlerContextKey{}).(HandlerContext); ok && ctx != nil {
		return ctx
	}
	return core.NewContext(w, r)
}

// isOriginAllowed checks if the given origin is allowed by the CORS policy.
// Returns true if:
//   - No CORS policy is configured (allow all for backwards compatibility)
//   - The origin is in the AllowedOrigins list
//   - Wildcard "*" is configured
//
// Returns false if:
//   - CORS policy exists but origin is not in AllowedOrigins and no wildcard
//
// This is used for defense-in-depth CSRF protection on sensitive endpoints
// like /auth/login where we want to validate the Origin header even before
// the CORS middleware runs.
func (s *Server) isOriginAllowed(origin string) bool {
	// No CORS policy = no origin restrictions (backwards compatible)
	if s.corsPolicy == nil {
		return true
	}

	// Check each allowed origin
	for _, allowed := range s.corsPolicy.AllowedOrigins {
		// Wildcard allows any origin
		if allowed == "*" {
			return true
		}
		// Exact match
		if allowed == origin {
			return true
		}
	}

	return false
}

// --- CIBA ping delivery -----------------------------------------------
//
// Lives here (not a dedicated file) because interfaces/sso is at its frozen
// file-count ceiling (directory_fanout_test.go) — this is otherwise
// unrelated to origin/CORS validation above; it backs CIBA's ping/push
// notification-delivery mode.

// ErrCIBANotEnabled is returned by ResolveBackchannelAuthRequest when no
// CIBA store is wired (WithCIBA not configured). It is an SDK-level
// sentinel, not a wire error code.
var ErrCIBANotEnabled = errors.New("sso: CIBA is not enabled")

// cibaPingDeliveryTimeout bounds the detached ping goroutine spawned on
// resolution. The request that triggered the approval has already returned,
// so the goroutine runs on context.Background() with NO inherited deadline —
// without this bound a hanging/never-returning custom notifier would leak the
// goroutine forever. Deliberately set LONGER than the reference
// httpCIBAPingNotifier's own 5s HTTP client timeout so the transport's timeout
// fires first on the common path (yielding a clean error, not a context
// cancellation), while a custom notifier that ignores ctx still gets bounded.
const cibaPingDeliveryTimeout = 10 * time.Second

// ResolveBackchannelAuthRequest transitions a pending CIBA request to
// approved or denied and, in ping or push delivery mode, notifies the
// client. Operators call this from their device-confirmation callback
// instead of poking CIBAStore.SetStatus directly, so delivery fires
// automatically on resolution.
//
// The status transition is authoritative (a /token poll — still available
// as a fallback even in push mode — mints or refuses tokens off it).
// Delivery is best-effort and fire-and-forget: dispatchCIBANotification
// (accessors_feature_gates.go) picks push over ping when both are wired
// and the resolution is an approval (push is a strict upgrade — it mints
// and delivers the actual token, see deliverCIBAPush); a denied resolution
// has no token to push, so ping (if wired) still fires for it. A failed
// delivery is logged, never returned, since the client can still poll.
//
// Returns ErrCIBANotEnabled if CIBA isn't wired, or the store's error for
// an unknown/expired (oauth.ErrCIBARequestNotFound) or already-resolved
// (oauth.ErrCIBARequestResolved) request.
func (s *Server) ResolveBackchannelAuthRequest(ctx context.Context, authReqID string, approved bool) error {
	if s.cibaStore == nil {
		return ErrCIBANotEnabled
	}
	// Read before transition so a racing /token poll that consumes +
	// deletes the entry can't strip the notification token from under us.
	req, err := s.cibaStore.Get(ctx, authReqID)
	if err != nil {
		return err
	}
	status := oauth.CIBADenied
	if approved {
		status = oauth.CIBAApproved
	}
	if err := s.cibaStore.SetStatus(ctx, authReqID, status); err != nil {
		return err
	}
	if req.ClientNotificationToken != "" {
		s.dispatchCIBANotification(authReqID, req.ClientID, req.ClientNotificationToken, approved)
	}
	return nil
}

// deliverCIBAPing supervises a single detached CIBA ping delivery. It is the
// body of the goroutine spawned by ResolveBackchannelAuthRequest, extracted so
// the timeout + recover + metric/audit wrapper is unit-testable in isolation.
//
// Hardening over the original bare `go n.Notify(context.Background(), ...)`:
//   - Bounded context: a hanging/never-returning notifier can no longer leak
//     this goroutine indefinitely (cibaPingDeliveryTimeout).
//   - recover(): a panicking custom notifier is contained here — it logs +
//     audits + counts an error instead of taking down the goroutine (and
//     potentially the process) with no trace.
//   - Observability: every outcome increments sso_ciba_ping_total{outcome};
//     failures (error return OR recovered panic) also emit a ciba_ping_failed
//     audit event so operators can see WHICH client's ping failed.
//
// The ping is best-effort by contract (the client can still poll), so a failure
// is logged + recorded, never surfaced — there is no caller to return to.
func (s *Server) deliverCIBAPing(clientID, authReqID, token string) {
	// recover() so a panic in a third-party notifier can't crash the goroutine
	// silently (or escalate to a process-wide crash on an unrecovered panic in
	// a bare goroutine). On recovery, treat it as a delivery failure.
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("panic: %v", r)
			s.logger.Error("ciba ping notification panicked", "auth_req_id", authReqID, "client_id", clientID, "panic", r)
			s.recordCIBAPingFailure(clientID, authReqID, reason)
		}
	}()

	// context.Background() is the correct PARENT here (the request that
	// triggered the approval has returned, so there is no live request ctx to
	// inherit — inheriting one would cancel the ping immediately). We ADD a
	// deadline so a notifier that blocks past the bound is unblocked and the
	// goroutine returns.
	ctx, cancel := context.WithTimeout(context.Background(), cibaPingDeliveryTimeout)
	defer cancel()

	if err := s.cibaPingNotifier.Notify(ctx, clientID, authReqID, token); err != nil {
		s.logger.Error("ciba ping notification failed", "auth_req_id", authReqID, "client_id", clientID, "error", err)
		s.recordCIBAPingFailure(clientID, authReqID, err.Error())
		return
	}
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("success").Inc()
	}
}

// recordCIBAPingFailure is the shared error tail for deliverCIBAPing: bump the
// error metric + emit the ciba_ping_failed audit event. Detached goroutine, so
// it audits over context.Background() via the background-context recorder helper
// (mirrors the signing-key aggregation degraded/recovered events).
func (s *Server) recordCIBAPingFailure(clientID, authReqID, reason string) {
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("error").Inc()
	}
	audit.RecordCIBAPingFailed(s.auditor, context.Background(), clientID, authReqID, reason)
}
