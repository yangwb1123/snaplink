package sso

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

func (s *Server) handleLogin(ctx HandlerContext) {
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
func (s *Server) rejectNonJSONLogin(ctx HandlerContext) bool {
	if ct := ctx.Request().Header.Get(core.HeaderContentType); ct != "" && !strings.HasPrefix(ct, "application/json") {
		ctx.JSON(http.StatusUnsupportedMediaType, errorBody(ctx, core.ErrInvalidRequest))
		return true
	}
	return false
}

// rejectDisallowedLoginOrigin is defense-in-depth against cross-origin POST:
// the Origin header is validated against the CORS allowed origins even if an
// attacker can set Content-Type: application/json (e.g., via fetch API with
// CORS disabled). Returns true when the 403 was written and the caller MUST
// return.
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
	ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrInvalidRequest))
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
