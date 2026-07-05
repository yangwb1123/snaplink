package sso

import (
	"net/http"
	"slices"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

// handleUserInfo delegates to oidc.HandleUserInfo (the OIDC §5.3 endpoint
// orchestration). *Server satisfies oidc.UserInfoDeps via accessors_userinfo.go;
// the security primitives (token validation, DPoP/mTLS sender-constraint,
// residency read-gate) are implemented in the root package.
func (s *Server) handleUserInfo(ctx HandlerContext) { oidc.HandleUserInfo(s, ctx) }

// handleCheckSessionIframe delegates to oidc.HandleCheckSessionIframe — the
// OpenID Connect Session Management 1.0 §2 endpoint. No Deps: see there.
func (s *Server) handleCheckSessionIframe(ctx HandlerContext) { oidc.HandleCheckSessionIframe(ctx) }

// mountOIDCUserEndpoints registers the OIDC-specific /userinfo,
// /end_session, and (session-management-gated) /check_session_iframe
// routes. Moved out of server_routes.go (which sat at the line budget) so
// the OIDC gate check + the session-management gate live beside the
// handlers they mount.
func (s *Server) mountOIDCUserEndpoints() {
	if !s.oidcGateOn() {
		return
	}
	s.router.GET(PathUserInfo, s.handleUserInfo)
	s.router.GET(PathEndSession, s.handleEndSession)
	if s.sessionManagementEnabled {
		s.router.GET(PathCheckSessionIframe, s.handleCheckSessionIframe)
	}
}

// applySessionManagement computes + stamps the OpenID Connect Session
// Management 1.0 §2 `session_state` (only when WithOIDCSessionManagement is
// wired AND the request carries the openid scope — byte-identical response
// shape otherwise) and sets the matching browser-state cookie the
// check_session_iframe page later reads via document.cookie.
//
// origin is derived from the RP's OWN redirect_uri — the only allowlist-
// validated RP URL available at /auth/login — per the algorithm's "origin"
// input. browserState is this login's freshly-created session id: it is
// fresh on every login and disappears at logout (ClearSessionManagementCookie
// in accessors.go), which is exactly the "changes when login state changes"
// contract the spec requires of browser_state.
//
// Fail-open: a salt-generation error just omits session_state (and skips
// the cookie) rather than blocking the login.
func (s *Server) applySessionManagement(ctx HandlerContext, req *login.Request, client *Client, session *Session, resp map[string]any) {
	if !s.sessionManagementEnabled || !slices.Contains(req.Scope, ScopeOpenID) {
		return
	}
	origin := oidc.OriginFromURL(req.RedirectURI)
	state, err := oidc.BuildSessionState(client.ID, origin, session.ID)
	if err != nil {
		s.logger.Error("session_state computation failed", "error", err)
		return
	}
	resp[core.KeySessionState] = state
	http.SetCookie(ctx.ResponseWriter(), &http.Cookie{
		Name:     oidc.CheckSessionCookieName,
		Value:    session.ID,
		Path:     PathCheckSessionIframe,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
}

// handleMeshExtAuthz is the Envoy/Istio ext_authz HTTP-mode authorization
// endpoint (cluster C1 mesh data-plane). A mesh sidecar calls it per
// request: a 200 ALLOWs (and the sidecar injects the X-Auth-* response
// headers stamped here into the upstream request), any other status
// DENIES. It is essentially a /userinfo variant that returns IDENTITY
// HEADERS instead of a body — so it reuses the EXACT bearer-validation
// path /userinfo uses (validateAnyToken + the DPoP/mTLS sender-constraint
// checks), with no new validation logic. The "validate at the sidecar,
// inject identity to the upstream" mesh pattern.
//
// TRUST MODEL: every X-Auth-* header is DERIVED from the validated token;
// the endpoint NEVER trusts an inbound X-Auth-*. The upstream trusts the
// injected headers ONLY because the sidecar ran this check, so the mesh
// MUST strip client-supplied X-Auth-* at ingress (same edge-strip model
// as X-Forwarded-* / mtls.backend: header — AGENTS.md §2). The endpoint
// is mesh-internal: only the trusted sidecar should be able to reach it.
func (s *Server) handleMeshExtAuthz(ctx HandlerContext) {
	// Credential-validating endpoint: the (header-only) response must
	// never be retained by an intermediary — a cached cross-request
	// ALLOW would let a different bearer's identity be injected upstream.
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(DepTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	// Thin HTTP wrapper over the dep-free MeshAuthorize seam (mesh_authz.go).
	// The decision (bearer validation + DPoP/mTLS sender-constraint +
	// residency + identity derivation) lives in MeshAuthorize so a future
	// Phase-B go-control-plane gRPC Authorization service reuses the EXACT
	// same logic without duplicating it.
	r := ctx.Request()
	res := s.MeshAuthorize(r.Context(), MeshAuthorizeRequest{
		Method: r.Method,
		URL:    requestURLForDPoP(r),
		Header: r.Header,
		TLS:    r.TLS,
	})
	s.writeMeshAuthzResponse(ctx, res)
}
