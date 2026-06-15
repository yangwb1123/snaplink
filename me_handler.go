package sso

import (
	"net/http"
	"github.com/snaplink/sso/tenant"

	"github.com/snaplink/sso/core"
)
func (s *Server) meSubjectOrChallenge(ctx HandlerContext) (userID string, ok bool) {
	claims, ok := s.meClaimsOrChallenge(ctx)
	if !ok {
		return "", false
	}
	return claims.Subject, true
}

// meClaimsOrChallenge is the full-claims variant backing meSubjectOrChallenge:
// it validates the bearer and returns the whole TokenClaims so handlers that
// need more than the subject (e.g. the current session SID for "sign out of
// other devices") can read it without a second validation. On any failure it
// has already written the oracle-safe resource challenge + 401.
func (s *Server) meClaimsOrChallenge(ctx HandlerContext) (*core.TokenClaims, bool) {
	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return nil, false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	return claims, true
}

// handleBranding serves GET /branding — the public white-label lookup the
// hosted login SPA fetches before authentication to theme the sign-in page.
// Branding is per-vanity-host (tenant.Domain.Branding), so it resolves by the
// request Host, reusing the exact host extraction + trust model the tenant
// middleware uses. Returns only that presentation map (name, color, logo).
//
// Unauthenticated and non-enumerable: an unknown host, a domain with no
// branding, no tenant store, or a store outage all return the same 200 with an
// empty branding object, so the endpoint never reveals which hosts are
// configured. Branding carries only non-sensitive UI data.
func (s *Server) handleBranding(ctx HandlerContext) {
	out := map[string]any{
		"branding": map[string]string{},
		KeyIss:     s.resolveIssuer(ctx),
	}
	if s.tenantStore == nil {
		ctx.JSON(http.StatusOK, out)
		return
	}
	// Prefer the domain the tenant middleware already resolved for this host.
	if r, ok := tenant.FromHandlerContext(ctx); ok && r.Domain != nil && len(r.Domain.Branding) > 0 {
		out["branding"] = r.Domain.Branding
		ctx.JSON(http.StatusOK, out)
		return
	}
	// Fall back to a direct host lookup — the middleware skips stashing for a
	// suspended tenant. Branding is UI-only, so showing a suspended tenant's
	// brand on its own login host is harmless. Use the same host extractor the
	// tenant middleware was configured with, so an operator who disabled
	// X-Forwarded-Host trust is honored here too.
	extract := s.tenantMiddlewareOpts.HostExtractor
	if extract == nil {
		extract = tenant.DefaultHostExtractor
	}
	host := extract(ctx.Request())
	if host == "" {
		ctx.JSON(http.StatusOK, out)
		return
	}
	d, err := s.tenantStore.GetDomain(ctx.Request().Context(), host)
	if err != nil || d == nil || len(d.Branding) == 0 {
		ctx.JSON(http.StatusOK, out)
		return
	}
	out["branding"] = d.Branding
	ctx.JSON(http.StatusOK, out)
}

// handleMe serves GET /me — the authenticated user's self-service account
// overview: their own profile plus active-session and granted-app counts. The
// landing entry for a self-service portal, consolidating data the SPA would
// otherwise assemble from /sessions/me + /consents/me + the token.
//
// Credential-adjacent (same no-store headers as /userinfo). Each enrichment is
// best-effort: a store outage drops that field rather than failing the whole
// response, and the sub/iss baseline is always present.
func (s *Server) handleMe(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	out := map[string]any{
		KeyIss: s.resolveIssuer(ctx),
		KeySub: userID,
	}
	if s.userProvider != nil {
		if u, err := s.userProvider.GetByID(ctx.Request().Context(), userID); err == nil && u != nil {
			out["user"] = u
		}
	}
	if s.sessionMgr != nil {
		if sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), userID); err == nil {
			out["active_sessions"] = len(sessions)
		}
	}
	if s.consentStore != nil {
		if grants, err := s.consentStore.ListByUser(ctx.Request().Context(), userID); err == nil {
			out["granted_apps"] = len(grants)
		}
	}
	ctx.JSON(http.StatusOK, out)
}

// handlePatchMe serves PATCH /me — the authenticated user edits their own
// profile. Body: {name?, attributes?}. The display name is always editable (an
// empty/omitted name leaves it unchanged); attributes are applied ONLY for
// keys in the operator's self-editable allowlist (WithSelfEditableProfileAttributes)
// — every other key is silently dropped, so a user can never escalate by
// writing an authz-relevant attribute the operator keeps alongside presentation
// data. Identity-critical fields (id, external_id, provider, email, timestamps)
// are never self-editable: email in particular needs a verification flow that
// lives outside self-service. Credential-adjacent: no-store headers.
func (s *Server) handlePatchMe(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		Name       string            `json:"name"`
		Attributes map[string]string `json:"attributes"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	u, err := s.userProvider.GetByID(ctx.Request().Context(), userID)
	if err != nil || u == nil {
		// The caller authenticated, so their record should exist; collapse a
		// lookup miss/outage into 404 rather than leak store internals.
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if req.Name != "" {
		u.Name = req.Name
	}
	if len(req.Attributes) > 0 && len(s.selfEditableAttrs) > 0 {
		if u.Attributes == nil {
			u.Attributes = make(map[string]string, len(req.Attributes))
		}
		for k, v := range req.Attributes {
			if _, allowed := s.selfEditableAttrs[k]; allowed {
				u.Attributes[k] = v
			}
		}
	}
	if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), u); err != nil {
		s.logger.Error("update profile failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"user": u, KeyIss: s.resolveIssuer(ctx)})
}

// handleChangeMyPassword serves POST /me/password — the authenticated user
// changes their own password. Body: {current_password, new_password}. Verifies
// the current password against the credential store, then sets the new one.
//
// Credential endpoint: no-store headers. The caller is authenticated as their
// own account, so naming the wrong-current-password case (invalid_password) is
// not an enumeration leak — the user needs to know their entry was wrong. The
// store's VerifyPassword is itself anti-enumeration (dummy compare on unknown).
