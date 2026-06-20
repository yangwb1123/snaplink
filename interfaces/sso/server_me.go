package sso

import (
	"net/http"

	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/protocols/selfservice"

	"github.com/snaplink/sso/shared/core"
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

// handleMe delegates to selfservice.HandleMe.
func (s *Server) handleMe(ctx HandlerContext) { selfservice.HandleMe(s, ctx) }

// handlePatchMe delegates to selfservice.HandleMyProfileUpdate.
func (s *Server) handlePatchMe(ctx HandlerContext) { selfservice.HandleMyProfileUpdate(s, ctx) }

// handleMyMFAFactors delegates to selfservice.HandleMyMFAFactors.
func (s *Server) handleMyMFAFactors(ctx HandlerContext) { selfservice.HandleMyMFAFactors(s, ctx) }

// handleDeleteMyMFAFactor delegates to selfservice.HandleDeleteMyMFAFactor.
func (s *Server) handleDeleteMyMFAFactor(ctx HandlerContext) {
	selfservice.HandleDeleteMyMFAFactor(s, ctx)
}

// handleTOTPEnrollBegin delegates to selfservice.HandleTOTPEnrollBegin.
func (s *Server) handleTOTPEnrollBegin(ctx HandlerContext) { selfservice.HandleTOTPEnrollBegin(s, ctx) }

// handleTOTPEnrollConfirm delegates to selfservice.HandleTOTPEnrollConfirm.
func (s *Server) handleTOTPEnrollConfirm(ctx HandlerContext) {
	selfservice.HandleTOTPEnrollConfirm(s, ctx)
}

// handleChangeMyPassword delegates to selfservice.HandleChangeMyPassword.
func (s *Server) handleChangeMyPassword(ctx HandlerContext) {
	selfservice.HandleChangeMyPassword(s, ctx)
}

// handleMyWebAuthnRegisterBegin delegates to selfservice.HandleWebAuthnRegisterBegin.
func (s *Server) handleMyWebAuthnRegisterBegin(ctx HandlerContext) {
	selfservice.HandleWebAuthnRegisterBegin(s, ctx)
}

// handleMyWebAuthnRegisterFinish delegates to selfservice.HandleWebAuthnRegisterFinish.
func (s *Server) handleMyWebAuthnRegisterFinish(ctx HandlerContext) {
	selfservice.HandleWebAuthnRegisterFinish(s, ctx)
}

// handleMySessions delegates to selfservice.HandleMySessions.
func (s *Server) handleMySessions(ctx HandlerContext) { selfservice.HandleMySessions(s, ctx) }

// handleDeleteMySession delegates to selfservice.HandleDeleteMySession.
func (s *Server) handleDeleteMySession(ctx HandlerContext) { selfservice.HandleDeleteMySession(s, ctx) }

// handleRevokeMySessions delegates to selfservice.HandleRevokeMySessions.
func (s *Server) handleRevokeMySessions(ctx HandlerContext) {
	selfservice.HandleRevokeMySessions(s, ctx)
}

// handleMyConsents delegates to selfservice.HandleMyConsents.
func (s *Server) handleMyConsents(ctx HandlerContext) { selfservice.HandleMyConsents(s, ctx) }

// handleDeleteMyConsent delegates to selfservice.HandleDeleteMyConsent.
func (s *Server) handleDeleteMyConsent(ctx HandlerContext) { selfservice.HandleDeleteMyConsent(s, ctx) }
