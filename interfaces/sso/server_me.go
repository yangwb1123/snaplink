package sso

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/identitylink"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/protocols/selfservice"

	"github.com/snaplink/sso/shared/core"
)

// IdentityLinkStore exposes the wired self-service identity-link store (may
// be nil — see domains/identitylink). Satisfies selfservicecore.Deps.
// Relocated from accessors.go to keep that file within the per-file line
// budget; belongs beside the /me/identities wiring here.
func (s *Server) IdentityLinkStore() identitylink.Store { return s.identityLinkStore }

// IdentityMergePolicy exposes the operator's wired conflict-resolution
// strategy (WithIdentityMergePolicy), or nil when unwired. This is the
// extension point a CUSTOM authenticator/login integration calls
// identitylink.Resolve with — see the domains/identitylink package doc for
// why the stock /auth/login handler does not invoke it itself.
func (s *Server) IdentityMergePolicy() identitylink.MergePolicy { return s.identityMergePolicy }

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
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrMissingToken))
		return nil, false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidToken))
		return nil, false
	}
	stampBreakGlassActor(ctx, claims)
	return claims, true
}

// stampBreakGlassActor propagates break-glass impersonation attribution onto the
// request context so every audit event a downstream handler records under this
// bearer (via ctx.Request().Context()) carries the acting admin + grant id — not
// just the mint event. It mutates the request in place because the self-service
// handlers read ctx.Request().Context() afresh for each audit.Record call; a
// returned-but-unthreaded context would be dropped. No-op (byte-identical) for an
// ordinary user bearer — the marker is absent.
func stampBreakGlassActor(ctx HandlerContext, claims *core.TokenClaims) {
	if !core.IsBreakGlassImpersonationClaims(claims) {
		return
	}
	adminID := ""
	if claims.Actor != nil {
		adminID = claims.Actor.Subject
	}
	bg := core.BreakGlassActor{AdminID: adminID, AdminSessionID: claims.Extra[core.ClaimBreakGlassAdminSessionID]}
	r := ctx.Request()
	*r = *r.WithContext(core.ContextWithBreakGlassActor(r.Context(), bg))
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

// handleGenerateRecoveryCodes delegates to selfservice.HandleGenerateRecoveryCodes.
func (s *Server) handleGenerateRecoveryCodes(ctx HandlerContext) {
	selfservice.HandleGenerateRecoveryCodes(s, ctx)
}

// handleGetRecoveryCodesCount delegates to selfservice.HandleGetRecoveryCodesCount.
func (s *Server) handleGetRecoveryCodesCount(ctx HandlerContext) {
	selfservice.HandleGetRecoveryCodesCount(s, ctx)
}

// handleChangeMyPassword delegates to selfservice.HandleChangeMyPassword.
func (s *Server) handleChangeMyPassword(ctx HandlerContext) {
	selfservice.HandleChangeMyPassword(s, ctx)
}

// handleMyTrustedDevices delegates to selfservice.HandleMyTrustedDevices.
func (s *Server) handleMyTrustedDevices(ctx HandlerContext) {
	selfservice.HandleMyTrustedDevices(s, ctx)
}

// handleTrustMyDevice delegates to selfservice.HandleTrustMyDevice.
func (s *Server) handleTrustMyDevice(ctx HandlerContext) { selfservice.HandleTrustMyDevice(s, ctx) }

// handleRevokeMyTrustedDevice delegates to selfservice.HandleRevokeMyTrustedDevice.
func (s *Server) handleRevokeMyTrustedDevice(ctx HandlerContext) {
	selfservice.HandleRevokeMyTrustedDevice(s, ctx)
}

// mountTrustedDeviceRoutes registers the self-service "remember this device"
// MFA-skip surface (GET/POST/DELETE /me/devices*). Called from
// mountSelfServiceCredentials (server_routes.go); kept here — rather than
// grown inline there — to keep that orchestrator within the per-function
// line budget. Byte-identical without a store wired.
func (s *Server) mountTrustedDeviceRoutes() {
	if s.trustedDeviceStore == nil {
		return
	}
	s.router.GET(PathMyDevices, s.handleMyTrustedDevices)
	s.router.POST(PathMyDevicesTrust, s.handleTrustMyDevice)
	s.router.DELETE(PathMyDeviceByID, s.handleRevokeMyTrustedDevice)
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

// handleMeSessions delegates to selfservice.HandleMySessions for GET /me/sessions.
func (s *Server) handleMeSessions(ctx HandlerContext) { selfservice.HandleMySessions(s, ctx) }

// handleDeleteMeSession delegates to selfservice.HandleDeleteMySession for DELETE /me/sessions/:id.
func (s *Server) handleDeleteMeSession(ctx HandlerContext) { selfservice.HandleDeleteMySession(s, ctx) }

// handleMeSessionsRevokeAll delegates to selfservice.HandleRevokeAllMySessions for POST /me/sessions/revoke-all.
// Unlike DELETE /sessions/me, this always revokes every session (no keepCurrent).
func (s *Server) handleMeSessionsRevokeAll(ctx HandlerContext) {
	selfservice.HandleRevokeAllMySessions(s, ctx)
}

// handleMyConsents delegates to selfservice.HandleMyConsents.
func (s *Server) handleMyConsents(ctx HandlerContext) { selfservice.HandleMyConsents(s, ctx) }

// handleDeleteMyConsent delegates to selfservice.HandleDeleteMyConsent.
func (s *Server) handleDeleteMyConsent(ctx HandlerContext) { selfservice.HandleDeleteMyConsent(s, ctx) }

// PathMyIdentities lists (GET) the authenticated user's linked external
// identities (federated IdP subjects, or other local accounts folded in);
// PathMyIdentityByID unlinks one (DELETE). See domains/identitylink for the
// self-service identity-linking / account-merge-safety feature these back.
// Defined here (rather than shared/core/consts.go, which is near its own
// budget) — mirrors the existing PathHomeRealm/PathDRMode/PathOIDCDiscovery
// precedent of package-local path constants.
const (
	PathMyIdentities   = "/me/identities"
	PathMyIdentityByID = "/me/identities/:id"
)

// handleMyIdentities delegates to selfservice.HandleMyIdentities.
func (s *Server) handleMyIdentities(ctx HandlerContext) { selfservice.HandleMyIdentities(s, ctx) }

// handleUnlinkMyIdentity delegates to selfservice.HandleUnlinkMyIdentity.
func (s *Server) handleUnlinkMyIdentity(ctx HandlerContext) {
	selfservice.HandleUnlinkMyIdentity(s, ctx)
}

// mountSelfServiceProfile, mountSelfServiceCredentials, and
// mountBrandingEndpoint relocated here from server_routes.go, which sat at
// the 500-line file budget — this file (self-service /me* handlers) is
// their natural home and had ample headroom. Mount() (server_routes.go)
// still calls them; only the definitions moved.

// mountSelfServiceProfile registers the authenticated /me* self-service
// endpoints for permissions/menus/roles, sessions, consents, identities, org
// membership, and profile — each gated on its backing store, and all of them
// behind the SelfService feature gate (a deployment that never wants an
// end-user-facing self-service surface hides the whole group).
func (s *Server) mountSelfServiceProfile() {
	if !s.selfServiceGateOn() {
		return
	}
	s.router.GET(PathMyPermissions, s.handleMyPermissions)
	s.router.GET(PathMyMenus, s.handleMyMenus)
	s.router.GET(PathMyRoles, s.handleMyRoles)
	if s.sessionMgr != nil {
		s.router.GET(PathMySessions, s.handleMySessions)
		s.router.DELETE(PathMySessions, s.handleRevokeMySessions)
		s.router.DELETE(PathMySessionByID, s.handleDeleteMySession)
		// /me/sessions* self-service endpoints follow the /me/* naming
		// convention used by the rest of the self-service API surface.
		s.router.GET(PathMeSessions, s.handleMeSessions)
		s.router.DELETE(PathMeSessionByID, s.handleDeleteMeSession)
		s.router.POST(PathMeSessionsRevokeAll, s.handleMeSessionsRevokeAll)
	}
	if s.consentStore != nil {
		s.router.GET(PathMyConsents, s.handleMyConsents)
		s.router.DELETE(PathMyConsentByID, s.handleDeleteMyConsent)
	}
	// Self-service identity linking: list the caller's linked external
	// identities + unlink one. Mounted only when a Store is wired
	// (WithIdentityLinkStore) — byte-identical to a build without it.
	if s.identityLinkStore != nil {
		s.router.GET(PathMyIdentities, s.handleMyIdentities)
		s.router.DELETE(PathMyIdentityByID, s.handleUnlinkMyIdentity)
	}
	// Self-service B2B org membership: list my orgs + leave one.
	if s.tenantUserStore != nil {
		s.router.GET(PathMyOrganizations, s.handleMyOrganizations)
		s.router.DELETE(PathMyOrganizationByID, s.handleLeaveMyOrganization)
		// Accept an invitation (joins an org) — needs both stores.
		if s.invitationStore != nil {
			s.router.POST(PathMyInvitationAccept, s.handleAcceptInvitation)
		}
	}
	// Self-service account overview. Mounted with a user directory (the
	// profile is its core); byte-identical without one.
	if s.userProvider != nil {
		s.router.GET(PathMe, s.handleMe)
		s.router.PATCH(PathMe, s.handlePatchMe)
	}
	// Self-service password change. Mounted only with a password credential
	// store; byte-identical without one.
	if s.passwordCredentialStore != nil {
		s.router.POST(PathMyPassword, s.handleChangeMyPassword)
	}
}

// mountSelfServiceCredentials registers the authenticated /me* credential +
// privacy endpoints (MFA factors, passkey registration, GDPR export/erasure,
// verified email change), gated on both their backing store and the
// SelfService feature gate. The public per-host branding lookup used to live
// here too; it moved to mountBrandingEndpoint (gated by WebSPA instead — it
// serves the hosted login SPA, not an authenticated self-service action).
func (s *Server) mountSelfServiceCredentials() {
	if !s.selfServiceGateOn() {
		return
	}
	// Self-service MFA factor management. Mounted only with an enrollment
	// store; byte-identical without one.
	if s.mfaEnrollmentStore != nil {
		s.router.GET(PathMyMFA, s.handleMyMFAFactors)
		s.router.DELETE(PathMyMFAByID, s.handleDeleteMyMFAFactor)
		// Self-service TOTP enrollment (the write-half). Mounted only when the
		// enrollment store can persist a TOTP factor AND a TOTP enroller is
		// wired to verify the confirm code — byte-identical otherwise.
		if _, ok := s.mfaEnrollmentStore.(TOTPEnrollmentWriter); ok && s.totpEnroller != nil {
			s.router.POST(PathMyMFATOTPBegin, s.handleTOTPEnrollBegin)
			s.router.POST(PathMyMFATOTPConfirm, s.handleTOTPEnrollConfirm)
		}
	}
	// Self-service MFA recovery codes (regenerate + remaining count); byte-identical without a store.
	if s.recoveryCodeStore != nil {
		s.router.POST(PathMyMFARecoveryCodes, s.handleGenerateRecoveryCodes)
		s.router.GET(PathMyMFARecoveryCodes, s.handleGetRecoveryCodesCount)
	}
	s.mountTrustedDeviceRoutes()
	// Self-service passkey registration (authenticated, bearer-bound). Mounts
	// independently of the enrollment store: the registered credential lands in
	// the WebAuthn store the Registrar wraps and surfaces in /me/mfa via the
	// WebAuthn adapter. Byte-identical when no registrar is wired.
	if s.webauthnRegistrar != nil {
		s.router.POST(PathMyWebAuthnRegisterBegin, s.handleMyWebAuthnRegisterBegin)
		s.router.POST(PathMyWebAuthnRegisterFinish, s.handleMyWebAuthnRegisterFinish)
	}
	// GDPR Art. 15 self-service data export of the bearer's own data.
	if s.dataExporter != nil {
		s.router.GET(PathMyDataExport, s.handleMyDataExport)
	}
	// GDPR Art. 17 self-service account erasure (opt-in, irreversible).
	if s.accountEraser != nil {
		s.router.POST(PathMyAccountErase, s.handleMyAccountErase)
	}
	// Verified email change. Needs the token store + sender (deliver to the new
	// address) + a UserProvider (commit the new email). Byte-identical without.
	if s.emailChangeStore != nil && s.emailChangeSender != nil && s.userProvider != nil {
		s.router.POST(PathMyEmailChange, s.handleMyEmailChange)
		s.router.POST(PathMyEmailVerify, s.handleMyEmailVerify)
	}
}

// mountBrandingEndpoint registers the public per-host branding lookup the
// hosted login SPA consumes. Mounted whenever a tenant store is wired
// (Domain.Branding is its source) — byte-identical to a build without one.
// Reachability is gated LIVE by the WebSPA flag via core.GatedRouter (NOT
// a bare core.GateHandler wrap around the handler): this route is
// registered on s.router, which also carries global middleware added via
// Use() (Tracing) BEFORE Mount() reaches this call — only GatedRouter's
// route-matching-level gate (StdRoute.live) prevents that middleware
// from running on a gated-off request; a handler-only wrap would still
// let it stamp response headers before the wrapped handler's own check
// ever ran. Hot-toggles with the rest of the WebSPA surface
// (server_routes.go's buildProbeMux) instead of needing a re-Mount.
func (s *Server) mountBrandingEndpoint() {
	if s.tenantStore != nil {
		core.NewGatedRouter(s.router, s.webSPAGateOn).GET(PathBranding, s.handleBranding)
	}
}

// WithTrustedDeviceStore wires the "remember this device" MFA-skip store. It
// mounts the self-service surface GET /me/devices (list), POST
// /me/devices/trust (mark the CURRENT device trusted — gated on the
// caller's bearer token having completed MFA THIS session, i.e. its amr
// contains "mfa"), and DELETE /me/devices/:id (revoke one) — and it arms the
// /auth/login step-up-skip check: when the configured RiskScorer demands
// DecisionRequireMFA, a request presenting a live grant
// (login.Request.DeviceToken) for the SAME (user, client) pair skips the
// challenge.
//
// ttl bounds how long a single grant stays valid; pass 0 to inherit
// [core.DefaultTrustedDeviceTTL] (30 days). There is no renew-on-use, so a
// forgotten device decays on its own rather than staying trusted forever.
// When nil (the default), neither the self-service routes nor the
// login-time skip are active — byte-identical to a build without this
// feature. Relocated from options_passwd.go (which was at the line budget).
func WithTrustedDeviceStore(store TrustedDeviceStore, ttl time.Duration) Option {
	return func(srv *Server) {
		srv.trustedDeviceStore = store
		if ttl > 0 {
			srv.trustedDeviceTTL = ttl
		}
	}
}
