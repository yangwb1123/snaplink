package sso

import (
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/domains/identitylink"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/protocols/selfservice"

	"github.com/yangwb1123/snaplink/shared/core"
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
// MFA-skip surface (GET/POST/DELETE /me/trusted-devices*) on gr, the SAME
// SelfService-gated core.GatedRouter mountSelfServiceCredentials builds — so
// this group hot-toggles with the rest of the self-service surface instead
// of needing its own gate. Byte-identical without a store wired.
func (s *Server) mountTrustedDeviceRoutes(gr Router) {
	if s.trustedDeviceStore == nil {
		return
	}
	gr.GET(PathMyTrustedDevices, s.handleMyTrustedDevices)
	gr.POST(PathMyTrustedDevicesTrust, s.handleTrustMyDevice)
	gr.DELETE(PathMyTrustedDeviceByID, s.handleRevokeMyTrustedDevice)
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

// handleMyLoginHistory delegates to selfservice.HandleMyLoginHistory.
func (s *Server) handleMyLoginHistory(ctx HandlerContext) { selfservice.HandleMyLoginHistory(s, ctx) }

// handleMySecurityActivity delegates to selfservice.HandleMySecurityActivity.
func (s *Server) handleMySecurityActivity(ctx HandlerContext) {
	selfservice.HandleMySecurityActivity(s, ctx)
}

// handleMeSessionsEnriched delegates to the enriched session listing.
func (s *Server) handleMeSessionsEnriched(ctx HandlerContext) {
	selfservice.HandleMySessionsEnriched(s, ctx)
}

// handleLoginUIMetadata serves the login UI metadata endpoint, enriched
// with geo context and provider list from the server's configuration.
func (s *Server) handleLoginUIMetadata(ctx HandlerContext) {
	selfservice.HandleLoginUIMetadata(s, ctx)
}

// handleMyDevices delegates to selfservice.HandleMyDevices.
func (s *Server) handleMyDevices(ctx HandlerContext) { selfservice.HandleMyDevices(s, ctx) }

// handleMyDeviceByID delegates to selfservice.HandleMyDeviceByID.
func (s *Server) handleMyDeviceByID(ctx HandlerContext) { selfservice.HandleMyDeviceByID(s, ctx) }

// handleDeleteMyDevice delegates to selfservice.HandleDeleteMyDevice.
func (s *Server) handleDeleteMyDevice(ctx HandlerContext) { selfservice.HandleDeleteMyDevice(s, ctx) }
func (s *Server) handleUpdateMyDevice(ctx HandlerContext) { selfservice.HandleUpdateMyDevice(s, ctx) }
func (s *Server) handleMyDeviceActivity(ctx HandlerContext) {
	selfservice.HandleMyDeviceActivity(s, ctx)
}
func (s *Server) handleMyDeviceSessions(ctx HandlerContext) {
	selfservice.HandleMyDeviceSessions(s, ctx)
}
func (s *Server) handleSetDeviceTrust(ctx HandlerContext) { selfservice.HandleSetDeviceTrust(s, ctx) }
func (s *Server) handleReportLostDevice(ctx HandlerContext) {
	selfservice.HandleReportLostDevice(s, ctx)
}

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

// mountUnauthenticatedSelfServiceRoutes registers the unauthenticated
// forgot/reset-password flow and the opt-in self-service signup/verify
// routes — called from mountCoreOAuthOIDC (server_routes.go), relocated
// here (which was at the line budget) to sit beside the rest of the
// self-service mount functions. Each route is gated on its backing store (a
// boot-time nil-check, unchanged) AND mounted through the SAME
// SelfService-gated core.GatedRouter mountSelfServiceProfile /
// mountSelfServiceCredentials use, so it hot-toggles with the rest of the
// self-service surface (SetSelfServiceGateEnabled) instead of needing its
// own gate.
func (s *Server) mountUnauthenticatedSelfServiceRoutes() {
	selfServiceGR := core.NewGatedRouter(s.router, s.selfServiceGateOn)
	// Unauthenticated forgot-password flow. Requires the reset-token store AND
	// the credential store (reset must SetPassword on success) — byte-identical
	// without both.
	if s.passwordResetStore != nil && s.passwordCredentialStore != nil {
		selfServiceGR.POST(PathForgotPassword, s.handleForgotPassword)
		selfServiceGR.POST(PathResetPassword, s.handleResetPassword)
	}
	// Opt-in self-service signup. Needs a UserProvider (create) + credential
	// store (set password). Default-off — byte-identical when not enabled.
	if s.signupEnabled && s.userProvider != nil && s.passwordCredentialStore != nil {
		// Mode B (mandatory verification) requires the store + sender; without
		// them the handler nil-derefs on EmailVerificationStore.Issue(). Suppress
		// the route rather than panic at request time.
		if !s.signupRequireVerification || (s.emailVerificationStore != nil && s.emailVerificationSender != nil) {
			selfServiceGR.POST(PathSignup, s.handleSelfRegister)
		}
		// Verification endpoint: Mode B needs store + sender (both required for
		// the register route above). Mode A opt-in (?send_verification=true) only
		// needs the store — the sender was already invoked at register time.
		// Mount whenever the store is wired so Mode A opt-in verify does not 404.
		if s.emailVerificationStore != nil {
			selfServiceGR.POST(PathVerifyEmail, s.handleVerifyEmail)
		}
	}
}

// mountSelfServiceCredentials registers the authenticated /me* credential +
// privacy endpoints (MFA factors, passkey registration, GDPR export/erasure,
// verified email change), each gated on its backing store (a boot-time
// nil-check, unchanged) and mounted UNCONDITIONALLY + gated LIVE as one
// group via core.GatedRouter (SetSelfServiceGateEnabled) instead of the
// previous single boot-time early-return. The public per-host branding
// lookup used to live here too; it moved to mountBrandingEndpoint (gated by
// WebSPA instead — it serves the hosted login SPA, not an authenticated
// self-service action).
func (s *Server) mountSelfServiceCredentials() {
	gr := core.NewGatedRouter(s.router, s.selfServiceGateOn)
	// Self-service MFA factor management. Mounted only with an enrollment
	// store; byte-identical without one.
	if s.mfaEnrollmentStore != nil {
		gr.GET(PathMyMFA, s.handleMyMFAFactors)
		gr.DELETE(PathMyMFAByID, s.handleDeleteMyMFAFactor)
		// Self-service TOTP enrollment (the write-half). Mounted only when the
		// enrollment store can persist a TOTP factor AND a TOTP enroller is
		// wired to verify the confirm code — byte-identical otherwise.
		if _, ok := s.mfaEnrollmentStore.(TOTPEnrollmentWriter); ok && s.totpEnroller != nil {
			gr.POST(PathMyMFATOTPBegin, s.handleTOTPEnrollBegin)
			gr.POST(PathMyMFATOTPConfirm, s.handleTOTPEnrollConfirm)
		}
	}
	// Self-service MFA recovery codes (regenerate + remaining count); byte-identical without a store.
	if s.recoveryCodeStore != nil {
		gr.POST(PathMyMFARecoveryCodes, s.handleGenerateRecoveryCodes)
		gr.GET(PathMyMFARecoveryCodes, s.handleGetRecoveryCodesCount)
	}
	s.mountTrustedDeviceRoutes(gr)
	// Self-service passkey registration (authenticated, bearer-bound). Mounts
	// independently of the enrollment store: the registered credential lands in
	// the WebAuthn store the Registrar wraps and surfaces in /me/mfa via the
	// WebAuthn adapter. Byte-identical when no registrar is wired.
	if s.webauthnRegistrar != nil {
		gr.POST(PathMyWebAuthnRegisterBegin, s.handleMyWebAuthnRegisterBegin)
		gr.POST(PathMyWebAuthnRegisterFinish, s.handleMyWebAuthnRegisterFinish)
	}
	// GDPR Art. 15 self-service data export of the bearer's own data.
	if s.dataExporter != nil {
		gr.GET(PathMyDataExport, s.handleMyDataExport)
	}
	// GDPR Art. 17 self-service account erasure (opt-in, irreversible).
	if s.accountEraser != nil {
		gr.POST(PathMyAccountErase, s.handleMyAccountErase)
	}
	// Verified email change. Needs the token store + sender (deliver to the new
	// address) + a UserProvider (commit the new email). Byte-identical without.
	if s.emailChangeStore != nil && s.emailChangeSender != nil && s.userProvider != nil {
		gr.POST(PathMyEmailChange, s.handleMyEmailChange)
		gr.POST(PathMyEmailVerify, s.handleMyEmailVerify)
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
// mounts the self-service surface GET /me/trusted-devices (list), POST
// /me/trusted-devices/trust (mark the CURRENT device trusted — gated on the
// caller's bearer token having completed MFA THIS session, i.e. its amr
// contains "mfa"), and DELETE /me/trusted-devices/:id (revoke one) — and it arms the
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
