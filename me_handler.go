package sso

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/tenant"
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
func (s *Server) handleChangeMyPassword(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	// bindOAuthParams accepts form-urlencoded + JSON (the §2 binder), unlike a
	// JSON-only decode. An empty current_password is rejected here so an
	// omitted field can never count as proof of the current credential (which
	// would otherwise pass against an empty-password account).
	if err := bindOAuthParams(ctx, &req); err != nil || req.NewPassword == "" || req.CurrentPassword == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if err := s.passwordCredentialStore.VerifyPassword(ctx.Request().Context(), userID, req.CurrentPassword); err != nil {
		// Wrong current password (or no credential): one response either way.
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidPassword))
		return
	}
	if err := s.passwordCredentialStore.SetPassword(ctx.Request().Context(), userID, req.NewPassword); err != nil {
		s.logger.Error("set password failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// handleMyMFAFactors serves GET /me/mfa — lists the authenticated user's
// registered second factors (non-sensitive metadata only). Credential-adjacent;
// same cache headers as /userinfo.
func (s *Server) handleMyMFAFactors(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if factors == nil {
		factors = []core.MFAEnrolledFactor{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"factors": factors})
}

// handleDeleteMyMFAFactor serves DELETE /me/mfa/:id — unbinds one of the
// authenticated user's own factors. A factor belonging to another user (or a
// missing id) responds with the same 404 (oracle-safe: ownership is enforced
// via the user-scoped list, so a cross-user delete can never remove someone
// else's factor).
func (s *Server) handleDeleteMyMFAFactor(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	factorID := ctx.Param("id")
	if factorID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if !slices.ContainsFunc(factors, func(f core.MFAEnrolledFactor) bool { return f.ID == factorID }) {
		// Not owned by this user, or never existed — one response either way.
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if err := s.mfaEnrollmentStore.RemoveFactor(ctx.Request().Context(), userID, factorID); err != nil {
		s.logger.Error("remove mfa factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// handleTOTPEnrollBegin serves POST /me/mfa/totp/begin — the first leg of
// self-service TOTP enrollment. It mints a fresh secret and returns it (base32)
// plus an otpauth:// URI the SPA renders as a QR code. The secret is NOT
// persisted here: the flow is stateless, and the client returns it to the
// confirm leg alongside a code proving possession. Round-tripping the secret is
// safe because it only ever becomes a second factor for the caller's OWN
// authenticated account — no cross-user exposure. Credential-adjacent headers.
func (s *Server) handleTOTPEnrollBegin(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	if s.totpEnroller == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrTOTPEnrollmentNotSupported))
		return
	}
	secret, err := s.totpEnroller.GenerateSecret()
	if err != nil {
		s.logger.Error("totp enroll: generate secret failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"secret":      s.totpEnroller.EncodeSecret(secret),
		"otpauth_uri": s.totpEnroller.OTPAuthURI(s.resolveIssuer(ctx), userID, secret),
	})
}

// handleTOTPEnrollConfirm serves POST /me/mfa/totp/confirm — the second leg.
// Body: {secret, code, label?}. It verifies code against the supplied secret
// (proof of possession), then persists the secret + records the factor via the
// TOTPEnrollmentWriter so the factor is immediately usable at login AND listed
// by GET /me/mfa. Oracle-safe: a malformed secret and a wrong code collapse to
// one totp_invalid_code response; the operator-side cause lives only in the
// mfa_totp_enroll_failed audit event. Credential-adjacent headers.
func (s *Server) handleTOTPEnrollConfirm(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	writer, ok := s.mfaEnrollmentStore.(TOTPEnrollmentWriter)
	if !ok || s.totpEnroller == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrTOTPEnrollmentNotSupported))
		return
	}
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
		Label  string `json:"label"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.Secret == "" || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	secret, err := s.totpEnroller.DecodeSecret(req.Secret)
	if err != nil || !s.totpEnroller.VerifyCode(secret, req.Code) {
		// Bad secret encoding and wrong code collapse to one response.
		s.recordTOTPEnrollFailure(ctx, userID, "invalid_code")
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrTOTPInvalidCode))
		return
	}
	factorID, err := newMFAChallengeID()
	if err != nil {
		s.logger.Error("totp enroll: mint factor id failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "Authenticator app"
	}
	if err := writer.AddTOTPFactor(ctx.Request().Context(), userID, factorID, label, secret); err != nil {
		s.logger.Error("totp enroll: persist factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordTOTPEnrollSuccess(ctx, userID, factorID)
	ctx.JSON(http.StatusCreated, map[string]any{"factor_id": factorID, "label": label})
}

// recordTOTPEnrollSuccess / recordTOTPEnrollFailure emit the enrollment audit
// events. The secret is NEVER recorded; only the opaque factor_id (success) or
// the operator-side reason (failure, never returned to the caller).
func (s *Server) recordTOTPEnrollSuccess(ctx HandlerContext, userID, factorID string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventTOTPEnrolled,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "factor_id", factorID)
	s.auditor.Record(ctx.Request().Context(), evt)
}

func (s *Server) recordTOTPEnrollFailure(ctx HandlerContext, userID, reason string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventTOTPEnrollFailed,
		Outcome: audit.OutcomeFailure,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "reason", reason)
	s.auditor.Record(ctx.Request().Context(), evt)
}

// handleMyWebAuthnRegisterBegin serves POST /me/mfa/webauthn/begin — the first
// leg of AUTHENTICATED self-service passkey registration. The registration user
// is the BEARER SUBJECT (never request input), so the resulting credential can
// only bind to the caller's own account. Body: optional {display_name}. Returns
// {session_id, options} — the client passes options to navigator.credentials.create
// and returns session_id to the finish leg. Credential-adjacent headers.
func (s *Server) handleMyWebAuthnRegisterBegin(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	if s.webauthnRegistrar == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	// display_name is optional; an empty/missing body is fine (ignore bind error).
	_ = bindOAuthParams(ctx, &req)
	opts, sessionID, err := s.webauthnRegistrar.BeginRegistration(ctx.Request().Context(), userID, req.DisplayName)
	if err != nil {
		s.logger.Error("webauthn register begin failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"session_id": sessionID, "options": json.RawMessage(opts)})
}

// handleMyWebAuthnRegisterFinish serves POST /me/mfa/webauthn/finish?session_id=
// — verifies the attestation and commits the passkey, which then appears in
// GET /me/mfa. The session (from begin) determines the owning user, so the
// credential binds to the subject that began the ceremony; a valid bearer is
// still required so an unauthenticated caller can't drive finish. Failures
// collapse to one webauthn_registration_failed (cause in logs). Returns
// {credential_id}.
func (s *Server) handleMyWebAuthnRegisterFinish(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	if s.webauthnRegistrar == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	sessionID := ctx.Query("session_id")
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	credID, err := s.webauthnRegistrar.FinishRegistration(ctx.Request().Context(), sessionID, ctx.Request())
	if err != nil {
		s.logger.Error("webauthn register finish failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrWebAuthnRegistration))
		return
	}
	ctx.JSON(http.StatusCreated, map[string]any{"credential_id": credID})
}

// handleMySessions serves GET /sessions/me — lists the authenticated user's
// own active sessions. Session data is credential-adjacent so we apply the
// same cache-prevention headers as /token and /userinfo.
func (s *Server) handleMySessions(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list sessions failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if sessions == nil {
		sessions = []*core.Session{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"sessions": sessions})
}

// handleDeleteMySession serves DELETE /sessions/me/:id — lets a user revoke
// one of their own sessions. Sessions belonging to other users respond with
// the same 404 as a missing session (oracle-safe: don't reveal that a
// session exists but belongs to someone else).
func (s *Server) handleDeleteMySession(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	sessionID := ctx.Param("id")
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	sess, err := s.sessionMgr.Get(ctx.Request().Context(), sessionID)
	if err != nil || sess.UserID != userID {
		// Collapse not-found and wrong-user into one 404 (oracle-safe).
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if err := s.sessionMgr.Destroy(ctx.Request().Context(), sessionID); err != nil {
		s.logger.Error("destroy session failed", "session_id", sessionID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// handleRevokeMySessions serves DELETE /sessions/me — "sign out everywhere".
// By default it revokes every active session of the authenticated user EXCEPT
// the one the caller is currently using (identified by the bearer token's SID
// claim), matching the near-universal "sign out of all other devices" UX so
// the user is not kicked out of the very portal issuing the request. Pass
// ?all=true to revoke the current session too (a full sign-out). When the
// token carries no SID (e.g. a stateless service token with no server-managed
// session), there is nothing to preserve and every session is revoked.
//
// Scope mirrors single-session revoke (DELETE /sessions/me/:id): it destroys
// sessions only. Bulk refresh-token revocation remains the OAuth-token concern
// of /token/revoke-all. Credential-adjacent, so the same no-store headers.
func (s *Server) handleRevokeMySessions(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	claims, ok := s.meClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), claims.Subject)
	if err != nil {
		s.logger.Error("list sessions failed", "user_id", claims.Subject, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	keepCurrent := claims.SID != "" && ctx.Query("all") != "true"
	revoked := 0
	for _, sess := range sessions {
		if keepCurrent && sess.ID == claims.SID {
			continue
		}
		if err := s.sessionMgr.Destroy(ctx.Request().Context(), sess.ID); err != nil {
			s.logger.Error("destroy session failed", "session_id", sess.ID, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
			return
		}
		revoked++
	}
	ctx.JSON(http.StatusOK, map[string]any{"revoked": revoked})
}

// handleMyConsents serves GET /consents/me — lists the authenticated user's
// consent grants. Credential-adjacent; same cache headers as /userinfo.
func (s *Server) handleMyConsents(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	grants, err := s.consentStore.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list consents failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if grants == nil {
		grants = []core.ConsentGrant{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"consents": grants})
}

// handleDeleteMyConsent serves DELETE /consents/me/:client_id — revokes the
// authenticated user's consent grant for a given client. Idempotent per the
// ConsentStore contract; a missing grant returns 404.
func (s *Server) handleDeleteMyConsent(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	clientID := ctx.Param("client_id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if _, err := s.consentStore.GetConsent(ctx.Request().Context(), userID, clientID); err != nil {
		if errors.Is(err, core.ErrNoConsentGrant) {
			ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
			return
		}
		s.logger.Error("get consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if err := s.consentStore.RevokeConsent(ctx.Request().Context(), userID, clientID); err != nil {
		s.logger.Error("revoke consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordConsentEvent(ctx, audit.EventConsentRevoked, audit.OutcomeSuccess, userID, clientID, nil)
	ctx.JSON(http.StatusNoContent, nil)
}
