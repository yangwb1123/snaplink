package sso

import (
	"net/http"
	"slices"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
)
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
