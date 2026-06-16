package sso

import (
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/core"
)

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
