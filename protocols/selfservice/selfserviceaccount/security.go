package selfserviceaccount

import (
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// HandleChangeMyPassword serves POST /me/password — the authenticated user
// changes their own password. Body: {current_password, new_password}. Verifies
// the current password against the credential store, then sets the new one.
//
// Credential endpoint: no-store headers. The caller is authenticated as their
// own account, so naming the wrong-current-password case (invalid_password) is
// not an enumeration leak — the user needs to know their entry was wrong. The
// store's VerifyPassword is itself anti-enumeration (dummy compare on unknown).
func HandleChangeMyPassword(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateWrite(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	userID := claims.Subject
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	// BindParams accepts form-urlencoded + JSON (the §2 binder), unlike a
	// JSON-only decode. An empty current_password is rejected here so an
	// omitted field can never count as proof of the current credential (which
	// would otherwise pass against an empty-password account).
	if err := oauth.BindParams(ctx, &req); err != nil || req.NewPassword == "" || req.CurrentPassword == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.PasswordCredentialStore().VerifyPassword(ctx.Request().Context(), userID, req.CurrentPassword); err != nil {
		// Wrong current password (or no credential): one response either way.
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidPassword))
		return
	}
	// Validate the new password against the policy before setting it.
	if v := d.PasswordPolicyValidator(); v != nil {
		if err := v.ValidatePassword(ctx.Request().Context(), req.NewPassword); err != nil {
			ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrPasswordPolicyViolation))
			return
		}
	}
	if err := d.PasswordCredentialStore().SetPassword(ctx.Request().Context(), userID, req.NewPassword); err != nil {
		d.Logger().Error("set password failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleWebAuthnRegisterBegin serves POST /me/mfa/webauthn/begin — starts an
// authenticated self-service passkey registration ceremony, returning the
// CredentialCreation options + an opaque session id. Credential-adjacent;
// no-op (501) when no registrar is wired.
func HandleWebAuthnRegisterBegin(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	reg := d.WebAuthnRegistrar()
	if reg == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrNotFound))
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	// display_name is optional; an empty/missing body is fine (ignore bind error).
	_ = oauth.BindParams(ctx, &req)
	opts, sessionID, err := reg.BeginRegistration(ctx.Request().Context(), userID, req.DisplayName)
	if err != nil {
		d.Logger().Error("webauthn register begin failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"session_id": sessionID, "options": json.RawMessage(opts)})
}

// HandleWebAuthnRegisterFinish serves POST /me/mfa/webauthn/finish?session_id=
// — verifies the attestation and commits the passkey, which then appears in
// GET /me/mfa. The session (from begin) determines the owning user, so the
// credential binds to the subject that began the ceremony; a valid bearer is
// still required so an unauthenticated caller can't drive finish. Failures
// collapse to one webauthn_registration_failed (cause in logs). Returns
// {credential_id}.
func HandleWebAuthnRegisterFinish(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	reg := d.WebAuthnRegistrar()
	if reg == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrNotFound))
		return
	}
	sessionID := ctx.Query("session_id")
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	credID, err := reg.FinishRegistration(ctx.Request().Context(), sessionID, userID, ctx.Request())
	if err != nil {
		d.Logger().Error("webauthn register finish failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrWebAuthnRegistration))
		return
	}
	ctx.JSON(http.StatusCreated, map[string]any{"credential_id": credID})
}
