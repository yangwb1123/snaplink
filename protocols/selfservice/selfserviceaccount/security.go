package selfserviceaccount

import (
	"encoding/json"
	"net/http"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/selfservice/selfservicecore"
	"github.com/yangwb1123/snaplink/shared/core"
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
	if !validateNewPassword(d, ctx, userID, req.NewPassword) {
		return
	}
	if err := d.PasswordCredentialStore().SetPassword(ctx.Request().Context(), userID, req.NewPassword); err != nil {
		d.Logger().Error("set password failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordPasswordHistory(d, ctx, userID, req.NewPassword)
	// A changed password is the strongest account-compromise-adjacent signal
	// this handler sees: a trusted-device grant minted under the OLD password
	// must not silently outlive it. Shared with the "sign out everywhere" /
	// "revoke all sessions" self-service call sites (sessions.go) and
	// /token/revoke-all — see selfservicecore.RevokeTrustedDevicesOnCompromiseSignal.
	selfservicecore.RevokeTrustedDevicesOnCompromiseSignal(d, ctx, userID, "password_change")
	recordPasswordChanged(d, ctx, userID)
	ctx.JSON(http.StatusNoContent, nil)
}

func recordPasswordChanged(d Deps, ctx core.HandlerContext, userID string) {
	if d.Auditor() == nil {
		return
	}
	event := &audit.Event{Type: audit.EventPasswordChanged, Outcome: audit.OutcomeSuccess,
		ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
	d.Auditor().Record(ctx.Request().Context(), event)
}

// validateNewPassword runs the wired complexity-policy check followed by the
// wired history check (cheap static check first, store round-trip second).
// Returns true when the password is acceptable or neither is configured;
// writes the 400 response on rejection either way.
func validateNewPassword(d Deps, ctx core.HandlerContext, userID, password string) bool {
	if v := d.PasswordPolicyValidator(); v != nil {
		if err := v.ValidatePassword(ctx.Request().Context(), password); err != nil {
			ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrPasswordPolicyViolation))
			return false
		}
	}
	return checkPasswordHistory(d, ctx, userID, password)
}

// checkPasswordHistory rejects a new password that matches userID's recent
// password history, when a history store is wired. Fails OPEN on a store
// error (logged) — an outage must not block an otherwise-legitimate change.
func checkPasswordHistory(d Deps, ctx core.HandlerContext, userID, password string) bool {
	store := d.PasswordHistoryStore()
	if store == nil {
		return true
	}
	reused, err := store.CheckHistory(ctx.Request().Context(), userID, password)
	if err != nil {
		d.Logger().Error("password history check failed", "user_id", userID, "error", err)
		return true
	}
	if reused {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrPasswordPolicyViolation))
		return false
	}
	return true
}

// recordPasswordHistory best-effort records the just-set password so a
// future change can detect reuse. Non-fatal: the password change already
// succeeded, so a history-store write failure is logged, not surfaced.
func recordPasswordHistory(d Deps, ctx core.HandlerContext, userID, password string) {
	store := d.PasswordHistoryStore()
	if store == nil {
		return
	}
	if err := store.Record(ctx.Request().Context(), userID, password); err != nil {
		d.Logger().Error("password history record failed", "user_id", userID, "error", err)
	}
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
