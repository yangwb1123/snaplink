package selfservice

import (
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// HandleForgotPassword serves POST /auth/forgot-password — the UNAUTHENTICATED
// first leg of account recovery. Body: {identifier}. It resolves the identifier
// to a user, mints a single-use reset token, and delivers it out-of-band.
//
// ANTI-ENUMERATION (§4): it ALWAYS returns 200 {status:"sent"} — a malformed
// body, an unknown identifier, a user with no delivery address, a store error,
// and a delivery failure are INDISTINGUISHABLE on the wire. The only signal is
// server-side (log level + the delivery_ok audit metadata). The token is never
// logged, audited, or returned. Credential-adjacent: no-store headers.
func HandleForgotPassword(d Deps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	var req struct {
		Identifier string `json:"identifier"`
	}
	// A bad body is not surfaced — it collapses to the same 200 as everything else.
	_ = oauth.BindParams(ctx, &req)
	deliveryOK := initiatePasswordReset(d, ctx, req.Identifier)
	recordPasswordResetRequested(d, ctx, deliveryOK)
	ctx.JSON(http.StatusOK, map[string]any{"status": "sent"})
}

// initiatePasswordReset runs resolve -> deliver-target -> mint -> issue ->
// send, returning whether delivery succeeded. EVERY failure path returns false;
// the caller 200s regardless (anti-enumeration). Operator-side causes are
// logged, never surfaced.
func initiatePasswordReset(d Deps, ctx core.HandlerContext, identifier string) bool {
	resolver := d.PasswordResetResolver()
	sender := d.PasswordResetSender()
	deliveryResolver := d.PasswordResetDeliveryResolver()

	if identifier == "" || resolver == nil || sender == nil || deliveryResolver == nil {
		return false
	}
	rctx := ctx.Request().Context()
	userID, err := resolver(rctx, identifier)
	if err != nil || userID == "" {
		return false
	}
	target, err := deliveryResolver(rctx, userID)
	if err != nil || target == "" {
		return false
	}
	token, err := d.GenerateAuthCodeBytes()
	if err != nil {
		d.Logger().Error("password reset: mint token failed", "error", err)
		return false
	}
	ttl := d.PasswordResetTTL()
	if ttl <= 0 {
		ttl = core.DefaultPasswordResetTTL
	}
	if err := d.PasswordResetStore().Issue(rctx, &core.PasswordResetToken{
		Token: token, UserID: userID, ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		d.Logger().Error("password reset: store issue failed", "error", err)
		return false
	}
	if err := sender.SendResetToken(rctx, target, token); err != nil {
		// The token is already stored; it expires naturally. The user can retry.
		d.Logger().Error("password reset: delivery failed", "error", err)
		return false
	}
	return true
}

// HandleResetPassword serves POST /auth/reset-password — the second leg. Body:
// {token, new_password}. It CONSUMES the token (single-use, before setting the
// password so a race or a later failure can't replay it), then sets the new
// password and best-effort revokes the user's existing sessions (a reset is the
// moment to lock out an attacker). Oracle-safe: unknown/expired/consumed token,
// a user gone after consume, and a SetPassword error ALL collapse to one
// reset_invalid (400) — the cause lives only in the audit event. no-store headers.
func HandleResetPassword(d Deps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || req.Token == "" || req.NewPassword == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrResetInvalid))
		return
	}
	rctx := ctx.Request().Context()
	rt, err := d.PasswordResetStore().Consume(rctx, req.Token)
	if err != nil {
		// Unknown / expired / already-consumed / store error — one response.
		recordPasswordResetFailed(d, ctx, "consume_failed")
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrResetInvalid))
		return
	}
	if d.UserProvider() != nil {
		if _, uerr := d.UserProvider().GetByID(rctx, rt.UserID); uerr != nil {
			recordPasswordResetFailed(d, ctx, "user_not_found")
			ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrResetInvalid))
			return
		}
	}
	// Validate the new password against the policy before setting it.
	if !checkPasswordPolicy(d, rctx, ctx, req.NewPassword) {
		return
	}
	if !checkPasswordHistory(d, rctx, ctx, rt.UserID, req.NewPassword) {
		return
	}
	if err := d.PasswordCredentialStore().SetPassword(rctx, rt.UserID, req.NewPassword); err != nil {
		// Token already consumed; the user must request another reset. We return
		// the SAME reset_invalid (not 500) so an attacker can't distinguish a
		// server error from a bad token by status code.
		d.Logger().Error("password reset: set password failed", "user_id", rt.UserID, "error", err)
		recordPasswordResetFailed(d, ctx, "set_password_failed")
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrResetInvalid))
		return
	}
	recordPasswordHistory(d, rctx, rt.UserID, req.NewPassword)
	revoked := revokeUserSessionsBestEffort(d, ctx, rt.UserID)
	recordPasswordResetCompleted(d, ctx, rt.UserID, revoked)
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

// revokeUserSessionsBestEffort destroys all of userID's sessions after a reset
// so an attacker holding a live session under the old credential is cut off.
// Fail-open (logs, never fails the reset). Returns whether revocation ran.
func revokeUserSessionsBestEffort(d Deps, ctx core.HandlerContext, userID string) bool {
	if d.SessionManager() == nil {
		return false
	}
	rctx := ctx.Request().Context()
	sessions, err := d.SessionManager().ListByUser(rctx, userID)
	if err != nil {
		d.Logger().Error("password reset: list sessions failed", "user_id", userID, "error", err)
		return false
	}
	for _, sess := range sessions {
		if derr := d.SessionManager().Destroy(rctx, sess.ID); derr != nil {
			d.Logger().Error("password reset: destroy session failed", "session_id", sess.ID, "error", derr)
		}
	}
	return true
}

func passwordResetBoolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func recordPasswordResetRequested(d Deps, ctx core.HandlerContext, deliveryOK bool) {
	if d.Auditor() == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventPasswordResetRequested,
		Outcome: audit.OutcomeSuccess,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "delivery_ok", passwordResetBoolStr(deliveryOK))
	d.Auditor().Record(ctx.Request().Context(), evt)
}

func recordPasswordResetCompleted(d Deps, ctx core.HandlerContext, userID string, revoked bool) {
	if d.Auditor() == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventPasswordResetCompleted,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "sessions_revoked", passwordResetBoolStr(revoked))
	d.Auditor().Record(ctx.Request().Context(), evt)
}

func recordPasswordResetFailed(d Deps, ctx core.HandlerContext, reason string) {
	if d.Auditor() == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventPasswordResetFailed,
		Outcome: audit.OutcomeFailure,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "reason", reason)
	d.Auditor().Record(ctx.Request().Context(), evt)
}
