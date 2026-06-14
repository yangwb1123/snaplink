package sso

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
)

// handleForgotPassword serves POST /auth/forgot-password — the UNAUTHENTICATED
// first leg of account recovery. Body: {identifier}. It resolves the identifier
// to a user, mints a single-use reset token, and delivers it out-of-band.
//
// ANTI-ENUMERATION (§4): it ALWAYS returns 200 {status:"sent"} — a malformed
// body, an unknown identifier, a user with no delivery address, a store error,
// and a delivery failure are INDISTINGUISHABLE on the wire. The only signal is
// server-side (log level + the delivery_ok audit metadata). The token is never
// logged, audited, or returned. Credential-adjacent: no-store headers.
func (s *Server) handleForgotPassword(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	var req struct {
		Identifier string `json:"identifier"`
	}
	// A bad body is not surfaced — it collapses to the same 200 as everything else.
	_ = bindOAuthParams(ctx, &req)
	deliveryOK := s.initiatePasswordReset(ctx, req.Identifier)
	s.recordPasswordResetRequested(ctx, deliveryOK)
	ctx.JSON(http.StatusOK, map[string]any{"status": "sent"})
}

// initiatePasswordReset runs resolve -> deliver-target -> mint -> issue ->
// send, returning whether delivery succeeded. EVERY failure path returns false;
// the caller 200s regardless (anti-enumeration). Operator-side causes are
// logged, never surfaced.
func (s *Server) initiatePasswordReset(ctx HandlerContext, identifier string) bool {
	if identifier == "" || s.passwordResetResolver == nil || s.passwordResetSender == nil || s.passwordResetDeliveryResolver == nil {
		return false
	}
	rctx := ctx.Request().Context()
	userID, err := s.passwordResetResolver(rctx, identifier)
	if err != nil || userID == "" {
		return false
	}
	target, err := s.passwordResetDeliveryResolver(rctx, userID)
	if err != nil || target == "" {
		return false
	}
	token, err := generateAuthCodeBytes()
	if err != nil {
		s.logger.Error("password reset: mint token failed", "error", err)
		return false
	}
	ttl := s.passwordResetTTL
	if ttl <= 0 {
		ttl = core.DefaultPasswordResetTTL
	}
	if err := s.passwordResetStore.Issue(rctx, &core.PasswordResetToken{
		Token: token, UserID: userID, ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		s.logger.Error("password reset: store issue failed", "error", err)
		return false
	}
	if err := s.passwordResetSender.SendResetToken(rctx, target, token); err != nil {
		// The token is already stored; it expires naturally. The user can retry.
		s.logger.Error("password reset: delivery failed", "error", err)
		return false
	}
	return true
}

// handleResetPassword serves POST /auth/reset-password — the second leg. Body:
// {token, new_password}. It CONSUMES the token (single-use, before setting the
// password so a race or a later failure can't replay it), then sets the new
// password and best-effort revokes the user's existing sessions (a reset is the
// moment to lock out an attacker). Oracle-safe: unknown/expired/consumed token,
// a user gone after consume, and a SetPassword error ALL collapse to one
// reset_invalid (400) — the cause lives only in the audit event. no-store headers.
func (s *Server) handleResetPassword(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.Token == "" || req.NewPassword == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrResetInvalid))
		return
	}
	rctx := ctx.Request().Context()
	rt, err := s.passwordResetStore.Consume(rctx, req.Token)
	if err != nil {
		// Unknown / expired / already-consumed / store error — one response.
		s.recordPasswordResetFailed(ctx, "consume_failed")
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrResetInvalid))
		return
	}
	if s.userProvider != nil {
		if _, uerr := s.userProvider.GetByID(rctx, rt.UserID); uerr != nil {
			s.recordPasswordResetFailed(ctx, "user_not_found")
			ctx.JSON(http.StatusBadRequest, errorBody(core.ErrResetInvalid))
			return
		}
	}
	if err := s.passwordCredentialStore.SetPassword(rctx, rt.UserID, req.NewPassword); err != nil {
		// Token already consumed; the user must request another reset. We return
		// the SAME reset_invalid (not 500) so an attacker can't distinguish a
		// server error from a bad token by status code.
		s.logger.Error("password reset: set password failed", "user_id", rt.UserID, "error", err)
		s.recordPasswordResetFailed(ctx, "set_password_failed")
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrResetInvalid))
		return
	}
	revoked := s.revokeUserSessionsBestEffort(ctx, rt.UserID)
	s.recordPasswordResetCompleted(ctx, rt.UserID, revoked)
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

// revokeUserSessionsBestEffort destroys all of userID's sessions after a reset
// so an attacker holding a live session under the old credential is cut off.
// Fail-open (logs, never fails the reset). Returns whether revocation ran.
func (s *Server) revokeUserSessionsBestEffort(ctx HandlerContext, userID string) bool {
	if s.sessionMgr == nil {
		return false
	}
	rctx := ctx.Request().Context()
	sessions, err := s.sessionMgr.ListByUser(rctx, userID)
	if err != nil {
		s.logger.Error("password reset: list sessions failed", "user_id", userID, "error", err)
		return false
	}
	for _, sess := range sessions {
		if derr := s.sessionMgr.Destroy(rctx, sess.ID); derr != nil {
			s.logger.Error("password reset: destroy session failed", "session_id", sess.ID, "error", derr)
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

func (s *Server) recordPasswordResetRequested(ctx HandlerContext, deliveryOK bool) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventPasswordResetRequested,
		Outcome: audit.OutcomeSuccess,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "delivery_ok", passwordResetBoolStr(deliveryOK))
	s.auditor.Record(ctx.Request().Context(), evt)
}

func (s *Server) recordPasswordResetCompleted(ctx HandlerContext, userID string, revoked bool) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventPasswordResetCompleted,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "sessions_revoked", passwordResetBoolStr(revoked))
	s.auditor.Record(ctx.Request().Context(), evt)
}

func (s *Server) recordPasswordResetFailed(ctx HandlerContext, reason string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventPasswordResetFailed,
		Outcome: audit.OutcomeFailure,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "reason", reason)
	s.auditor.Record(ctx.Request().Context(), evt)
}
