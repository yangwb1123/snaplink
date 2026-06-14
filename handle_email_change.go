package sso

import (
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
)

// handleMyEmailChange serves POST /me/email/change — the first leg of a verified
// email change for the AUTHENTICATED bearer. Body: {new_email}. It mints a
// single-use token bound to (subject, new_email) and delivers it to the NEW
// address (proving the user controls it). Returns 200 {status:"sent"}. This is
// the verification flow PATCH /me deliberately routes email edits through.
// Credential-adjacent: no-store headers.
func (s *Server) handleMyEmailChange(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		NewEmail string `json:"new_email"`
	}
	newEmail := ""
	if err := bindOAuthParams(ctx, &req); err == nil {
		newEmail = strings.TrimSpace(req.NewEmail)
	}
	// A new email is required + must look like an address (minimal sanity — full
	// validation is the deliverability of the token, which only the real owner
	// receives).
	if newEmail == "" || !strings.Contains(newEmail, "@") {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()
	token, err := generateAuthCodeBytes()
	if err != nil {
		s.logger.Error("email change: mint token failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ttl := s.emailChangeTTL
	if ttl <= 0 {
		ttl = core.DefaultEmailChangeTTL
	}
	if err := s.emailChangeStore.Issue(rctx, &core.EmailChangeToken{
		Token: token, UserID: userID, NewEmail: newEmail, ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		s.logger.Error("email change: store issue failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if err := s.emailChangeSender.SendEmailChangeToken(rctx, newEmail, token); err != nil {
		s.logger.Error("email change: delivery failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if s.auditor != nil {
		evt := &audit.Event{Type: audit.EventEmailChangeRequested, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		s.auditor.Record(rctx, evt)
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "sent"})
}

// handleMyEmailVerify serves POST /me/email/verify — the second leg. Body:
// {token}. It consumes the token (single-use), checks it belongs to the
// authenticated bearer (a token delivered to a new address can only be
// completed by the user who started the change), and commits the new email via
// the UserProvider. Oracle-safe: unknown/expired/consumed token, or a token
// for a different user, ALL collapse to one email_change_invalid (400).
func (s *Server) handleMyEmailVerify(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.Token == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrEmailChangeInvalid))
		return
	}
	rctx := ctx.Request().Context()
	tok, err := s.emailChangeStore.Consume(rctx, req.Token)
	if err != nil || tok.UserID != userID {
		// Unknown/expired/consumed, or someone else's token — one response.
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrEmailChangeInvalid))
		return
	}
	u, err := s.userProvider.GetByID(rctx, userID)
	if err != nil || u == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrEmailChangeInvalid))
		return
	}
	u.Email = tok.NewEmail
	if err := s.userProvider.CreateOrUpdate(rctx, u); err != nil {
		s.logger.Error("email change: commit failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if s.auditor != nil {
		evt := &audit.Event{Type: audit.EventEmailChanged, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		s.auditor.Record(rctx, evt)
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok", "email": tok.NewEmail})
}
