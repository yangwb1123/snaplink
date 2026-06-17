package sso

import (
	"net/http"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
)

// handleSelfRegister serves POST /auth/register — the opt-in UNAUTHENTICATED
// self-service signup. Body: {username, password, email?}. It creates the
// account and sets the password, reusing the wired UserProvider +
// PasswordCredentialStore. The username becomes the userID (the same identity
// assumption the default forgot-password resolver makes).
//
// NEVER overwrites an existing account: it pre-checks GetByID and rejects a
// taken username with 409 account_exists (CreateOrUpdate is an upsert, so the
// guard is essential). The check is safe against takeover — an attacker can't
// pass it for an existing victim (GetByID returns the victim → 409); the only
// race is two concurrent NEW signups of the same fresh username (benign; the
// loser retries). Rate-limited by the standard middleware. no-store headers.
func (s *Server) handleSelfRegister(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()
	if existing, err := s.userProvider.GetByID(rctx, username); err == nil && existing != nil {
		// Username taken — signup must not overwrite. (Operators who treat the
		// username as PII/email and want anti-enumeration should front this.)
		s.recordSelfRegister(ctx, username, false)
		ctx.JSON(http.StatusConflict, errorBody(core.ErrAccountExists))
		return
	}
	if err := s.userProvider.CreateOrUpdate(rctx, &core.User{ID: username, Email: strings.TrimSpace(req.Email)}); err != nil {
		s.logger.Error("signup: create user failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if err := s.passwordCredentialStore.SetPassword(rctx, username, req.Password); err != nil {
		// Roll back the just-created user so we don't leave a passwordless
		// orphan account (best-effort; Delete is idempotent).
		s.logger.Error("signup: set password failed, rolling back user", "username", username, "error", err)
		if derr := s.userProvider.Delete(rctx, username); derr != nil {
			s.logger.Error("signup: rollback delete failed", "username", username, "error", derr)
		}
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordSelfRegister(ctx, username, true)
	ctx.JSON(http.StatusCreated, map[string]any{"status": "created", "user_id": username})
}

func (s *Server) recordSelfRegister(ctx HandlerContext, username string, ok bool) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventSelfRegistered,
		Outcome: audit.OutcomeSuccess,
		ActorID: username,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	if !ok {
		evt.Outcome = audit.OutcomeFailure
		evt.Reason = "account_exists"
	}
	s.auditor.Record(ctx.Request().Context(), evt)
}
