package sso

import (
	"errors"
	"net/http"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
)

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
