package selfservice

import (
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// HandleMySessions serves GET /sessions/me — lists the authenticated user's
// active sessions. Credential-adjacent; no-store headers.
func HandleMySessions(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	sessions, err := d.SessionManager().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list sessions failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if sessions == nil {
		sessions = []*core.Session{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"sessions": sessions})
}

// HandleDeleteMySession serves DELETE /sessions/me/:id — lets a user revoke
// one of their own sessions. Sessions belonging to other users respond with
// the same 404 as a missing session (oracle-safe: don't reveal that a
// session exists but belongs to someone else).
func HandleDeleteMySession(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	sessionID := ctx.Param("id")
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	sess, err := d.SessionManager().Get(ctx.Request().Context(), sessionID)
	if err != nil || sess.UserID != userID {
		// Collapse not-found and wrong-user into one 404 (oracle-safe).
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	if err := d.SessionManager().Destroy(ctx.Request().Context(), sessionID); err != nil {
		d.Logger().Error("destroy session failed", "session_id", sessionID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleRevokeMySessions serves DELETE /sessions/me — "sign out everywhere".
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
func HandleRevokeMySessions(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	sessions, err := d.SessionManager().ListByUser(ctx.Request().Context(), claims.Subject)
	if err != nil {
		d.Logger().Error("list sessions failed", "user_id", claims.Subject, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	keepCurrent := claims.SID != "" && ctx.Query("all") != "true"
	revoked := 0
	for _, sess := range sessions {
		if keepCurrent && sess.ID == claims.SID {
			continue
		}
		if err := d.SessionManager().Destroy(ctx.Request().Context(), sess.ID); err != nil {
			d.Logger().Error("destroy session failed", "session_id", sess.ID, "error", err)
			ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
			return
		}
		revoked++
	}
	ctx.JSON(http.StatusOK, map[string]any{"revoked": revoked})
}
