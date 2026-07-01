package sso

import (
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// handleAdminListTokens returns the active admin bearer tokens.
func (s *Server) handleAdminListTokens(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNotFound))
		return
	}
	// Optional query param ?admin_id= to filter by issuing admin.
	adminID := ctx.Query("admin_id")
	tokens, err := s.adminTokenStore.List(ctx.Request().Context(), adminID)
	if err != nil {
		s.logger.Error("admin list tokens failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus: StatusOK,
		"tokens":  tokens,
	})
}

// handleAdminRevokeToken revokes a single admin bearer token by ID.
func (s *Server) handleAdminRevokeToken(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNotFound))
		return
	}
	tokenID := ctx.Param("id")
	if tokenID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if err := s.adminTokenStore.Revoke(ctx.Request().Context(), tokenID); err != nil {
		s.logger.Error("admin revoke token failed", "id", tokenID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusOK})
}

// handleAdminLogout revokes the admin bearer token used in the current
// request. The token is validated and its jti (matching AdminToken.ID)
// is used to revoke it. On success the caller should discard the token.
func (s *Server) handleAdminLogout(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNotFound))
		return
	}
	token := bearerToken(ctx.Request())
	if token == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(core.ErrUnauthorized))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), token)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(core.ErrInvalidToken))
		return
	}
	if claims.JTI == "" {
		s.logger.Error("admin logout: token has no jti")
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.adminTokenStore.Revoke(ctx.Request().Context(), claims.JTI); err != nil {
		s.logger.Error("admin logout revoke failed", "jti", claims.JTI, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: "logged_out"})
}
