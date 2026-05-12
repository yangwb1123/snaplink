package sso

import (
	"context"
	"errors"
	"net/http"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/permissions"
)

// Query parameter accepted by the /permissions/me, /menus/me, /roles/me
// endpoints to scope the lookup to a particular APP.
const QueryClientID = "client_id"

// Response keys for the permission endpoints.
const (
	KeyPermissions = "permissions"
	KeyRoles       = "roles"
	KeyMenus       = "menus"
	KeyClient      = "client_id"
)

// Error codes for the permission endpoints.
const (
	ErrPermissionProviderNotConfigured = "permission_provider_not_configured"
	ErrPermissionLookupFailed          = "permission_lookup_failed"
)

// authenticatedSubject resolves the bearer token to a user ID + client ID.
// client_id resolution: explicit query param > token audience > "".
func (s *Server) authenticatedSubject(ctx HandlerContext) (userID, clientID string, ok bool) {
	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return "", "", false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return "", "", false
	}
	clientID = ctx.Query(QueryClientID)
	if clientID == "" && len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	return claims.Subject, clientID, true
}

func (s *Server) handleMyPermissions(ctx HandlerContext) {
	userID, clientID, ok := s.authenticatedSubject(ctx)
	if !ok {
		return
	}
	if s.permissions == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrPermissionProviderNotConfigured))
		return
	}
	perms, err := s.permissions.Permissions(ctx.Request().Context(), userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("permissions lookup failed", "user", userID, "client", clientID, "error", err)
		s.recordPermissionQuery(ctx, userID, clientID, KeyPermissions, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrPermissionLookupFailed))
		return
	}
	if perms == nil {
		perms = []permissions.Permission{}
	}
	s.recordPermissionQuery(ctx, userID, clientID, KeyPermissions, true)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyClient:      clientID,
		KeyPermissions: perms,
	})
}

func (s *Server) handleMyRoles(ctx HandlerContext) {
	userID, clientID, ok := s.authenticatedSubject(ctx)
	if !ok {
		return
	}
	if s.permissions == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrPermissionProviderNotConfigured))
		return
	}
	roles, err := s.permissions.Roles(ctx.Request().Context(), userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("roles lookup failed", "user", userID, "client", clientID, "error", err)
		s.recordPermissionQuery(ctx, userID, clientID, KeyRoles, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrPermissionLookupFailed))
		return
	}
	if roles == nil {
		roles = []permissions.Role{}
	}
	s.recordPermissionQuery(ctx, userID, clientID, KeyRoles, true)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyClient: clientID,
		KeyRoles:  roles,
	})
}

func (s *Server) handleMyMenus(ctx HandlerContext) {
	userID, clientID, ok := s.authenticatedSubject(ctx)
	if !ok {
		return
	}
	if s.permissions == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrPermissionProviderNotConfigured))
		return
	}
	menus, err := s.permissions.Menus(ctx.Request().Context(), userID, clientID)
	if err != nil {
		s.logger.Error("menus lookup failed", "user", userID, "client", clientID, "error", err)
		s.recordPermissionQuery(ctx, userID, clientID, KeyMenus, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrPermissionLookupFailed))
		return
	}
	if menus == nil {
		menus = permissions.MenuTree{}
	}
	s.recordPermissionQuery(ctx, userID, clientID, KeyMenus, true)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyClient: clientID,
		KeyMenus:  menus,
	})
}

// resolvePermissionsForLogin pulls the bundle that gets embedded in a login
// response. Errors are swallowed and turned into empty slices so login never
// fails due to a permission lookup hiccup.
func (s *Server) resolvePermissionsForLogin(ctx context.Context, userID, clientID string) (
	[]permissions.Role, []permissions.Permission, permissions.MenuTree,
) {
	if s.permissions == nil {
		return nil, nil, nil
	}
	roles, err := s.permissions.Roles(ctx, userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("login embed: roles", "error", err)
	}
	perms, err := s.permissions.Permissions(ctx, userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("login embed: permissions", "error", err)
	}
	menus, err := s.permissions.Menus(ctx, userID, clientID)
	if err != nil {
		s.logger.Error("login embed: menus", "error", err)
	}
	return roles, perms, menus
}

func (s *Server) recordPermissionQuery(ctx HandlerContext, userID, clientID, kind string, ok bool) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx.Request())
	e.Type = audit.EventPermissionQuery
	e.ActorID = userID
	e.ClientID = clientID
	if ok {
		e.Outcome = audit.OutcomeSuccess
	} else {
		e.Outcome = audit.OutcomeFailure
	}
	e.Metadata = map[string]string{"kind": kind}
	s.auditor.Record(ctx.Request().Context(), e)
}
