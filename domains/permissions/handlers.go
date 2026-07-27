package permissions

import (
	"context"
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HandlerDeps is what the /me/{permissions,roles,menus} handlers need.
// *sso.Server satisfies this via its accessor methods.
type HandlerDeps interface {
	Permissions() Provider
	SrvLogger() spi.Logger
	Auditor() *audit.Recorder
	AuthenticatedSubject(ctx core.HandlerContext) (userID, clientID string, ok bool)
}

// HandleMyPermissions implements GET /me/permissions — returns the
// authenticated subject's permission codes for the requested client.
func HandleMyPermissions(d HandlerDeps, ctx core.HandlerContext) {
	userID, clientID, ok := d.AuthenticatedSubject(ctx)
	if !ok {
		return
	}
	prov := d.Permissions()
	if prov == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: core.ErrPermissionProviderNotConfigured})
		return
	}
	perms, err := prov.Permissions(ctx.Request().Context(), userID, clientID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		d.SrvLogger().Error("permissions lookup failed", "user", userID, "client", clientID, "error", err)
		RecordQuery(d.Auditor(), ctx, userID, clientID, core.KeyPermissions, false)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrPermissionLookupFailed})
		return
	}
	if perms == nil {
		perms = []Permission{}
	}
	RecordQuery(d.Auditor(), ctx, userID, clientID, core.KeyPermissions, true)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyClient:      clientID,
		core.KeyPermissions: perms,
	})
}

// HandleMyRoles implements GET /me/roles.
func HandleMyRoles(d HandlerDeps, ctx core.HandlerContext) {
	userID, clientID, ok := d.AuthenticatedSubject(ctx)
	if !ok {
		return
	}
	prov := d.Permissions()
	if prov == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: core.ErrPermissionProviderNotConfigured})
		return
	}
	roles, err := prov.Roles(ctx.Request().Context(), userID, clientID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		d.SrvLogger().Error("roles lookup failed", "user", userID, "client", clientID, "error", err)
		RecordQuery(d.Auditor(), ctx, userID, clientID, core.KeyRoles, false)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrPermissionLookupFailed})
		return
	}
	if roles == nil {
		roles = []Role{}
	}
	RecordQuery(d.Auditor(), ctx, userID, clientID, core.KeyRoles, true)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyClient: clientID,
		core.KeyRoles:  roles,
	})
}

// HandleMyMenus implements GET /me/menus.
func HandleMyMenus(d HandlerDeps, ctx core.HandlerContext) {
	userID, clientID, ok := d.AuthenticatedSubject(ctx)
	if !ok {
		return
	}
	prov := d.Permissions()
	if prov == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: core.ErrPermissionProviderNotConfigured})
		return
	}
	menus, err := prov.Menus(ctx.Request().Context(), userID, clientID)
	if err != nil {
		d.SrvLogger().Error("menus lookup failed", "user", userID, "client", clientID, "error", err)
		RecordQuery(d.Auditor(), ctx, userID, clientID, core.KeyMenus, false)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrPermissionLookupFailed})
		return
	}
	if menus == nil {
		menus = MenuTree{}
	}
	RecordQuery(d.Auditor(), ctx, userID, clientID, core.KeyMenus, true)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyClient: clientID,
		core.KeyMenus:  menus,
	})
}

// ResolveForLogin pulls the bundle that gets embedded in a login
// response. Errors are swallowed and turned into empty slices so login
// never fails due to a permission lookup hiccup.
func ResolveForLogin(prov Provider, log spi.Logger, ctx context.Context, userID, clientID string) ([]Role, []Permission, MenuTree) {
	if prov == nil {
		return nil, nil, nil
	}
	roles, err := prov.Roles(ctx, userID, clientID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		log.Error("login embed: roles", "error", err)
	}
	perms, err := prov.Permissions(ctx, userID, clientID)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		log.Error("login embed: permissions", "error", err)
	}
	menus, err := prov.Menus(ctx, userID, clientID)
	if err != nil {
		log.Error("login embed: menus", "error", err)
	}
	return roles, perms, menus
}

// RecordQuery emits the audit event for a /me/* lookup. Safe to call
// with a nil recorder (the audit subsystem is opt-in).
func RecordQuery(rec *audit.Recorder, ctx core.HandlerContext, userID, clientID, kind string, ok bool) {
	if rec == nil {
		return
	}
	e := audit.EventFromRequest(ctx)
	e.Type = audit.EventPermissionQuery
	e.ActorID = userID
	e.ClientID = clientID
	if ok {
		e.Outcome = audit.OutcomeSuccess
	} else {
		e.Outcome = audit.OutcomeFailure
	}
	audit.SetMeta(e, "kind", kind)
	rec.Record(ctx.Request().Context(), e)
}
