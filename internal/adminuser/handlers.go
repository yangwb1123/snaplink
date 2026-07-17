package adminuser

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// HTTP handler functions for the admin user CRUD API. These are pure functions
// that take a Deps interface and a core.HandlerContext — the same pattern as
// the existing admin handlers in interfaces/admin/. They live in the
// internal/adminuser package (alongside the business logic) rather than in
// interfaces/admin/ to keep that directory within the per-directory go-file
// fanout budget.
//
// All handlers are registered under /api/v1/admin/local-users* and gated by
// AdminMiddleware (admin:read for GET, admin:write for POST/PUT/DELETE).
// Thin wrappers in interfaces/sso/server_admin_handlers.go delegate here.

// HandleAdminCreateUser serves POST /api/v1/admin/local-users.
// admin:write. Creates a new user with username, email, display_name, and
// password. Returns 201 with the created user (password NEVER included).
// Returns 409 on username/email conflict, 400 on validation failure.
func HandleAdminCreateUser(d Deps, ctx core.HandlerContext) {
	tokenNoStoreHeaders(ctx)

	var req CreateUserRequest
	if err := oauth.BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	user, err := CreateUser(ctx.Request().Context(), d, &req)
	if err != nil {
		if errors.Is(err, core.ErrUserExists) {
			ctx.JSON(http.StatusConflict, core.ErrorBody(core.ErrUserConflict))
			return
		}
		if isValidationError(err) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
		d.Logger().Error("admin create user failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	recordAdminUserCRUDAction(d, ctx, audit.EventAdminUserCreated, user.ID, "username", user.Username)
	ctx.JSON(http.StatusCreated, userToCRUDResponse(user))
}

// HandleAdminGetUser serves GET /api/v1/admin/local-users/:id.
// admin:read. Returns the user (password NEVER included). Returns 404 when
// the user is not found.
func HandleAdminGetUser(d Deps, ctx core.HandlerContext) {
	tokenNoStoreHeaders(ctx)

	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	resp, err := GetUser(ctx.Request().Context(), d, userID)
	if err != nil {
		if errors.Is(err, core.ErrNoSuchUser) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin get user failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

// HandleAdminUpdateUser serves PUT /api/v1/admin/local-users/:id.
// admin:write. Updates mutable user fields (email, display_name). Username
// and password are NOT modifiable through this path. Returns 404 when the
// user is not found, 409 on email conflict, 400 on validation failure.
func HandleAdminUpdateUser(d Deps, ctx core.HandlerContext) {
	tokenNoStoreHeaders(ctx)

	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	var req UpdateUserRequest
	if err := oauth.BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	resp, err := UpdateUser(ctx.Request().Context(), d, userID, &req)
	if err != nil {
		if errors.Is(err, core.ErrNoSuchUser) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		if errors.Is(err, core.ErrUserExists) {
			ctx.JSON(http.StatusConflict, core.ErrorBody(core.ErrUserConflict))
			return
		}
		if isValidationError(err) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
		d.Logger().Error("admin update user failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	recordAdminUserCRUDAction(d, ctx, audit.EventAdminUserUpdated, userID, "", "")
	ctx.JSON(http.StatusOK, resp)
}

// HandleAdminDeleteUser serves DELETE /api/v1/admin/local-users/:id.
// admin:write. Deletes the user (and best-effort their password credential).
// Returns 204 No Content regardless of whether the user existed (idempotent).
func HandleAdminDeleteUser(d Deps, ctx core.HandlerContext) {
	tokenNoStoreHeaders(ctx)

	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	if err := DeleteUser(ctx.Request().Context(), d, userID); err != nil {
		d.Logger().Error("admin delete user failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	recordAdminUserCRUDAction(d, ctx, audit.EventAdminUserDeleted, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleAdminListUsers serves GET /api/v1/admin/local-users.
// admin:read. Returns a paginated list of users. Query params: page (default
// 1), limit (default 10, max 100). Returns 400 on invalid pagination params.
func HandleAdminListUsers(d Deps, ctx core.HandlerContext) {
	tokenNoStoreHeaders(ctx)

	pageStr := ctx.Query("page")
	limitStr := ctx.Query("limit")

	page := 1
	limit := 10

	if pageStr != "" {
		var err error
		page, err = strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
	}
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 100 {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
	}

	resp, err := ListUsers(ctx.Request().Context(), d, page, limit)
	if err != nil {
		d.Logger().Error("admin list users failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

// tokenNoStoreHeaders sets Cache-Control: no-store + Pragma: no-cache on the
// response. Used for credential endpoints to prevent sensitive data caching.
func tokenNoStoreHeaders(ctx core.HandlerContext) {
	ctx.ResponseWriter().Header().Set("Cache-Control", "no-store")
	ctx.ResponseWriter().Header().Set("Pragma", "no-cache")
}

// userToCRUDResponse converts a core.User to a safe API response map.
func userToCRUDResponse(u *core.User) map[string]any {
	if u == nil {
		return map[string]any{}
	}
	return map[string]any{
		"id":           u.ID,
		"username":     u.Username,
		"email":        u.Email,
		"name":         u.Name,
		"display_name": u.DisplayName,
		"external_id":  u.ExternalID,
		"provider":     u.Provider,
		"attributes":   u.Attributes,
		"created_at":   u.CreatedAt,
		"updated_at":   u.UpdatedAt,
	}
}

// isValidationError returns true when err is one of the known validation errors.
func isValidationError(err error) bool {
	return errors.Is(err, ErrValidationUsernameFormat) ||
		errors.Is(err, ErrValidationUsernameLength) ||
		errors.Is(err, ErrValidationEmailFormat) ||
		errors.Is(err, ErrValidationPassword)
}

// recordAdminUserCRUDAction emits an admin user CRUD audit event with the
// actor identity extracted from the request context via d.ActorFromContext().
// No-op when no Auditor is wired.
func recordAdminUserCRUDAction(d Deps, ctx core.HandlerContext, evtType audit.EventType, targetUser, metaKey, metaVal string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	actor, _, _ := d.ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{
		Type:    evtType,
		Outcome: audit.OutcomeSuccess,
		ActorID: actor,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "target_user", targetUser)
	if metaKey != "" {
		audit.SetMeta(evt, metaKey, metaVal)
	}
	aud.Record(ctx.Request().Context(), evt)
}
