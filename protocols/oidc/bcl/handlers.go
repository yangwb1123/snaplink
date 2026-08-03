package bcl

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/shared/core"
)

func HandleList(manager AdminManager, ctx core.HandlerContext) {
	limit, _ := strconv.Atoi(ctx.Query("limit"))
	entries, err := manager.ListFailures(ctx.Request().Context(), handlerTenant(ctx), limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"failures": entries, "total": len(entries)})
}

func HandleReplay(manager AdminManager, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest})
		return
	}
	entry, err := manager.ReplayFailure(ctx.Request().Context(), id, handlerTenant(ctx))
	switch {
	case errors.Is(err, ErrNotFound):
		ctx.JSON(http.StatusNotFound, map[string]string{core.KeyError: core.ErrBCLFailureNotFound})
	case errors.Is(err, ErrLeaseUnavailable):
		ctx.JSON(http.StatusConflict, map[string]string{core.KeyError: core.ErrBCLReplayInProgress})
	case errors.Is(err, ErrReplayCleanup):
		ctx.JSON(http.StatusMultiStatus, map[string]any{"failure": entry, "delivery_status": "delivered", "cleanup_status": "pending"})
	case err != nil:
		ctx.JSON(http.StatusBadGateway, map[string]any{"failure": entry, core.KeyError: core.ErrBCLDeliveryFailed})
	default:
		ctx.JSON(http.StatusOK, map[string]any{"failure": entry, "delivery_status": "delivered", "cleanup_status": "complete"})
	}
}

func HandleReplayDue(manager AdminManager, ctx core.HandlerContext) {
	limit, _ := strconv.Atoi(ctx.Query("limit"))
	summary, err := manager.ReplayDue(ctx.Request().Context(), handlerTenant(ctx), limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": core.StatusOK, "replay": summary})
}

func handlerTenant(ctx core.HandlerContext) string {
	resolved, ok := tenant.FromHandlerContext(ctx)
	if !ok || resolved == nil || resolved.Tenant == nil {
		return ""
	}
	return resolved.Tenant.ID
}
