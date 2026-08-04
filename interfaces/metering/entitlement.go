package meteringhttp

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

func (a *API) HandleEntitlement(ctx core.HandlerContext) {
	privateNoStore(ctx)
	binding, ok := currentBinding(ctx)
	if !ok {
		return
	}
	if !emptyRequestBody(ctx) || len(ctx.Request().URL.Query()) != 0 {
		writeMachineError(ctx, http.StatusBadRequest, core.ErrInvalidRequest)
		return
	}
	entitlement, err := a.deps.Entitlements.CurrentEntitlement(
		ctx.Request().Context(), binding.TenantID,
	)
	if err != nil {
		writeMappedError(ctx, err)
		return
	}
	if !a.recheckSource(ctx, binding) {
		return
	}
	if entitlement == nil || entitlement.TenantID != binding.TenantID {
		writeMachineError(ctx, http.StatusServiceUnavailable, ErrorUnavailable)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{responseEntitlement: entitlement})
}
