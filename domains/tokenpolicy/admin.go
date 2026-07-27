package tokenpolicy

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HandleAdminPolicies serves GET /api/v1/admin/token-policies — the active
// token-policy governance view. Admin gating (admin:read) is the caller's
// responsibility (the /api/v1/admin/ prefix middleware).
//
// The response lists every active [Policy] verbatim. Policies carry NO
// secret material (only client/scope selectors and numeric limits), so there
// is nothing to redact — this is a pure governance read: "what token limits
// are in force on this replica".
func HandleAdminPolicies(store Store, log spi.Logger, ctx core.HandlerContext) {
	policies, err := store.Policies(ctx.Request().Context())
	if err != nil {
		log.Error("token policy list failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if policies == nil {
		policies = []Policy{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		"policies":     policies,
		"total":        len(policies),
	})
}
