package threataction

import (
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// Query parameter and response key constants for the threat-policy admin API.
const (
	paramPolicyName = ":name"

	keyPolicies = "policies"
	keyPolicy   = "policy"
	keyTotal    = "total"
)

// HandleAdminListPolicies serves GET /api/v1/admin/threat-policies — lists
// every configured threat policy. Admin-gated (admin:read) by the caller.
func HandleAdminListPolicies(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	policies, err := store.List(ctx.Request().Context())
	if err != nil {
		log.Error("threat policy list failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if policies == nil {
		policies = []ThreatPolicy{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		keyPolicies:    policies,
		keyTotal:       len(policies),
	})
}

// HandleAdminGetPolicy serves GET /api/v1/admin/threat-policies/:name —
// returns a single policy. Admin-gated (admin:read) by the caller.
func HandleAdminGetPolicy(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	name := ctx.Param(paramPolicyName)
	policy, err := store.Get(ctx.Request().Context(), name)
	if err != nil {
		if err == ErrPolicyNotFound {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		log.Error("threat policy get failed", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		keyPolicy:      policy,
	})
}

// HandleAdminPutPolicy serves PUT /api/v1/admin/threat-policies/:name —
// creates or updates a threat policy. Admin-gated (admin:write) by the caller.
func HandleAdminPutPolicy(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	name := ctx.Param(paramPolicyName)
	var policy ThreatPolicy
	if err := json.NewDecoder(ctx.Request().Body).Decode(&policy); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	policy.Name = name
	if err := store.Put(ctx.Request().Context(), policy); err != nil {
		log.Error("threat policy put failed", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		keyPolicy:      policy,
	})
}

// HandleAdminDeletePolicy serves DELETE /api/v1/admin/threat-policies/:name —
// deletes a threat policy. Admin-gated (admin:write) by the caller.
func HandleAdminDeletePolicy(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	name := ctx.Param(paramPolicyName)
	if err := store.Delete(ctx.Request().Context(), name); err != nil {
		if err == ErrPolicyNotFound {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		log.Error("threat policy delete failed", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
	})
}
