package commercehttp

import (
	"net/http"
	"strconv"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

func (a *API) HandleListPlans(ctx core.HandlerContext) {
	privateNoStore(ctx)
	plans, err := a.deps.Queries.ListPlans(ctx.Request().Context())
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	if plans == nil {
		plans = []*tenantcommerce.Plan{}
	}
	ctx.JSON(http.StatusOK, map[string]any{responsePlans: plans, responseTotal: len(plans)})
}

func (a *API) HandlePublishPlan(ctx core.HandlerContext) {
	privateNoStore(ctx)
	var plan tenantcommerce.Plan
	if err := oauth.BindParams(ctx, &plan); err != nil {
		a.invalidMutation(ctx, operationPlanPublish, "", resourcePlan, "")
		return
	}
	resourceID := planResourceID(plan.ID, plan.Version)
	if err := a.deps.Commands.PublishPlan(ctx.Request().Context(), &plan); err != nil {
		a.failMutation(ctx, operationPlanPublish, "", resourcePlan, resourceID, err)
		return
	}
	a.successfulMutation(ctx, operationPlanPublish, "", resourcePlan, resourceID)
	persisted, err := a.deps.Queries.GetPlan(ctx.Request().Context(), plan.ID, plan.Version)
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	ctx.JSON(http.StatusCreated, map[string]any{resourcePlan: persisted})
}

func planResourceID(id string, version uint64) string {
	if id == "" {
		return ""
	}
	return id + ":" + strconv.FormatUint(version, 10)
}
