package commercehttp

import (
	"net/http"
	"strings"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

type createSubscriptionRequest struct {
	ID                     string    `json:"id"`
	TenantID               string    `json:"tenant_id,omitempty"`
	PlanID                 string    `json:"plan_id"`
	PlanVersion            uint64    `json:"plan_version"`
	TrialEnd               time.Time `json:"trial_end,omitempty"`
	Provider               string    `json:"provider,omitempty"`
	ProviderSubscriptionID string    `json:"provider_subscription_id,omitempty"`
}

type transitionSubscriptionRequest struct {
	Status           string `json:"status"`
	ExpectedRevision uint64 `json:"expected_revision,omitempty"`
}

type changePlanRequest struct {
	PlanID           string `json:"plan_id"`
	PlanVersion      uint64 `json:"plan_version"`
	ExpectedRevision uint64 `json:"expected_revision,omitempty"`
}

type renewSubscriptionRequest struct {
	ExpectedRevision uint64 `json:"expected_revision,omitempty"`
}

func (a *API) HandleListSubscriptions(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	if tenantID == "" {
		writeInvalidRequest(ctx)
		return
	}
	subscriptions, err := a.deps.Queries.ListSubscriptionsByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	if subscriptions == nil {
		subscriptions = []*tenantcommerce.Subscription{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyTenantID: tenantID, responseSubscriptions: subscriptions, responseTotal: len(subscriptions),
	})
}

func (a *API) HandleCreateSubscription(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	var request createSubscriptionRequest
	if tenantID == "" || oauth.BindParams(ctx, &request) != nil ||
		!tenantMatchesPath(tenantID, request.TenantID) || !validPlanRef(request.PlanID, request.PlanVersion) {
		a.invalidMutation(ctx, operationSubscriptionCreate, tenantID, resourceSubscription, request.ID)
		return
	}
	command := tenantcommerce.CreateSubscriptionCommand{
		ID: request.ID, TenantID: tenantID,
		Plan:     tenantcommerce.PlanRef{ID: request.PlanID, Version: request.PlanVersion},
		TrialEnd: request.TrialEnd, Provider: request.Provider,
		ProviderSubscriptionID: request.ProviderSubscriptionID,
	}
	subscription, entitlement, err := a.deps.Commands.CreateSubscription(ctx.Request().Context(), command)
	if err != nil {
		a.failMutation(ctx, operationSubscriptionCreate, tenantID, resourceSubscription, request.ID, err)
		return
	}
	a.successfulMutation(ctx, operationSubscriptionCreate, tenantID, resourceSubscription, subscription.ID)
	writeSubscriptionResult(ctx, http.StatusCreated, subscription, entitlement)
}

func (a *API) HandleTransitionSubscription(ctx core.HandlerContext) {
	privateNoStore(ctx)
	id := strings.TrimSpace(ctx.Param("id"))
	var request transitionSubscriptionRequest
	if id == "" || oauth.BindParams(ctx, &request) != nil || !validSubscriptionStatus(request.Status) {
		a.invalidMutation(ctx, operationSubscriptionStatus, "", resourceSubscription, id)
		return
	}
	command := tenantcommerce.TransitionSubscriptionCommand{
		SubscriptionID: id, To: tenantcommerce.SubscriptionStatus(request.Status),
		ExpectedRevision: request.ExpectedRevision,
	}
	subscription, entitlement, err := a.deps.Commands.TransitionSubscription(ctx.Request().Context(), command)
	if err != nil {
		a.failMutation(ctx, operationSubscriptionStatus, "", resourceSubscription, id, err)
		return
	}
	a.successfulMutation(ctx, operationSubscriptionStatus, subscription.TenantID, resourceSubscription, id)
	writeSubscriptionResult(ctx, http.StatusOK, subscription, entitlement)
}

func (a *API) HandleChangePlan(ctx core.HandlerContext) {
	privateNoStore(ctx)
	id := strings.TrimSpace(ctx.Param("id"))
	var request changePlanRequest
	if id == "" || oauth.BindParams(ctx, &request) != nil || !validPlanRef(request.PlanID, request.PlanVersion) {
		a.invalidMutation(ctx, operationSubscriptionPlan, "", resourceSubscription, id)
		return
	}
	command := tenantcommerce.ChangePlanCommand{
		SubscriptionID: id, Plan: tenantcommerce.PlanRef{ID: request.PlanID, Version: request.PlanVersion},
		ExpectedRevision: request.ExpectedRevision,
	}
	subscription, entitlement, err := a.deps.Commands.ChangePlan(ctx.Request().Context(), command)
	if err != nil {
		a.failMutation(ctx, operationSubscriptionPlan, "", resourceSubscription, id, err)
		return
	}
	a.successfulMutation(ctx, operationSubscriptionPlan, subscription.TenantID, resourceSubscription, id)
	writeSubscriptionResult(ctx, http.StatusOK, subscription, entitlement)
}

func (a *API) HandleRenewSubscription(ctx core.HandlerContext) {
	privateNoStore(ctx)
	id := strings.TrimSpace(ctx.Param("id"))
	var request renewSubscriptionRequest
	if id == "" || oauth.BindParams(ctx, &request) != nil {
		a.invalidMutation(ctx, operationSubscriptionRenew, "", resourceSubscription, id)
		return
	}
	command := tenantcommerce.RenewSubscriptionCommand{
		SubscriptionID: id, ExpectedRevision: request.ExpectedRevision,
	}
	subscription, entitlement, err := a.deps.Commands.RenewSubscription(ctx.Request().Context(), command)
	if err != nil {
		a.failMutation(ctx, operationSubscriptionRenew, "", resourceSubscription, id, err)
		return
	}
	a.successfulMutation(ctx, operationSubscriptionRenew, subscription.TenantID, resourceSubscription, id)
	writeSubscriptionResult(ctx, http.StatusOK, subscription, entitlement)
}

func (a *API) HandleCurrentEntitlement(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	if tenantID == "" {
		writeInvalidRequest(ctx)
		return
	}
	entitlement, err := a.deps.Queries.CurrentEntitlement(ctx.Request().Context(), tenantID)
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{responseEntitlement: entitlement})
}

func writeSubscriptionResult(
	ctx core.HandlerContext, status int, subscription *tenantcommerce.Subscription,
	entitlement *tenantcommerce.EntitlementSnapshot,
) {
	ctx.JSON(status, map[string]any{
		responseSubscription: subscription, responseEntitlement: entitlement,
	})
}

func validPlanRef(id string, version uint64) bool {
	return strings.TrimSpace(id) != "" && version > 0
}

func tenantMatchesPath(pathTenantID, bodyTenantID string) bool {
	bodyTenantID = strings.TrimSpace(bodyTenantID)
	return bodyTenantID == "" || bodyTenantID == pathTenantID
}

func validSubscriptionStatus(status string) bool {
	switch tenantcommerce.SubscriptionStatus(status) {
	case tenantcommerce.SubscriptionPending, tenantcommerce.SubscriptionTrialing,
		tenantcommerce.SubscriptionActive, tenantcommerce.SubscriptionPastDue,
		tenantcommerce.SubscriptionPaused, tenantcommerce.SubscriptionCanceled,
		tenantcommerce.SubscriptionExpired:
		return true
	default:
		return false
	}
}
