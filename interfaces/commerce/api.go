// Package commercehttp exposes the tenant-commerce management API without
// coupling the domain to Snaplink's SSO Server. Stock deployments mount these
// full paths on the same core.Router; a dedicated billing process can mount
// them on its own router and apply the same admin bearer middleware.
package commercehttp

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	operationPlanPublish        = "plan.publish"
	operationSubscriptionCreate = "subscription.create"
	operationSubscriptionStatus = "subscription.status_change"
	operationSubscriptionPlan   = "subscription.plan_change"
	operationSubscriptionRenew  = "subscription.renew"
	operationWalletAdjustment   = "wallet.adjustment"
	operationTopUpCreate        = "payment.top_up_create"
	operationPaymentOrderRead   = "payment.order_read"
	operationPaymentReconcile   = "payment.reconcile"
	operationPaymentEventApply  = "payment.event_apply"
	resourcePlan                = "plan"
	resourceSubscription        = "subscription"
	resourceWallet              = "wallet"
	resourcePaymentOrder        = "payment_order"
)

type API struct {
	deps Deps
}

func New(deps Deps) (*API, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	return &API{deps: deps}, nil
}

// RouteContract makes the authorization boundary machine-readable. Snaplink's
// AdminMiddleware already enforces these full paths by HTTP method; standalone
// services must apply an equivalent bearer gate before serving the router.
type RouteContract struct {
	Method        string
	Path          string
	RequiredScope string
}

func RouteContracts() []RouteContract {
	return []RouteContract{
		{http.MethodGet, PathPlans, ScopeAdminRead},
		{http.MethodPost, PathPlans, ScopeAdminWrite},
		{http.MethodGet, PathTenantSubscriptions, ScopeAdminRead},
		{http.MethodPost, PathTenantSubscriptions, ScopeAdminWrite},
		{http.MethodPatch, PathSubscriptionStatus, ScopeAdminWrite},
		{http.MethodPatch, PathSubscriptionPlan, ScopeAdminWrite},
		{http.MethodPost, PathSubscriptionRenew, ScopeAdminWrite},
		{http.MethodGet, PathTenantEntitlement, ScopeAdminRead},
		{http.MethodGet, PathTenantWallet, ScopeAdminRead},
		{http.MethodGet, PathTenantLedger, ScopeAdminRead},
		{http.MethodPost, PathTenantAdjustment, ScopeAdminWrite},
		{http.MethodGet, PathTenantPaymentOrders, ScopeAdminRead},
		{http.MethodPost, PathTenantPaymentOrders, ScopeAdminWrite},
		{http.MethodGet, PathTenantPaymentOrder, ScopeAdminRead},
		{http.MethodGet, PathTenantPaymentEvents, ScopeAdminRead},
		{http.MethodPost, PathTenantReconcile, ScopeAdminWrite},
		{http.MethodGet, PathPaymentOrderRead, ScopePaymentOrderRead},
		{http.MethodPost, PathPaymentEventIngest, ScopePaymentWrite},
	}
}

// RegisterRoutes mounts the complete management surface on a core.Router.
// Authorization remains an upstream concern so the same handlers compose with
// Snaplink's AdminMiddleware and with an external policy gateway.
func (a *API) RegisterRoutes(router core.Router) error {
	if router == nil {
		return ErrRouterRequired
	}
	router.GET(PathPlans, a.HandleListPlans)
	router.POST(PathPlans, a.HandlePublishPlan)
	router.GET(PathTenantSubscriptions, a.HandleListSubscriptions)
	router.POST(PathTenantSubscriptions, a.HandleCreateSubscription)
	router.PATCH(PathSubscriptionStatus, a.HandleTransitionSubscription)
	router.PATCH(PathSubscriptionPlan, a.HandleChangePlan)
	router.POST(PathSubscriptionRenew, a.HandleRenewSubscription)
	router.GET(PathTenantEntitlement, a.HandleCurrentEntitlement)
	router.GET(PathTenantWallet, a.HandleGetWallet)
	router.GET(PathTenantLedger, a.HandleListLedgerEntries)
	router.POST(PathTenantAdjustment, a.HandlePostAdjustment)
	router.GET(PathTenantPaymentOrders, a.HandleListPaymentOrders)
	router.POST(PathTenantPaymentOrders, a.HandleCreateTopUpOrder)
	router.GET(PathTenantPaymentOrder, a.HandleGetPaymentOrder)
	router.GET(PathTenantPaymentEvents, a.HandleListPaymentEvents)
	router.POST(PathTenantReconcile, a.HandleReconcilePayments)
	return nil
}

// Mount is the one-call constructor used by composition roots.
func Mount(router core.Router, deps Deps) (*API, error) {
	api, err := New(deps)
	if err != nil {
		return nil, err
	}
	if err := api.RegisterRoutes(router); err != nil {
		return nil, err
	}
	return api, nil
}

func privateNoStore(ctx core.HandlerContext) {
	headers := ctx.ResponseWriter().Header()
	headers.Set(headerCacheControl, cacheControlNoStore)
	headers.Set(headerPragma, pragmaNoCache)
}

func (a *API) observe(ctx core.HandlerContext, record MutationRecord) {
	if a.deps.Observer != nil {
		a.deps.Observer.ObserveCommerceMutation(ctx.Request().Context(), record)
	}
}
