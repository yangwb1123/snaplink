package commercehttp

// Commerce management paths are full paths so the same registrar can mount
// them on Snaplink's root router or on a dedicated billing-service router.
const (
	PathPlans               = "/api/v1/admin/commerce/plans"
	PathTenantSubscriptions = "/api/v1/admin/commerce/tenants/:tenant_id/subscriptions"
	PathSubscriptionStatus  = "/api/v1/admin/commerce/subscriptions/:id/status"
	PathSubscriptionPlan    = "/api/v1/admin/commerce/subscriptions/:id/plan"
	PathSubscriptionRenew   = "/api/v1/admin/commerce/subscriptions/:id/renew"
	PathTenantEntitlement   = "/api/v1/admin/commerce/tenants/:tenant_id/entitlement"
	PathTenantWallet        = "/api/v1/admin/commerce/tenants/:tenant_id/wallet"
	PathTenantLedger        = "/api/v1/admin/commerce/tenants/:tenant_id/wallet/entries"
	PathTenantAdjustment    = "/api/v1/admin/commerce/tenants/:tenant_id/wallet/adjustments"
	PathTenantPaymentOrders = "/api/v1/admin/commerce/tenants/:tenant_id/payments/orders"
	PathTenantPaymentOrder  = "/api/v1/admin/commerce/tenants/:tenant_id/payments/orders/:order_id"
	PathTenantPaymentEvents = "/api/v1/admin/commerce/tenants/:tenant_id/payments/orders/:order_id/events"
	PathTenantReconcile     = "/api/v1/admin/commerce/tenants/:tenant_id/payments/reconcile"
	PathPaymentOrderRead    = "/api/v1/commerce/tenants/:tenant_id/payments/orders/:order_id"
	PathPaymentEventIngest  = "/api/v1/commerce/tenants/:tenant_id/payments/orders/:order_id/events"
)

const (
	ScopeAdminRead        = "admin:read"
	ScopeAdminWrite       = "admin:write"
	ScopePaymentOrderRead = "billing:payment:order:read"
	ScopePaymentWrite     = "billing:payment:write"
	ScopeCheckoutCreate   = "billing:checkout:create"
)

const (
	ErrorInvalidPlan          = "commerce_invalid_plan"
	ErrorInvalidMoney         = "commerce_invalid_money"
	ErrorPlanNotFound         = "commerce_plan_not_found"
	ErrorPlanConflict         = "commerce_plan_conflict"
	ErrorPlanRetired          = "commerce_plan_retired"
	ErrorInvalidSubscription  = "commerce_invalid_subscription"
	ErrorSubscriptionNotFound = "commerce_subscription_not_found"
	ErrorEntitlementNotFound  = "commerce_entitlement_not_found"
	ErrorTenantSubscribed     = "commerce_tenant_subscribed"
	ErrorTransitionDenied     = "commerce_transition_denied"
	ErrorRevisionConflict     = "commerce_revision_conflict"
	ErrorInvalidLedgerEntry   = "commerce_invalid_ledger_entry"
	ErrorInsufficientFunds    = "commerce_insufficient_funds"
	ErrorWalletOverflow       = "commerce_wallet_overflow"
	ErrorWalletFrozen         = "commerce_wallet_frozen"
	ErrorIdempotencyConflict  = "commerce_idempotency_conflict"
	ErrorInvalidPayment       = "commerce_invalid_payment"
	ErrorPaymentNotFound      = "commerce_payment_not_found"
	ErrorPaymentEventNotFound = "commerce_payment_event_not_found"
	ErrorPaymentStateConflict = "commerce_payment_state_conflict"
	ErrorUnavailable          = "commerce_unavailable"
	ErrorInsufficientScope    = "insufficient_scope"
)

const (
	headerCacheControl  = "Cache-Control"
	headerPragma        = "Pragma"
	headerIdempotency   = "Idempotency-Key"
	headerAuthenticate  = "WWW-Authenticate"
	cacheControlNoStore = "no-store"
	pragmaNoCache       = "no-cache"
	billingRealm        = "billing"
	defaultLedgerLimit  = 100
	maximumLedgerLimit  = 1000
)

const (
	responsePlans         = "plans"
	responseSubscriptions = "subscriptions"
	responseEntitlement   = "entitlement"
	responseSubscription  = "subscription"
	responseWallet        = "wallet"
	responseEntries       = "entries"
	responseEntry         = "entry"
	responseTotal         = "total"
	responseOrders        = "orders"
	responseOrder         = "order"
	responseEvents        = "events"
	responseReport        = "report"
)
