package commercehttp

import (
	"context"
	"errors"
	"net/http"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

type errorMapping struct {
	target error
	status int
	code   string
}

var commerceErrorMappings = []errorMapping{
	{tenantcommerce.ErrInvalidPayment, http.StatusBadRequest, ErrorInvalidPayment},
	{tenantcommerce.ErrInvalidMoney, http.StatusBadRequest, ErrorInvalidMoney},
	{tenantcommerce.ErrInvalidPlan, http.StatusBadRequest, ErrorInvalidPlan},
	{tenantcommerce.ErrInvalidSubscription, http.StatusBadRequest, ErrorInvalidSubscription},
	{tenantcommerce.ErrInvalidLedgerEntry, http.StatusBadRequest, ErrorInvalidLedgerEntry},
	{tenantcommerce.ErrPlanNotFound, http.StatusNotFound, ErrorPlanNotFound},
	{tenantcommerce.ErrSubscriptionNotFound, http.StatusNotFound, ErrorSubscriptionNotFound},
	{tenantcommerce.ErrEntitlementNotFound, http.StatusNotFound, ErrorEntitlementNotFound},
	{tenantcommerce.ErrPlanConflict, http.StatusConflict, ErrorPlanConflict},
	{tenantcommerce.ErrPlanRetired, http.StatusConflict, ErrorPlanRetired},
	{tenantcommerce.ErrTenantSubscribed, http.StatusConflict, ErrorTenantSubscribed},
	{tenantcommerce.ErrTransitionDenied, http.StatusConflict, ErrorTransitionDenied},
	{tenantcommerce.ErrRevisionConflict, http.StatusConflict, ErrorRevisionConflict},
	{tenantcommerce.ErrInsufficientFunds, http.StatusConflict, ErrorInsufficientFunds},
	{tenantcommerce.ErrWalletOverflow, http.StatusConflict, ErrorWalletOverflow},
	{tenantcommerce.ErrWalletFrozen, http.StatusLocked, ErrorWalletFrozen},
	{tenantcommerce.ErrIdempotencyConflict, http.StatusConflict, ErrorIdempotencyConflict},
	{tenantcommerce.ErrPaymentNotFound, http.StatusNotFound, ErrorPaymentNotFound},
	{tenantcommerce.ErrPaymentEventNotFound, http.StatusNotFound, ErrorPaymentEventNotFound},
	{tenantcommerce.ErrPaymentStateConflict, http.StatusConflict, ErrorPaymentStateConflict},
	{tenantcommerce.ErrPaymentSourceUnauthorized, http.StatusForbidden, ErrorInsufficientScope},
	{context.Canceled, http.StatusServiceUnavailable, ErrorUnavailable},
	{context.DeadlineExceeded, http.StatusServiceUnavailable, ErrorUnavailable},
}

func commerceError(err error) (int, string) {
	for _, mapping := range commerceErrorMappings {
		if errors.Is(err, mapping.target) {
			return mapping.status, mapping.code
		}
	}
	return http.StatusInternalServerError, core.ErrInternal
}

func writeCommerceError(ctx core.HandlerContext, err error) {
	status, code := commerceError(err)
	ctx.JSON(status, core.ErrorBody(code))
}

func writeInvalidRequest(ctx core.HandlerContext) {
	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
}

func (a *API) failMutation(
	ctx core.HandlerContext, operation, tenantID, resourceType, resourceID string, err error,
) {
	_, code := commerceError(err)
	a.observe(ctx, MutationRecord{
		Operation: operation, TenantID: tenantID, ResourceType: resourceType,
		ResourceID: resourceID, Outcome: MutationFailed, ErrorCode: code,
	})
	writeCommerceError(ctx, err)
}

func (a *API) invalidMutation(
	ctx core.HandlerContext, operation, tenantID, resourceType, resourceID string,
) {
	a.observe(ctx, MutationRecord{
		Operation: operation, TenantID: tenantID, ResourceType: resourceType,
		ResourceID: resourceID, Outcome: MutationFailed, ErrorCode: core.ErrInvalidRequest,
	})
	writeInvalidRequest(ctx)
}

func (a *API) successfulMutation(
	ctx core.HandlerContext, operation, tenantID, resourceType, resourceID string,
) {
	a.observe(ctx, MutationRecord{
		Operation: operation, TenantID: tenantID, ResourceType: resourceType,
		ResourceID: resourceID, Outcome: MutationSucceeded,
	})
}
