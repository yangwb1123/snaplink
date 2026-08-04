package commercehttp

import (
	"errors"
	"io"
	"net/http"
	"strings"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

type createTopUpRequest struct {
	ID              string `json:"id,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	Provider        string `json:"provider"`
	ProviderOrderID string `json:"provider_order_id,omitempty"`
	Currency        string `json:"currency"`
	AmountMinor     int64  `json:"amount_minor"`
	IdempotencyKey  string `json:"idempotency_key"`
}

type reconcileRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

func (a *API) HandleCreateTopUpOrder(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	var request createTopUpRequest
	if tenantID == "" || oauth.BindParams(ctx, &request) != nil {
		a.invalidMutation(ctx, operationTopUpCreate, tenantID, resourcePaymentOrder, request.ID)
		return
	}
	if request.IdempotencyKey == "" {
		request.IdempotencyKey = strings.TrimSpace(ctx.Request().Header.Get(headerIdempotency))
	}
	if !tenantMatchesPath(tenantID, request.TenantID) {
		a.invalidMutation(ctx, operationTopUpCreate, tenantID, resourcePaymentOrder, request.ID)
		return
	}
	command := tenantcommerce.CreateTopUpCommand{
		ID: request.ID, TenantID: tenantID, Provider: request.Provider,
		ProviderOrderID: request.ProviderOrderID, Currency: request.Currency,
		AmountMinor: request.AmountMinor, IdempotencyKey: request.IdempotencyKey,
	}
	order, err := a.deps.Commands.CreateTopUpOrder(ctx.Request().Context(), command)
	if err != nil {
		a.failMutation(ctx, operationTopUpCreate, tenantID, resourcePaymentOrder, request.ID, err)
		return
	}
	a.successfulMutation(ctx, operationTopUpCreate, tenantID, resourcePaymentOrder, order.ID)
	ctx.JSON(http.StatusCreated, map[string]any{responseOrder: order})
}

func (a *API) HandleListPaymentOrders(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	if tenantID == "" {
		writeInvalidRequest(ctx)
		return
	}
	orders, err := a.deps.Queries.ListPaymentOrdersByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	if orders == nil {
		orders = []*tenantcommerce.PaymentOrder{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyTenantID: tenantID, responseOrders: orders, responseTotal: len(orders),
	})
}

func (a *API) HandleGetPaymentOrder(ctx core.HandlerContext) {
	privateNoStore(ctx)
	order, ok := a.paymentOrderForPath(ctx)
	if !ok {
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{responseOrder: order})
}

func (a *API) HandleListPaymentEvents(ctx core.HandlerContext) {
	privateNoStore(ctx)
	order, ok := a.paymentOrderForPath(ctx)
	if !ok {
		return
	}
	events, err := a.deps.Queries.ListPaymentEvents(ctx.Request().Context(), order.ID)
	if err != nil {
		writeCommerceError(ctx, err)
		return
	}
	if events == nil {
		events = []*tenantcommerce.PaymentEvent{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyTenantID: order.TenantID, "order_id": order.ID,
		responseEvents: events, responseTotal: len(events),
	})
}

func (a *API) HandleReconcilePayments(ctx core.HandlerContext) {
	privateNoStore(ctx)
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	var request reconcileRequest
	if tenantID == "" || bindOptional(ctx, &request) != nil || !tenantMatchesPath(tenantID, request.TenantID) {
		a.invalidMutation(ctx, operationPaymentReconcile, tenantID, resourcePaymentOrder, tenantID)
		return
	}
	report, err := a.deps.Queries.ReconcilePayments(ctx.Request().Context(), tenantID)
	if err != nil {
		a.failMutation(ctx, operationPaymentReconcile, tenantID, resourcePaymentOrder, tenantID, err)
		return
	}
	a.successfulMutation(ctx, operationPaymentReconcile, tenantID, resourcePaymentOrder, tenantID)
	ctx.JSON(http.StatusOK, map[string]any{responseReport: report})
}

func (a *API) paymentOrderForPath(ctx core.HandlerContext) (*tenantcommerce.PaymentOrder, bool) {
	tenantID := strings.TrimSpace(ctx.Param("tenant_id"))
	orderID := strings.TrimSpace(ctx.Param("order_id"))
	if tenantID == "" || orderID == "" {
		writeInvalidRequest(ctx)
		return nil, false
	}
	order, err := a.deps.Queries.GetPaymentOrder(ctx.Request().Context(), orderID)
	if err != nil {
		writeCommerceError(ctx, err)
		return nil, false
	}
	if order.TenantID != tenantID {
		writeCommerceError(ctx, tenantcommerce.ErrPaymentNotFound)
		return nil, false
	}
	return order, true
}

func bindOptional(ctx core.HandlerContext, target any) error {
	err := oauth.BindParams(ctx, target)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
