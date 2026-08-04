package commercehttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestAdminTopUpOrderCreateListAndGet(t *testing.T) {
	environment := newTestEnvironment(t)
	order := createTopUpOrderHTTP(t, environment, "tenant-1", "pay-1", 1000)
	path := "/api/v1/admin/commerce/tenants/tenant-1/payments/orders"
	response := serveJSON(t, environment.router, http.MethodGet, path, nil)
	var list struct {
		Orders []*tenantcommerce.PaymentOrder `json:"orders"`
		Total  int                            `json:"total"`
	}
	decodeResponse(t, response, &list)
	if response.Code != http.StatusOK || list.Total != 1 || list.Orders[0].ID != order.ID {
		t.Fatalf("orders = %+v, status=%d", list, response.Code)
	}
	path += "/" + order.ID
	response = serveJSON(t, environment.router, http.MethodGet, path, nil)
	if response.Code != http.StatusOK || response.Header().Get(headerCacheControl) != cacheControlNoStore {
		t.Fatalf("get status=%d headers=%v", response.Code, response.Header())
	}
	crossTenant := "/api/v1/admin/commerce/tenants/tenant-2/payments/orders/" + order.ID
	response = serveJSON(t, environment.router, http.MethodGet, crossTenant, nil)
	assertErrorResponse(t, response, http.StatusNotFound, ErrorPaymentNotFound)
}

func TestTopUpOrderRejectsBodyTenantMismatch(t *testing.T) {
	environment := newTestEnvironment(t)
	path := "/api/v1/admin/commerce/tenants/tenant-1/payments/orders"
	body := topUpOrderBody("tenant-2", "pay-1", 1000)
	response := serveJSON(t, environment.router, http.MethodPost, path, body)
	assertErrorResponse(t, response, http.StatusBadRequest, core.ErrInvalidRequest)
	reconcile := "/api/v1/admin/commerce/tenants/tenant-1/payments/reconcile"
	response = serveJSON(t, environment.router, http.MethodPost, reconcile, map[string]any{"tenant_id": "tenant-2"})
	assertErrorResponse(t, response, http.StatusBadRequest, core.ErrInvalidRequest)
}

func TestNormalizedPaymentEventAndReconciliation(t *testing.T) {
	environment := newTestEnvironment(t)
	order := createTopUpOrderHTTP(t, environment, "tenant-1", "pay-1", 1000)
	registerPaymentEventRoute(t, environment)
	path := paymentEventPath("tenant-1", order.ID)
	response := serveJSON(t, environment.router, http.MethodPost, path, paymentEventBody("tenant-1", order.ID, 1000))
	var applied struct {
		Order  *tenantcommerce.PaymentOrder `json:"order"`
		Wallet *tenantcommerce.Wallet       `json:"wallet"`
	}
	decodeResponse(t, response, &applied)
	if response.Code != http.StatusOK || applied.Order.Status != tenantcommerce.PaymentSucceeded ||
		applied.Wallet.BalanceMinor != 1000 {
		t.Fatalf("payment result = %+v, status=%d", applied, response.Code)
	}
	assertPaymentEvents(t, environment, order.ID, 1)
	reconcile := "/api/v1/admin/commerce/tenants/tenant-1/payments/reconcile"
	response = serveJSON(t, environment.router, http.MethodPost, reconcile, nil)
	var report struct {
		Report *tenantcommerce.ReconciliationReport `json:"report"`
	}
	decodeResponse(t, response, &report)
	if response.Code != http.StatusOK || report.Report.OrdersChecked != 1 || len(report.Report.Issues) != 0 {
		t.Fatalf("reconciliation = %+v, status=%d", report.Report, response.Code)
	}
}

func TestPaymentEventRouteRequiresBillingScopeGate(t *testing.T) {
	environment := newTestEnvironment(t)
	unmounted := serveJSON(t, environment.router, http.MethodPost, paymentEventPath("tenant-1", "pay-1"), map[string]any{})
	if unmounted.Code != http.StatusNotFound {
		t.Fatalf("machine route without gate status = %d, want 404", unmounted.Code)
	}
	if err := environment.api.RegisterPaymentEventRoute(environment.router, nil); !errors.Is(err, ErrPaymentEventGateRequired) {
		t.Fatalf("nil gate error = %v", err)
	}
	if err := environment.api.RegisterPaymentEventRoute(environment.router, func(string) core.MiddlewareFunc {
		return nil
	}); !errors.Is(err, ErrPaymentEventGateRequired) {
		t.Fatalf("nil middleware error = %v", err)
	}
	withoutSources, err := New(Deps{Commands: environment.service, Queries: environment.store})
	if err != nil {
		t.Fatal(err)
	}
	err = withoutSources.RegisterPaymentEventRoute(core.NewStdRouter(), func(string) core.MiddlewareFunc {
		return func(core.HandlerContext) {}
	})
	if !errors.Is(err, ErrPaymentSourceRequired) {
		t.Fatalf("missing payment source resolver error = %v", err)
	}
	capturedScope := ""
	err = environment.api.RegisterPaymentEventRoute(environment.router, func(scope string) core.MiddlewareFunc {
		capturedScope = scope
		return func(ctx core.HandlerContext) {
			ctx.JSON(http.StatusForbidden, core.ErrorBody("forbidden"))
			ctx.Abort()
		}
	})
	if err != nil || capturedScope != ScopePaymentWrite {
		t.Fatalf("register err=%v scope=%q", err, capturedScope)
	}
	response := serveJSON(t, environment.router, http.MethodPost, paymentEventPath("tenant-1", "pay-1"), map[string]any{})
	assertErrorResponse(t, response, http.StatusForbidden, "forbidden")
}

func TestPaymentOrderReadRequiresBoundMachineSource(t *testing.T) {
	environment := newTestEnvironment(t)
	order := createTopUpOrderHTTP(t, environment, "tenant-1", "pay-read", 1000)
	path := paymentOrderReadPath("tenant-1", order.ID)
	if response := serveJSON(t, environment.router, http.MethodGet, path, nil); response.Code != http.StatusNotFound {
		t.Fatalf("unmounted payment read status=%d", response.Code)
	}
	registerPaymentOrderReadRoute(t, environment, "provider-client")
	response := serveJSON(t, environment.router, http.MethodGet, path, nil)
	if response.Code != http.StatusOK || response.Header().Get(headerCacheControl) != cacheControlNoStore {
		t.Fatalf("payment read status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	crossTenant := paymentOrderReadPath("tenant-2", order.ID)
	response = serveJSON(t, environment.router, http.MethodGet, crossTenant, nil)
	assertErrorResponse(t, response, http.StatusForbidden, ErrorInsufficientScope)
	challenge := response.Header().Get(headerAuthenticate)
	if !strings.Contains(challenge, ScopePaymentOrderRead) || strings.Contains(challenge, ScopePaymentWrite) {
		t.Fatalf("payment order read challenge = %q", challenge)
	}

	other, err := environment.service.CreateTopUpOrder(t.Context(), tenantcommerce.CreateTopUpCommand{
		ID: "pay-other", TenantID: "tenant-1", Provider: "other-provider", Currency: "USD",
		AmountMinor: 1000, IdempotencyKey: "topup:other",
	})
	if err != nil {
		t.Fatal(err)
	}
	response = serveJSON(t, environment.router, http.MethodGet, paymentOrderReadPath("tenant-1", other.ID), nil)
	assertErrorResponse(t, response, http.StatusNotFound, ErrorPaymentNotFound)
}

func TestPaymentOrderReadRouteRejectsMissingGateAndSources(t *testing.T) {
	environment := newTestEnvironment(t)
	if err := environment.api.RegisterPaymentOrderReadRoute(environment.router, nil); !errors.Is(err, ErrPaymentOrderGateRequired) {
		t.Fatalf("nil order gate error = %v", err)
	}
	withoutSources, err := New(Deps{Commands: environment.service, Queries: environment.store})
	if err != nil {
		t.Fatal(err)
	}
	err = withoutSources.RegisterPaymentOrderReadRoute(core.NewStdRouter(), func(string) core.MiddlewareFunc {
		return func(core.HandlerContext) {}
	})
	if !errors.Is(err, ErrPaymentSourceRequired) {
		t.Fatalf("missing order source resolver error = %v", err)
	}
}

func TestStockPaymentGateRequiresClientCredentialsIdentityAndScope(t *testing.T) {
	tests := []struct {
		name   string
		claims *rs.Claims
		status int
		code   string
	}{
		{"missing validated claims", nil, http.StatusUnauthorized, core.ErrInvalidToken},
		{"user identity", &rs.Claims{Subject: "user-1", ClientID: "adapter", Scope: ScopePaymentWrite}, http.StatusForbidden, ErrorInsufficientScope},
		{"missing scope", &rs.Claims{Subject: "adapter", ClientID: "adapter"}, http.StatusForbidden, ErrorInsufficientScope},
		{"authorized adapter", &rs.Claims{Subject: "adapter", ClientID: "adapter", Scope: ScopePaymentWrite}, 0, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, response := paymentGateContext(test.claims)
			ClientCredentialsScopeGate(ScopePaymentWrite)(ctx)
			if test.status == 0 && (ctx.Aborted() || response.Code != http.StatusOK) {
				t.Fatalf("authorized gate aborted=%v status=%d", ctx.Aborted(), response.Code)
			}
			if test.status != 0 {
				assertErrorResponse(t, response, test.status, test.code)
			}
		})
	}
}

func TestPaymentEventRejectsBindingAndStateConflicts(t *testing.T) {
	environment := newTestEnvironment(t)
	order := createTopUpOrderHTTP(t, environment, "tenant-1", "pay-1", 1000)
	registerPaymentEventRoute(t, environment)
	path := paymentEventPath("tenant-1", order.ID)
	unknownField := paymentEventBody("tenant-1", order.ID, 1000)
	unknownField["provider_signature"] = "must-stay-at-adapter"
	response := serveJSON(t, environment.router, http.MethodPost, path, unknownField)
	assertErrorResponse(t, response, http.StatusBadRequest, core.ErrInvalidRequest)
	mismatch := paymentEventBody("tenant-2", order.ID, 1000)
	response = serveJSON(t, environment.router, http.MethodPost, path, mismatch)
	assertErrorResponse(t, response, http.StatusBadRequest, core.ErrInvalidRequest)
	mismatch = paymentEventBody("tenant-1", "pay-other", 1000)
	response = serveJSON(t, environment.router, http.MethodPost, path, mismatch)
	assertErrorResponse(t, response, http.StatusBadRequest, core.ErrInvalidRequest)
	wrongProvider := paymentEventBody("tenant-1", order.ID, 1000)
	wrongProvider["provider"] = "other-provider"
	response = serveJSON(t, environment.router, http.MethodPost, path, wrongProvider)
	assertErrorResponse(t, response, http.StatusForbidden, ErrorInsufficientScope)
	if !strings.Contains(response.Header().Get(headerAuthenticate), ErrorInsufficientScope) {
		t.Fatalf("payment binding rejection challenge = %q", response.Header().Get(headerAuthenticate))
	}
	response = serveJSON(t, environment.router, http.MethodPost, path, paymentEventBody("tenant-1", order.ID, 999))
	assertErrorResponse(t, response, http.StatusConflict, ErrorPaymentStateConflict)
	missingPath := paymentEventPath("tenant-1", "pay-missing")
	response = serveJSON(t, environment.router, http.MethodPost, missingPath, paymentEventBody("tenant-1", "pay-missing", 1000))
	assertErrorResponse(t, response, http.StatusNotFound, ErrorPaymentNotFound)
}

func TestPaymentEventRejectsDisabledSourceBinding(t *testing.T) {
	environment := newTestEnvironment(t)
	order := createTopUpOrderHTTP(t, environment, "tenant-1", "pay-disabled", 1000)
	registerPaymentEventRoute(t, environment)
	disabled := *environment.paymentBinding
	disabled.Enabled = false
	disabled.Revision = 2
	disabled.UpdatedAt = commerceTestNow.Add(time.Second)
	if _, err := environment.sourceStore.SaveSourceBinding(t.Context(), &disabled, 1); err != nil {
		t.Fatal(err)
	}
	path := paymentEventPath("tenant-1", order.ID)
	response := serveJSON(t, environment.router, http.MethodPost, path, paymentEventBody("tenant-1", order.ID, 1000))
	assertErrorResponse(t, response, http.StatusForbidden, ErrorInsufficientScope)
	stored, err := environment.store.GetPaymentOrder(t.Context(), order.ID)
	if err != nil || stored.Status != tenantcommerce.PaymentPending {
		t.Fatalf("disabled binding mutated order: %+v err=%v", stored, err)
	}
}

func TestChargebackFreezesWalletForFurtherAdjustments(t *testing.T) {
	environment := newTestEnvironment(t)
	order := createTopUpOrderHTTP(t, environment, "tenant-1", "pay-1", 1000)
	registerPaymentEventRoute(t, environment)
	capture := paymentDomainEvent("capture-1", order.ID, tenantcommerce.PaymentCaptured, 1000)
	if _, _, _, err := environment.service.ApplyPaymentEvent(t.Context(), capture); err != nil {
		t.Fatal(err)
	}
	chargeback := paymentDomainEvent("chargeback-1", order.ID, tenantcommerce.PaymentChargeback, 1000)
	if _, _, _, err := environment.service.ApplyPaymentEvent(t.Context(), chargeback); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/admin/commerce/tenants/tenant-1/wallet/adjustments"
	body := map[string]any{
		"tenant_id": "tenant-1", "currency": "USD", "amount_minor": -100,
		"idempotency_key": "manual:frozen", "reference": "ticket-frozen",
	}
	response := serveJSON(t, environment.router, http.MethodPost, path, body)
	assertErrorResponse(t, response, http.StatusLocked, ErrorWalletFrozen)
	reversal := paymentEventBody("tenant-1", order.ID, 1000)
	reversal["id"] = "chargeback-reversed-1"
	reversal["type"] = string(tenantcommerce.PaymentChargebackReversed)
	response = serveJSON(t, environment.router, http.MethodPost,
		paymentEventPath("tenant-1", order.ID), reversal)
	if response.Code != http.StatusOK {
		t.Fatalf("chargeback reversal status=%d body=%s", response.Code, response.Body.String())
	}
	wallet, err := environment.store.GetWallet(t.Context(), "tenant-1", "USD")
	if err != nil || wallet.Status != tenantcommerce.WalletActive || wallet.BalanceMinor != 1000 {
		t.Fatalf("restored wallet = %+v err=%v", wallet, err)
	}
}

func createTopUpOrderHTTP(
	t *testing.T, environment *testEnvironment, tenantID, orderID string, amount int64,
) *tenantcommerce.PaymentOrder {
	t.Helper()
	path := "/api/v1/admin/commerce/tenants/" + tenantID + "/payments/orders"
	response := serveJSON(t, environment.router, http.MethodPost, path, topUpOrderBody(tenantID, orderID, amount))
	var body struct {
		Order *tenantcommerce.PaymentOrder `json:"order"`
	}
	decodeResponse(t, response, &body)
	if response.Code != http.StatusCreated {
		t.Fatalf("create top-up status=%d body=%s", response.Code, response.Body.String())
	}
	return body.Order
}

func topUpOrderBody(tenantID, orderID string, amount int64) map[string]any {
	return map[string]any{
		"id": orderID, "tenant_id": tenantID, "provider": "provider-adapter",
		"provider_order_id": "provider-order-1", "currency": "USD", "amount_minor": amount,
		"idempotency_key": "topup:" + orderID,
	}
}

func registerPaymentEventRoute(t *testing.T, environment *testEnvironment) {
	t.Helper()
	err := environment.api.RegisterPaymentEventRoute(environment.router, func(scope string) core.MiddlewareFunc {
		if scope != ScopePaymentWrite {
			t.Fatalf("scope = %q", scope)
		}
		return func(ctx core.HandlerContext) {
			request := ctx.Request().WithContext(rs.NewContext(ctx.Request().Context(), &rs.Claims{
				Subject: "provider-client", ClientID: "provider-client", Scope: ScopePaymentWrite,
			}))
			*ctx.Request() = *request
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func registerPaymentOrderReadRoute(t *testing.T, environment *testEnvironment, clientID string) {
	t.Helper()
	err := environment.api.RegisterPaymentOrderReadRoute(environment.router, func(scope string) core.MiddlewareFunc {
		if scope != ScopePaymentOrderRead {
			t.Fatalf("scope = %q", scope)
		}
		return func(ctx core.HandlerContext) {
			claims := &rs.Claims{Subject: clientID, ClientID: clientID, Scope: ScopePaymentOrderRead}
			request := ctx.Request().WithContext(rs.NewContext(ctx.Request().Context(), claims))
			*ctx.Request() = *request
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func paymentEventPath(tenantID, orderID string) string {
	return "/api/v1/commerce/tenants/" + tenantID + "/payments/orders/" + orderID + "/events"
}

func paymentOrderReadPath(tenantID, orderID string) string {
	return "/api/v1/commerce/tenants/" + tenantID + "/payments/orders/" + orderID
}

func paymentEventBody(tenantID, orderID string, amount int64) map[string]any {
	return map[string]any{
		"tenant_id": tenantID, "id": "event-1", "provider": "provider-adapter",
		"provider_order_id": "provider-order-1", "order_id": orderID, "type": "captured",
		"currency": "USD", "amount_minor": amount, "occurred_at": commerceTestNow,
	}
}

func paymentDomainEvent(
	id, orderID string, eventType tenantcommerce.PaymentEventType, amount int64,
) *tenantcommerce.PaymentEvent {
	return &tenantcommerce.PaymentEvent{
		ID: id, Provider: "provider-adapter", ProviderOrderID: "provider-order-1", OrderID: orderID,
		Type: eventType, Currency: "USD", AmountMinor: amount, OccurredAt: commerceTestNow,
	}
}

func assertPaymentEvents(t *testing.T, environment *testEnvironment, orderID string, count int) {
	t.Helper()
	path := "/api/v1/admin/commerce/tenants/tenant-1/payments/orders/" + orderID + "/events"
	response := serveJSON(t, environment.router, http.MethodGet, path, nil)
	var body struct {
		Total int `json:"total"`
	}
	decodeResponse(t, response, &body)
	if response.Code != http.StatusOK || body.Total != count {
		t.Fatalf("events total=%d status=%d body=%s", body.Total, response.Code, response.Body.String())
	}
}

func paymentGateContext(claims *rs.Claims) (*core.Context, *httptest.ResponseRecorder) {
	request := httptest.NewRequest(http.MethodPost, PathPaymentEventIngest, nil)
	if claims != nil {
		request = request.WithContext(rs.NewContext(request.Context(), claims))
	}
	response := httptest.NewRecorder()
	return core.NewContext(response, request), response
}

func assertErrorResponse(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	result := response.Result()
	defer result.Body.Close()
	var body map[string]string
	if err := json.NewDecoder(result.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != status || body[core.KeyError] != code {
		t.Fatalf("status=%d error=%q, want status=%d error=%q", result.StatusCode, body[core.KeyError], status, code)
	}
}
