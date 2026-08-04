package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	commercehttp "github.com/yangwb1123/snaplink/interfaces/commerce"
	meteringhttp "github.com/yangwb1123/snaplink/interfaces/metering"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rstest"
)

func TestApplicationProtectsBusinessRoutesButNotProbes(t *testing.T) {
	issuer, err := rstest.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	app, err := buildApplication(testApplicationConfig(issuer.URL(), issuer.JWKSURL()))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	for _, path := range []string{pathLivez, pathReadyz} {
		response := serveApplication(app, http.MethodGet, path, "", "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	metrics := serveApplication(app, http.MethodGet, pathMetrics, "", "")
	if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), metricRenewalEnabled) {
		t.Fatalf("metrics status=%d body=%s", metrics.Code, metrics.Body.String())
	}
	response := serveApplication(app, http.MethodGet, commercehttp.PathPlans, "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated business status=%d", response.Code)
	}

	reader := mintBillingToken(t, issuer, "operator", "console", commercehttp.ScopeAdminRead, "billing-api")
	response = serveApplication(app, http.MethodGet, commercehttp.PathPlans, reader, "")
	if response.Code != http.StatusOK {
		t.Fatalf("admin read status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveApplication(app, http.MethodPost, commercehttp.PathPlans, reader, `{}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("admin reader write status=%d", response.Code)
	}
	writer := mintBillingToken(t, issuer, "operator", "console", commercehttp.ScopeAdminWrite, "billing-api")
	response = serveApplication(app, http.MethodGet, commercehttp.PathPlans, writer, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("admin writer read status=%d", response.Code)
	}
}

func TestApplicationPaymentIngestRequiresMachineIdentity(t *testing.T) {
	issuer, err := rstest.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	config := testApplicationConfig(issuer.URL(), issuer.JWKSURL())
	binding := sourceBindingFixture(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), 1, true)
	binding.ClientID = "adapter"
	binding.SourceSystem = "payment:adapter"
	config.SourceBindingsFile = writeSourceBindings(t, []*ledger.SourceBinding{binding})
	app, err := buildApplication(config)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	path := "/api/v1/commerce/tenants/tenant-a/payments/orders/missing/events"
	body := `{"tenant_id":"tenant-a","id":"evt-1","provider":"adapter","provider_order_id":"provider-1","order_id":"missing","type":"captured","currency":"USD","amount_minor":100,"occurred_at":"2026-08-04T12:00:00Z"}`
	userToken := mintBillingToken(t, issuer, "user-a", "adapter", commercehttp.ScopePaymentWrite, "billing-api")
	response := serveApplication(app, http.MethodPost, path, userToken, body)
	if response.Code != http.StatusForbidden {
		t.Fatalf("user payment event status=%d body=%s", response.Code, response.Body.String())
	}
	machineToken := mintBillingToken(t, issuer, "adapter", "adapter", commercehttp.ScopePaymentWrite, "billing-api")
	response = serveApplication(app, http.MethodPost, path, machineToken, body)
	if response.Code != http.StatusNotFound {
		t.Fatalf("machine payment event status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestApplicationPaymentOrderReadUsesMachineBinding(t *testing.T) {
	issuer, err := rstest.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	config := testApplicationConfig(issuer.URL(), issuer.JWKSURL())
	binding := sourceBindingFixture(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), 1, true)
	binding.ClientID = "stripe-adapter"
	binding.SourceSystem = "payment:stripe"
	config.SourceBindingsFile = writeSourceBindings(t, []*ledger.SourceBinding{binding})
	app, err := buildApplication(config)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	writer := mintBillingToken(t, issuer, "operator", "console", commercehttp.ScopeAdminWrite, "billing-api")
	adminPath := "/api/v1/admin/commerce/tenants/tenant-a/payments/orders"
	body := `{"id":"pay-stripe","provider":"stripe","currency":"USD","amount_minor":1250,"idempotency_key":"topup:stripe"}`
	if response := serveApplication(app, http.MethodPost, adminPath, writer, body); response.Code != http.StatusCreated {
		t.Fatalf("create order status=%d body=%s", response.Code, response.Body.String())
	}
	readPath := "/api/v1/commerce/tenants/tenant-a/payments/orders/pay-stripe"
	machine := mintBillingToken(t, issuer, "stripe-adapter", "stripe-adapter",
		commercehttp.ScopePaymentOrderRead, "billing-api")
	response := serveApplication(app, http.MethodGet, readPath, machine, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"amount_minor":1250`) {
		t.Fatalf("payment order read status=%d body=%s", response.Code, response.Body.String())
	}
	wrongScope := mintBillingToken(t, issuer, "stripe-adapter", "stripe-adapter",
		commercehttp.ScopePaymentWrite, "billing-api")
	response = serveApplication(app, http.MethodGet, readPath, wrongScope, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong-scope order read status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveApplication(app, http.MethodGet,
		"/api/v1/commerce/tenants/tenant-b/payments/orders/pay-stripe", machine, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant order read status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestApplicationMeteringResolvesBoundMachineIdentity(t *testing.T) {
	issuer, err := rstest.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	config := testApplicationConfig(issuer.URL(), issuer.JWKSURL())
	binding := sourceBindingFixture(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), 1, true,
		"messages_per_month")
	config.SourceBindingsFile = writeSourceBindings(t, []*ledger.SourceBinding{binding})
	app, err := buildApplication(config)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	known := mintBillingToken(t, issuer, binding.ClientID, binding.ClientID,
		meteringhttp.ScopeEntitlementRead, "billing-api")
	response := serveApplication(app, http.MethodGet, meteringhttp.PathEntitlement, known, "")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), meteringhttp.ErrorEntitlementNotFound) {
		t.Fatalf("bound client status=%d body=%s", response.Code, response.Body.String())
	}
	unknown := mintBillingToken(t, issuer, "unknown", "unknown",
		meteringhttp.ScopeEntitlementRead, "billing-api")
	response = serveApplication(app, http.MethodGet, meteringhttp.PathEntitlement, unknown, "")
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), meteringhttp.ErrorSourceUnauthorized) {
		t.Fatalf("unknown client status=%d body=%s", response.Code, response.Body.String())
	}
	user := mintBillingToken(t, issuer, "user-a", binding.ClientID,
		meteringhttp.ScopeEntitlementRead, "billing-api")
	response = serveApplication(app, http.MethodGet, meteringhttp.PathEntitlement, user, "")
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), meteringhttp.ErrorInsufficientScope) {
		t.Fatalf("user identity status=%d body=%s", response.Code, response.Body.String())
	}
	writer := mintBillingToken(t, issuer, binding.ClientID, binding.ClientID,
		meteringhttp.ScopeMeteringWrite, "billing-api")
	response = serveMeteringWrite(app, writer, `{"dimension":"messages_per_month","quantity":1}`)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), meteringhttp.ErrorEntitlementNotFound) {
		t.Fatalf("metering write status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveMeteringWrite(app, writer,
		`{"tenant_id":"tenant-b","dimension":"messages_per_month","quantity":1}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body tenant authority status=%d body=%s", response.Code, response.Body.String())
	}
}

func serveMeteringWrite(app *application, token, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, meteringhttp.PathUsageAppend, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "metering-request-1")
	response := httptest.NewRecorder()
	app.handler.ServeHTTP(response, request)
	return response
}

func testApplicationConfig(issuer, jwksURL string) runtimeConfig {
	return runtimeConfig{
		Listen: "127.0.0.1:0", DevMemory: true, Issuer: issuer, JWKSURL: jwksURL,
		Audience: "billing-api", AllowInsecureLoopback: true, ReadyTimeout: time.Second,
	}
}

func mintBillingToken(
	t *testing.T, issuer *rstest.Issuer, subject, clientID, scope, audience string,
) string {
	t.Helper()
	token, err := issuer.MintAccessToken(map[string]any{
		"sub": subject, "client_id": clientID, "scope": scope, "aud": audience,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func serveApplication(
	app *application, method, path, token, body string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	app.handler.ServeHTTP(response, request)
	return response
}
