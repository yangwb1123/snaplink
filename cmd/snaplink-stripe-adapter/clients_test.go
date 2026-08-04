package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestStripeCheckoutFormUsesTrustedOrderAndMetadata(t *testing.T) {
	var received url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer sk_test" || request.Header.Get("Idempotency-Key") != "idem-one" ||
			request.Header.Get("Stripe-Version") != "2025-06-30.basil" ||
			request.Header.Get("Stripe-Account") != "acct_connected" {
			t.Errorf("unexpected Stripe headers: %v", request.Header)
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		received = request.Form
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"id": "cs_one", "object": "checkout.session", "url": "https://checkout.stripe.com/one",
			"expires_at": time.Now().Add(time.Hour).Unix(), "payment_intent": "pi_one",
		})
	}))
	defer server.Close()
	client := &stripeClient{
		baseURL: server.URL, apiVersion: "2025-06-30.basil", apiKey: "sk_test",
		account: "acct_connected", httpClient: server.Client(),
	}
	session, err := client.CreateCheckout(context.Background(), testPaymentOrder(), checkoutRequest{
		OrderID: "order-one", SuccessURL: "https://console.example.test/s", CancelURL: "https://console.example.test/c",
	}, "idem-one")
	if err != nil || session.ID != "cs_one" || session.PaymentIntent != "pi_one" {
		t.Fatalf("CreateCheckout() session=%+v error=%v", session, err)
	}
	assertStripeCheckoutForm(t, received)
}

func TestStripeCheckoutPlatformAccountOmitsConnectHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if value := request.Header.Get("Stripe-Account"); value != "" {
			t.Errorf("Stripe-Account = %q, want omitted", value)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"id": "cs_platform", "object": "checkout.session", "url": "https://checkout.stripe.com/platform",
			"expires_at": time.Now().Add(time.Hour).Unix(), "payment_intent": "pi_platform",
		})
	}))
	defer server.Close()
	client := &stripeClient{
		baseURL: server.URL, apiVersion: "2025-06-30.basil", apiKey: "sk_test",
		account: "platform", httpClient: server.Client(),
	}
	if _, err := client.CreateCheckout(context.Background(), testPaymentOrder(), checkoutRequest{
		OrderID: "order-one", SuccessURL: "https://console.example.test/s", CancelURL: "https://console.example.test/c",
	}, "idem-platform"); err != nil {
		t.Fatalf("CreateCheckout() error = %v", err)
	}
}

func assertStripeCheckoutForm(t *testing.T, form url.Values) {
	t.Helper()
	want := map[string]string{
		"line_items[0][price_data][unit_amount]":            "1250",
		"line_items[0][price_data][currency]":               "usd",
		"metadata[snaplink_tenant_id]":                      "tenant-one",
		"metadata[snaplink_order_id]":                       "order-one",
		"payment_intent_data[metadata][snaplink_tenant_id]": "tenant-one",
		"payment_intent_data[metadata][snaplink_order_id]":  "order-one",
	}
	for key, value := range want {
		if form.Get(key) != value {
			t.Errorf("form[%q] = %q, want %q", key, form.Get(key), value)
		}
	}
}

func TestBillingClientUsesSeparateLeastPrivilegeTokens(t *testing.T) {
	var mu sync.Mutex
	tokenScopes := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/token":
			handleBillingTokenTest(t, writer, request, &mu, tokenScopes)
		case request.Method == http.MethodGet:
			if request.Header.Get("Authorization") != "Bearer token-order-read" {
				t.Errorf("order Authorization = %q", request.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"order": testPaymentOrder()})
		case request.Method == http.MethodPost:
			if request.Header.Get("Authorization") != "Bearer token-payment-write" {
				t.Errorf("delivery Authorization = %q", request.Header.Get("Authorization"))
			}
			writer.WriteHeader(http.StatusOK)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	config := runtimeConfig{BillingBaseURL: server.URL, TokenURL: server.URL + "/token", BillingResource: "billing-api"}
	client := newBillingClient(config, server.Client())
	binding := &tenantBinding{TenantID: "tenant-one", BillingClientID: "billing-client", BillingSecret: "billing-secret"}
	if _, err := client.GetOrder(context.Background(), binding, "order-one"); err != nil {
		t.Fatalf("GetOrder() error = %v", err)
	}
	if err := client.Deliver(context.Background(), binding, trustedDelivery{
		EventID: "evt_one", TenantID: "tenant-one", OrderID: "order-one", ProviderOrderID: "pi_one",
		Type: eventCaptured, Currency: "USD", AmountMinor: 1250, OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if tokenScopes[scopePaymentOrderRead] != 1 || tokenScopes[scopePaymentWrite] != 1 {
		t.Fatalf("token scopes = %#v", tokenScopes)
	}
}

func handleBillingTokenTest(
	t *testing.T, writer http.ResponseWriter, request *http.Request, mu *sync.Mutex, scopes map[string]int,
) {
	t.Helper()
	clientID, secret, ok := request.BasicAuth()
	if !ok || clientID != "billing-client" || secret != "billing-secret" {
		t.Errorf("unexpected client authentication")
	}
	if err := request.ParseForm(); err != nil {
		t.Error(err)
	}
	scope := request.Form.Get("scope")
	if request.Form.Get("grant_type") != "client_credentials" || request.Form.Get("resource") != "billing-api" {
		t.Errorf("unexpected token form: %v", request.Form)
	}
	mu.Lock()
	scopes[scope]++
	mu.Unlock()
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"access_token": "token-" + tokenSuffix(scope), "token_type": "Bearer", "expires_in": 300,
	})
}

func tokenSuffix(scope string) string {
	if scope == scopePaymentOrderRead {
		return "order-read"
	}
	return "payment-write"
}
