package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rstest"
)

type fakeHandlerStore struct {
	reservation checkoutReservation
	reserveErr  error
	saveErr     error
	inboxErr    error
	inboxCalls  int
	lastFact    providerFact
	backlog     backlogState
	deadlineSet bool
}

func (s *fakeHandlerStore) ReserveCheckout(
	ctx context.Context, order paymentOrder, request checkoutRequest,
) (checkoutReservation, error) {
	_, s.deadlineSet = ctx.Deadline()
	if s.reservation.TenantID == "" {
		s.reservation = checkoutReservation{
			TenantID: order.TenantID, OrderID: order.ID, Currency: order.Currency,
			AmountMinor: order.AmountMinor, IdempotencyKey: "idem-one", RequestDigest: checkoutRequestDigest(request), Generation: 1,
		}
	}
	if s.reservation.complete() && !s.reservation.available(time.Now()) {
		s.reservation.Generation++
		s.reservation.IdempotencyKey = "idem-rotated"
		s.reservation.SessionID, s.reservation.RedirectURL, s.reservation.PaymentIntent = "", "", ""
		s.reservation.ExpiresAt, s.reservation.Rotated = time.Time{}, true
	}
	return s.reservation, s.reserveErr
}

func (s *fakeHandlerStore) SaveCheckout(
	_ context.Context, reservation checkoutReservation, session stripeCheckoutSession,
) (checkoutReservation, error) {
	reservation.SessionID, reservation.RedirectURL = session.ID, session.URL
	reservation.ExpiresAt, reservation.PaymentIntent = session.ExpiresAt, session.PaymentIntent
	s.reservation = reservation
	return reservation, s.saveErr
}

func (s *fakeHandlerStore) InsertInbox(_ context.Context, fact providerFact, _ []byte) (inboxOutcome, error) {
	s.inboxCalls++
	s.lastFact = fact
	return inboxInserted, s.inboxErr
}

func (*fakeHandlerStore) Ping(context.Context) error { return nil }
func (s *fakeHandlerStore) Backlog(context.Context) (backlogState, error) {
	return s.backlog, nil
}

type fakeBillingGateway struct {
	order       paymentOrder
	err         error
	deliverErr  error
	lastBinding *tenantBinding
	lastOrderID string
	deliveries  []trustedDelivery
}

func (b *fakeBillingGateway) GetOrder(
	_ context.Context, binding *tenantBinding, orderID string,
) (paymentOrder, error) {
	b.lastBinding, b.lastOrderID = binding, orderID
	return b.order, b.err
}

func (b *fakeBillingGateway) Deliver(
	_ context.Context, _ *tenantBinding, delivery trustedDelivery,
) error {
	b.deliveries = append(b.deliveries, delivery)
	return b.deliverErr
}

type fakeStripeGateway struct {
	session stripeCheckoutSession
	err     error
	calls   int
	order   paymentOrder
	request checkoutRequest
	key     string
}

func (s *fakeStripeGateway) CreateCheckout(
	_ context.Context, order paymentOrder, request checkoutRequest, key string,
) (stripeCheckoutSession, error) {
	s.calls++
	s.order, s.request, s.key = order, request, key
	return s.session, s.err
}

func TestCheckoutUsesBoundTenantAndBillingAmount(t *testing.T) {
	store := &fakeHandlerStore{}
	billing := &fakeBillingGateway{order: testPaymentOrder()}
	stripe := &fakeStripeGateway{session: testStripeSession()}
	handler, token := testAdapterHandler(t, store, billing, stripe, "checkout-client", scopeCheckoutCreate)
	response := performCheckout(handler, token, `{"order_id":"order-one","success_url":"https://console.example.test/success","cancel_url":"https://console.example.test/cancel"}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("checkout status = %d, body = %s", response.Code, response.Body.String())
	}
	if billing.lastBinding.TenantID != "tenant-one" || billing.lastOrderID != "order-one" {
		t.Fatalf("unexpected billing lookup: binding=%+v order=%q", billing.lastBinding, billing.lastOrderID)
	}
	if stripe.order.AmountMinor != 1250 || stripe.order.Currency != "USD" || stripe.key != "idem-one" {
		t.Fatalf("untrusted amount or idempotency key reached Stripe: order=%+v key=%q", stripe.order, stripe.key)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("checkout response was cacheable")
	}
}

func TestCheckoutEnforcesClientBindingScopeAndReturnOrigin(t *testing.T) {
	tests := []struct {
		name, clientID, scope, body string
		want                        int
	}{
		{name: "unbound client", clientID: "other-client", scope: scopeCheckoutCreate, body: validCheckoutBody(), want: http.StatusForbidden},
		{name: "wrong scope", clientID: "checkout-client", scope: "billing:payment:write", body: validCheckoutBody(), want: http.StatusForbidden},
		{name: "unapproved return origin", clientID: "checkout-client", scope: scopeCheckoutCreate, body: `{"order_id":"order-one","success_url":"https://evil.example/s","cancel_url":"https://console.example.test/c"}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			billing := &fakeBillingGateway{order: testPaymentOrder()}
			handler, token := testAdapterHandler(t, &fakeHandlerStore{}, billing, &fakeStripeGateway{}, test.clientID, test.scope)
			if response := performCheckout(handler, token, test.body); response.Code != test.want {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestCheckoutRejectsUserIdentityUsingBoundClient(t *testing.T) {
	handler, token := testAdapterHandlerSubject(
		t, &fakeHandlerStore{}, &fakeBillingGateway{order: testPaymentOrder()}, &fakeStripeGateway{},
		"user-one", "checkout-client", scopeCheckoutCreate,
	)
	if response := performCheckout(handler, token, validCheckoutBody()); response.Code != http.StatusForbidden {
		t.Fatalf("user identity status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCheckoutAuthorizesAdminUserForExplicitBoundTenant(t *testing.T) {
	store := &fakeHandlerStore{}
	handler, token := testAdapterHandlerSubject(
		t, store, &fakeBillingGateway{order: testPaymentOrder()}, &fakeStripeGateway{session: testStripeSession()},
		"user-one", "", scopeAdminWrite,
	)
	body := `{"tenant_id":"tenant-one","order_id":"order-one","success_url":"https://console.example.test/success","cancel_url":"https://console.example.test/cancel"}`
	if response := performCheckout(handler, token, body); response.Code != http.StatusCreated {
		t.Fatalf("admin checkout status=%d body=%s", response.Code, response.Body.String())
	}
	if !store.deadlineSet {
		t.Fatal("checkout store call did not inherit a handler deadline")
	}
}

func TestCheckoutUserRequiresAdminScopeAndExplicitBoundTenant(t *testing.T) {
	tests := []struct {
		name, clientID, scope, body string
	}{
		{name: "missing tenant", clientID: "console-client", scope: scopeAdminWrite, body: validCheckoutBody()},
		{name: "unbound tenant", clientID: "console-client", scope: scopeAdminWrite, body: `{"tenant_id":"tenant-other","order_id":"order-one","success_url":"https://console.example.test/s","cancel_url":"https://console.example.test/c"}`},
		{name: "wrong scope", clientID: "console-client", scope: scopeCheckoutCreate, body: `{"tenant_id":"tenant-one","order_id":"order-one","success_url":"https://console.example.test/s","cancel_url":"https://console.example.test/c"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, token := testAdapterHandlerSubject(t, &fakeHandlerStore{}, &fakeBillingGateway{}, &fakeStripeGateway{}, "user-one", test.clientID, test.scope)
			response := performCheckout(handler, token, test.body)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="admin:write"`) {
				t.Fatalf("status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestCheckoutMachineRejectsCrossTenantRequest(t *testing.T) {
	handler, token := testAdapterHandler(t, &fakeHandlerStore{}, &fakeBillingGateway{}, &fakeStripeGateway{}, "checkout-client", scopeCheckoutCreate)
	body := `{"tenant_id":"tenant-other","order_id":"order-one","success_url":"https://console.example.test/s","cancel_url":"https://console.example.test/c"}`
	response := performCheckout(handler, token, body)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="billing:checkout:create"`) {
		t.Fatalf("status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
}

func TestCheckoutReplaysCompletedReservationWithoutStripeCall(t *testing.T) {
	store := &fakeHandlerStore{reservation: checkoutReservation{
		TenantID: "tenant-one", OrderID: "order-one", Currency: "USD", AmountMinor: 1250,
		IdempotencyKey: "idem-one", SessionID: "cs_one", RedirectURL: "https://checkout.stripe.com/one",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	stripe := &fakeStripeGateway{}
	handler, token := testAdapterHandler(t, store, &fakeBillingGateway{order: testPaymentOrder()}, stripe, "checkout-client", scopeCheckoutCreate)
	response := performCheckout(handler, token, validCheckoutBody())
	if response.Code != http.StatusOK || stripe.calls != 0 {
		t.Fatalf("replay status=%d Stripe calls=%d", response.Code, stripe.calls)
	}
}

func TestCheckoutSafelyReplacesExpiredSession(t *testing.T) {
	store := &fakeHandlerStore{reservation: checkoutReservation{
		TenantID: "tenant-one", OrderID: "order-one", Currency: "USD", AmountMinor: 1250,
		IdempotencyKey: "idem-one", SessionID: "cs_expired", RedirectURL: "https://checkout.stripe.com/expired",
		ExpiresAt: time.Now().Add(-time.Minute),
	}}
	stripe := &fakeStripeGateway{session: testStripeSession()}
	handler, token := testAdapterHandler(t, store, &fakeBillingGateway{order: testPaymentOrder()}, stripe, "checkout-client", scopeCheckoutCreate)
	response := performCheckout(handler, token, validCheckoutBody())
	if response.Code != http.StatusCreated || stripe.calls != 1 || stripe.key != "idem-rotated" ||
		strings.Contains(response.Body.String(), "checkout.stripe.com/expired") {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, stripe.calls, response.Body.String())
	}
}

func TestMetricsExposeBoundedBacklogAndCounters(t *testing.T) {
	store := &fakeHandlerStore{backlog: backlogState{Count: 101, Quarantined: 3, Oldest: time.Now().Add(-2 * time.Hour)}}
	handler, _ := testAdapterHandler(t, store, &fakeBillingGateway{}, &fakeStripeGateway{}, "checkout-client", scopeCheckoutCreate)
	request := httptest.NewRequest(http.MethodGet, pathMetrics, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "snaplink_stripe_inbox_pending 101") ||
		!strings.Contains(body, "snaplink_stripe_inbox_quarantined 3") ||
		!strings.Contains(body, "snaplink_stripe_backlog_threshold_exceeded 1") {
		t.Fatalf("metrics status=%d body=%s", response.Code, body)
	}
}

func TestWebhookAcknowledgesSupportedAndSignedUnsupportedEvents(t *testing.T) {
	store := &fakeHandlerStore{}
	handler, _ := testAdapterHandler(t, store, &fakeBillingGateway{}, &fakeStripeGateway{}, "checkout-client", scopeCheckoutCreate)
	now := time.Now().UTC()
	supported := eventPayload(stripeEventSucceeded, paymentIntentObject(1250, 1250), now)
	if response := performWebhook(handler, supported, signatureHeader("whsec-test", now.Unix(), supported)); response.Code != http.StatusOK {
		t.Fatalf("supported status=%d body=%s", response.Code, response.Body.String())
	}
	unsupported := eventPayload("customer.created", map[string]any{"id": "cus_one", "object": "customer"}, now)
	if response := performWebhook(handler, unsupported, signatureHeader("whsec-test", now.Unix(), unsupported)); response.Code != http.StatusNoContent {
		t.Fatalf("unsupported status=%d body=%s", response.Code, response.Body.String())
	}
	failed := eventPayload(stripeEventFailed, paymentIntentObject(1250, 0), now)
	if response := performWebhook(handler, failed, signatureHeader("whsec-test", now.Unix(), failed)); response.Code != http.StatusNoContent {
		t.Fatalf("payment failure status=%d body=%s", response.Code, response.Body.String())
	}
	if store.inboxCalls != 1 || store.lastFact.NormalizedType != eventCaptured {
		t.Fatalf("unexpected inbox projection: calls=%d fact=%+v", store.inboxCalls, store.lastFact)
	}
}

func TestWebhookRejectsInvalidSignatureAndDigestConflict(t *testing.T) {
	store := &fakeHandlerStore{}
	handler, _ := testAdapterHandler(t, store, &fakeBillingGateway{}, &fakeStripeGateway{}, "checkout-client", scopeCheckoutCreate)
	now := time.Now().UTC()
	payload := eventPayload(stripeEventRefund, refundObject(), now)
	if response := performWebhook(handler, payload, "t=1,v1=00"); response.Code != http.StatusBadRequest || store.inboxCalls != 0 {
		t.Fatalf("invalid signature status=%d calls=%d", response.Code, store.inboxCalls)
	}
	store.inboxErr = errInboxConflict
	response := performWebhook(handler, payload, signatureHeader("whsec-test", now.Unix(), payload))
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", response.Code, response.Body.String())
	}
}

func testAdapterHandler(
	t *testing.T, store handlerStore, billing billingGateway, stripe stripeGateway, clientID, scope string,
) (http.Handler, string) {
	t.Helper()
	return testAdapterHandlerSubject(t, store, billing, stripe, clientID, clientID, scope)
}

func testAdapterHandlerSubject(
	t *testing.T, store handlerStore, billing billingGateway, stripe stripeGateway,
	subject, clientID, scope string,
) (http.Handler, string) {
	t.Helper()
	issuer, err := rstest.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	cache := rs.NewJWKSCache(issuer.JWKSURL())
	t.Cleanup(func() { cache.Close(); issuer.Close() })
	config := runtimeConfig{
		Issuer: issuer.URL(), JWKSURL: issuer.JWKSURL(), Audience: "stripe-adapter",
		WebhookSecrets: []string{"whsec-test"}, ReadyTimeout: time.Second, HandlerTimeout: 5 * time.Second,
		StripeAccount: "platform", WebhookAPIVersion: "2025-06-30.basil",
		ReturnOrigins: map[string]struct{}{"https://console.example.test": {}},
		CheckoutBindings: map[string]*tenantBinding{
			"checkout-client": {TenantID: "tenant-one", BillingClientID: "billing-client"},
		},
		TenantBindings: map[string]*tenantBinding{
			"tenant-one": {TenantID: "tenant-one", BillingClientID: "billing-client"},
		},
		MaxBacklog: 100, MaxBacklogAge: time.Hour,
	}
	handler, err := newAdapterHandler(config, store, stripe, billing, cache, &http.Client{Timeout: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := issuer.MintAccessToken(map[string]any{
		"sub": subject, "client_id": clientID, "aud": "stripe-adapter", "scope": scope, "jti": "jti-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, token
}

func performCheckout(handler http.Handler, token, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, pathCheckout, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func performWebhook(handler http.Handler, payload []byte, signature string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, pathStripeWebhook, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Stripe-Signature", signature)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func testPaymentOrder() paymentOrder {
	return paymentOrder{
		ID: "order-one", TenantID: "tenant-one", Provider: providerStripe,
		Currency: "USD", AmountMinor: 1250, Status: "pending", Revision: 1, UpdatedAt: time.Now().UTC(),
	}
}

func testStripeSession() stripeCheckoutSession {
	return stripeCheckoutSession{
		ID: "cs_one", URL: "https://checkout.stripe.com/one",
		ExpiresAt: time.Now().Add(time.Hour).UTC(), PaymentIntent: "pi_one",
	}
}

func validCheckoutBody() string {
	body, err := json.Marshal(checkoutRequest{
		OrderID: "order-one", SuccessURL: "https://console.example.test/success",
		CancelURL: "https://console.example.test/cancel",
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}
