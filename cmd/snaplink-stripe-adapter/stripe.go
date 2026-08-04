package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type stripeGateway interface {
	CreateCheckout(context.Context, paymentOrder, checkoutRequest, string) (stripeCheckoutSession, error)
}

type stripeClient struct {
	baseURL    string
	apiVersion string
	apiKey     string
	account    string
	httpClient *http.Client
}

type stripeCheckoutResponse struct {
	ID            string          `json:"id"`
	Object        string          `json:"object"`
	URL           string          `json:"url"`
	ExpiresAt     int64           `json:"expires_at"`
	PaymentIntent json.RawMessage `json:"payment_intent"`
}

func newStripeClient(config runtimeConfig, client *http.Client) *stripeClient {
	return &stripeClient{
		baseURL:    strings.TrimRight(config.StripeAPIBaseURL, "/"),
		apiVersion: config.StripeAPIVersion, apiKey: config.StripeAPIKey,
		account: config.StripeAccount, httpClient: client,
	}
}

func (c *stripeClient) CreateCheckout(
	ctx context.Context, order paymentOrder, checkout checkoutRequest, idempotencyKey string,
) (stripeCheckoutSession, error) {
	form := stripeCheckoutForm(order, checkout)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return stripeCheckoutSession{}, &deliveryError{category: "stripe_request", err: err}
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("Stripe-Version", c.apiVersion)
	if c.account != "" && c.account != "platform" {
		request.Header.Set("Stripe-Account", c.account)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return stripeCheckoutSession{}, &deliveryError{category: "stripe_unavailable", err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxJSONResponseBytes))
		return stripeCheckoutSession{}, stripeRequestError("stripe_checkout", response.StatusCode)
	}
	var body stripeCheckoutResponse
	if err := decodeBoundedJSON(response.Body, maxJSONResponseBytes, &body); err != nil {
		return stripeCheckoutSession{}, &deliveryError{category: "stripe_response", err: err}
	}
	session := stripeCheckoutSession{
		ID: body.ID, URL: body.URL, ExpiresAt: time.Unix(body.ExpiresAt, 0).UTC(),
		PaymentIntent: stripeExpandableID(body.PaymentIntent),
	}
	if !validCheckoutSession(session, time.Now()) || body.Object != "checkout.session" {
		return stripeCheckoutSession{}, &deliveryError{category: "stripe_response", err: errInvalidProviderFact}
	}
	return session, nil
}

func stripeCheckoutForm(order paymentOrder, checkout checkoutRequest) url.Values {
	amount := strconv.FormatInt(order.AmountMinor, 10)
	return url.Values{
		"mode": {"payment"}, "client_reference_id": {order.ID},
		"success_url": {checkout.SuccessURL}, "cancel_url": {checkout.CancelURL},
		"line_items[0][quantity]":                                 {"1"},
		"line_items[0][price_data][currency]":                     {strings.ToLower(order.Currency)},
		"line_items[0][price_data][unit_amount]":                  {amount},
		"line_items[0][price_data][product_data][name]":           {"Snaplink account top-up"},
		"metadata[" + metadataTenantID + "]":                      {order.TenantID},
		"metadata[" + metadataOrderID + "]":                       {order.ID},
		"payment_intent_data[metadata][" + metadataTenantID + "]": {order.TenantID},
		"payment_intent_data[metadata][" + metadataOrderID + "]":  {order.ID},
	}
}

func validCheckoutSession(session stripeCheckoutSession, now time.Time) bool {
	if !validStripeID(session.ID) || session.URL == "" || !session.ExpiresAt.After(now) {
		return false
	}
	parsed, err := url.Parse(session.URL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

func stripeRequestError(operation string, status int) error {
	return &deliveryError{
		category: operation + "_status", err: fmt.Errorf("unexpected Stripe HTTP status %d", status),
	}
}
