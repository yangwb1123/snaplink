package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type billingGateway interface {
	GetOrder(context.Context, *tenantBinding, string) (paymentOrder, error)
	Deliver(context.Context, *tenantBinding, trustedDelivery) error
}

type billingClient struct {
	baseURL    string
	tokenURL   string
	resource   string
	httpClient *http.Client
	tokens     *clientTokenCache
}

type tokenCacheKey struct {
	clientID string
	scope    string
}

type cachedClientToken struct {
	value     string
	expiresAt time.Time
}

type clientTokenCache struct {
	mu     sync.Mutex
	tokens map[tokenCacheKey]cachedClientToken
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func newBillingClient(config runtimeConfig, client *http.Client) *billingClient {
	return &billingClient{
		baseURL:  strings.TrimRight(config.BillingBaseURL, "/"),
		tokenURL: config.TokenURL, resource: config.BillingResource,
		httpClient: client, tokens: &clientTokenCache{tokens: make(map[tokenCacheKey]cachedClientToken)},
	}
}

func (c *billingClient) GetOrder(
	ctx context.Context, binding *tenantBinding, orderID string,
) (paymentOrder, error) {
	token, err := c.clientToken(ctx, binding, scopePaymentOrderRead)
	if err != nil {
		return paymentOrder{}, err
	}
	path := "/api/v1/commerce/tenants/" + url.PathEscape(binding.TenantID) +
		"/payments/orders/" + url.PathEscape(orderID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return paymentOrder{}, &deliveryError{category: "billing_request", err: err}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return paymentOrder{}, &deliveryError{category: ErrBillingUnavailable, err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		c.invalidateOnUnauthorized(binding, scopePaymentOrderRead, response.StatusCode)
		return paymentOrder{}, billingStatusError("billing_order_read", response.StatusCode)
	}
	var body struct {
		Order paymentOrder `json:"order"`
	}
	if err := decodeBoundedJSON(response.Body, maxJSONResponseBytes, &body); err != nil {
		return paymentOrder{}, &deliveryError{category: "billing_response", err: err}
	}
	if !validOrderIdentity(body.Order, binding.TenantID, orderID) {
		return paymentOrder{}, &deliveryError{category: "billing_response", err: errCheckoutConflict}
	}
	return body.Order, nil
}

func (c *billingClient) Deliver(
	ctx context.Context, binding *tenantBinding, delivery trustedDelivery,
) error {
	token, err := c.clientToken(ctx, binding, scopePaymentWrite)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"tenant_id": delivery.TenantID, "id": delivery.EventID,
		"provider": providerStripe, "provider_order_id": delivery.ProviderOrderID,
		"order_id": delivery.OrderID, "type": delivery.Type,
		"currency": delivery.Currency, "amount_minor": delivery.AmountMinor,
		"occurred_at": delivery.OccurredAt,
	})
	if err != nil {
		return &deliveryError{category: "billing_request", err: err}
	}
	path := "/api/v1/commerce/tenants/" + url.PathEscape(delivery.TenantID) +
		"/payments/orders/" + url.PathEscape(delivery.OrderID) + "/events"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return &deliveryError{category: "billing_request", err: err}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return &deliveryError{category: ErrBillingUnavailable, err: err}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxJSONResponseBytes))
	if response.StatusCode != http.StatusOK {
		c.invalidateOnUnauthorized(binding, scopePaymentWrite, response.StatusCode)
		return billingStatusError("billing_payment_write", response.StatusCode)
	}
	return nil
}

func (c *billingClient) clientToken(
	ctx context.Context, binding *tenantBinding, scope string,
) (string, error) {
	key := tokenCacheKey{clientID: binding.BillingClientID, scope: scope}
	c.tokens.mu.Lock()
	if cached, ok := c.tokens.tokens[key]; ok && time.Now().Before(cached.expiresAt) {
		c.tokens.mu.Unlock()
		return cached.value, nil
	}
	c.tokens.mu.Unlock()
	token, expiry, err := c.requestClientToken(ctx, binding, scope)
	if err != nil {
		return "", err
	}
	c.tokens.mu.Lock()
	c.tokens.tokens[key] = cachedClientToken{value: token, expiresAt: expiry}
	c.tokens.mu.Unlock()
	return token, nil
}

func (c *billingClient) requestClientToken(
	ctx context.Context, binding *tenantBinding, scope string,
) (string, time.Time, error) {
	form := url.Values{
		"grant_type": {"client_credentials"}, "scope": {scope}, "resource": {c.resource},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, &deliveryError{category: "oauth_request", err: err}
	}
	request.SetBasicAuth(binding.BillingClientID, binding.BillingSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", time.Time{}, &deliveryError{category: "oauth_unavailable", err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxJSONResponseBytes))
		return "", time.Time{}, billingStatusError("oauth_token", response.StatusCode)
	}
	var body tokenResponse
	if err := decodeBoundedJSON(response.Body, maxJSONResponseBytes, &body); err != nil ||
		!validAccessToken(body.AccessToken) || !strings.EqualFold(body.TokenType, "Bearer") || body.ExpiresIn <= 0 {
		return "", time.Time{}, &deliveryError{category: "oauth_response", err: errInvalidProviderFact}
	}
	refreshEarly := 30 * time.Second
	lifetime := time.Duration(body.ExpiresIn) * time.Second
	if lifetime <= refreshEarly {
		refreshEarly = lifetime / 2
	}
	return body.AccessToken, time.Now().Add(lifetime - refreshEarly), nil
}

func (c *billingClient) invalidateOnUnauthorized(binding *tenantBinding, scope string, status int) {
	if status != http.StatusUnauthorized {
		return
	}
	c.tokens.mu.Lock()
	delete(c.tokens.tokens, tokenCacheKey{clientID: binding.BillingClientID, scope: scope})
	c.tokens.mu.Unlock()
}

func validOrderIdentity(order paymentOrder, tenantID, orderID string) bool {
	return validIdentity(order.ID) && order.ID == orderID && order.TenantID == tenantID &&
		order.Provider == providerStripe && len(order.Currency) == 3 && order.AmountMinor > 0 &&
		order.Revision > 0 && !order.UpdatedAt.IsZero()
}

func validAccessToken(value string) bool {
	return value != "" && len(value) <= 16*1024 && value == strings.TrimSpace(value) &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func decodeBoundedJSON(reader io.Reader, maximum int64, target any) error {
	limited := io.LimitReader(reader, maximum+1)
	payload, err := io.ReadAll(limited)
	if err != nil || int64(len(payload)) > maximum {
		return fmt.Errorf("bounded JSON response")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing JSON response")
	}
	return nil
}

func billingStatusError(operation string, status int) error {
	return &deliveryError{
		category: operation + "_status", err: fmt.Errorf("unexpected HTTP status %s", strconv.Itoa(status)),
	}
}
