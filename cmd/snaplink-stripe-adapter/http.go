package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/security"
)

type handlerStore interface {
	ReserveCheckout(context.Context, paymentOrder, checkoutRequest) (checkoutReservation, error)
	SaveCheckout(context.Context, checkoutReservation, stripeCheckoutSession) (checkoutReservation, error)
	InsertInbox(context.Context, providerFact, []byte) (inboxOutcome, error)
	Ping(context.Context) error
	Backlog(context.Context) (backlogState, error)
}

type adapterHTTP struct {
	config     runtimeConfig
	store      handlerStore
	stripe     stripeGateway
	billing    billingGateway
	jwks       *rs.JWKSCache
	httpClient *http.Client
	now        func() time.Time
	metrics    *adapterMetrics
}

func newAdapterHandler(
	config runtimeConfig, store handlerStore, stripe stripeGateway, billing billingGateway,
	jwks *rs.JWKSCache, client *http.Client, metrics *adapterMetrics,
) (http.Handler, error) {
	trusted, err := middleware.NewTrustedProxies([]string{}, 0)
	if err != nil {
		return nil, err
	}
	if metrics == nil {
		metrics = &adapterMetrics{}
	}
	adapter := &adapterHTTP{
		config: config, store: store, stripe: stripe, billing: billing,
		jwks: jwks, httpClient: client, now: time.Now, metrics: metrics,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(pathLive, adapter.handleLive)
	mux.HandleFunc(pathReady, adapter.handleReady)
	mux.HandleFunc(pathMetrics, adapter.handleMetrics)
	mux.Handle(pathStripeWebhook, withRequestDeadline(config.HandlerTimeout, http.HandlerFunc(adapter.handleStripeWebhook)))
	checkout := rs.HTTPMiddleware(rs.Config{
		Issuer: config.Issuer, JWKSCache: jwks, ExpectedAud: config.Audience,
		TrustedProxies: trusted,
	}, http.HandlerFunc(adapter.handleCheckout))
	mux.Handle(pathCheckout, withRequestDeadline(config.HandlerTimeout, checkout))
	return securityHeaders(mux), nil
}

func withRequestDeadline(timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), timeout)
		defer cancel()
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func (a *adapterHTTP) handleStripeWebhook(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !isJSONRequest(request) {
		a.rejectWebhook(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	payload, err := readBoundedBody(writer, request, maxWebhookBodyBytes)
	if err != nil {
		a.rejectWebhook(writer, http.StatusRequestEntityTooLarge, "invalid_request")
		return
	}
	if err := verifyStripeSignature(payload, request.Header.Get("Stripe-Signature"), a.config.WebhookSecrets, a.now()); err != nil {
		a.rejectWebhook(writer, http.StatusBadRequest, ErrInvalidSignature)
		return
	}
	binding := stripeEventBinding{
		LiveMode: a.config.StripeLiveMode, Account: a.config.StripeAccount,
		APIVersion: a.config.WebhookAPIVersion,
	}
	fact, err := parseProviderFact(payload, binding, a.now())
	if errors.Is(err, errUnsupportedEvent) || errors.Is(err, errIgnoredEvent) {
		a.metrics.webhookIgnored.Add(1)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		a.rejectWebhook(writer, http.StatusBadRequest, ErrInvalidEvent)
		return
	}
	_, err = a.store.InsertInbox(request.Context(), fact, payloadDigest(payload))
	switch {
	case errors.Is(err, errInboxConflict):
		a.metrics.webhookConflict.Add(1)
		writeJSON(writer, http.StatusConflict, map[string]string{"error": ErrEventConflict})
	case err != nil:
		a.metrics.webhookRejected.Add(1)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": ErrUnavailable})
	default:
		a.metrics.webhookAccepted.Add(1)
		writeJSON(writer, http.StatusOK, map[string]bool{"received": true})
	}
}

func (a *adapterHTTP) rejectWebhook(writer http.ResponseWriter, status int, code string) {
	a.metrics.webhookRejected.Add(1)
	writeJSON(writer, status, map[string]string{"error": code})
}

func (a *adapterHTTP) handleCheckout(writer http.ResponseWriter, request *http.Request) {
	privateNoStore(writer)
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input checkoutRequest
	if err := decodeRequestJSON(writer, request, 32*1024, &input); err != nil || !a.validCheckoutRequest(input) {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	binding, ok := a.authorizeCheckout(writer, request, input)
	if !ok {
		return
	}
	order, err := a.billing.GetOrder(request.Context(), binding, input.OrderID)
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, map[string]string{"error": ErrBillingUnavailable})
		return
	}
	if order.Status != "pending" || order.ProviderOrderID != "" {
		writeJSON(writer, http.StatusConflict, map[string]string{"error": ErrOrderNotPending})
		return
	}
	reservation, err := a.store.ReserveCheckout(request.Context(), order, input)
	if err != nil {
		a.writeCheckoutStoreError(writer, err)
		return
	}
	if reservation.Rotated {
		a.metrics.checkoutExpired.Add(1)
	}
	if a.writeExistingCheckout(writer, reservation) {
		return
	}
	session, err := a.stripe.CreateCheckout(request.Context(), order, input, reservation.IdempotencyKey)
	if err != nil {
		a.metrics.checkoutFailed.Add(1)
		writeJSON(writer, http.StatusBadGateway, map[string]string{"error": ErrProviderUnavailable})
		return
	}
	reservation, err = a.store.SaveCheckout(request.Context(), reservation, session)
	if err != nil {
		a.metrics.checkoutFailed.Add(1)
		a.writeCheckoutStoreError(writer, err)
		return
	}
	a.metrics.checkoutCreated.Add(1)
	writeCheckoutResponse(writer, http.StatusCreated, reservation)
}

func (a *adapterHTTP) writeExistingCheckout(writer http.ResponseWriter, reservation checkoutReservation) bool {
	if reservation.available(a.now()) {
		a.metrics.checkoutReplay.Add(1)
		writeCheckoutResponse(writer, http.StatusOK, reservation)
		return true
	}
	if !reservation.complete() {
		return false
	}
	a.metrics.checkoutExpired.Add(1)
	writeJSON(writer, http.StatusConflict, map[string]string{"error": "checkout_expired"})
	return true
}

func (a *adapterHTTP) authorizeCheckout(
	writer http.ResponseWriter, request *http.Request, input checkoutRequest,
) (*tenantBinding, bool) {
	claims, ok := rs.ClaimsFromContext(request.Context())
	if !ok || claims == nil || claims.Subject == "" {
		writeCheckoutChallenge(writer, http.StatusUnauthorized, "invalid_token", "")
		return nil, false
	}
	if claims.ClientID != "" && claims.Subject == claims.ClientID {
		return a.authorizeMachineCheckout(writer, claims, input)
	}
	return a.authorizeUserCheckout(writer, claims, input)
}

func (a *adapterHTTP) authorizeMachineCheckout(
	writer http.ResponseWriter, claims *rs.Claims, input checkoutRequest,
) (*tenantBinding, bool) {
	binding := a.config.CheckoutBindings[claims.ClientID]
	if rs.CheckScope(claims, scopeCheckoutCreate) != nil || binding == nil ||
		(input.TenantID != "" && input.TenantID != binding.TenantID) {
		writeCheckoutChallenge(writer, http.StatusForbidden, "insufficient_scope", scopeCheckoutCreate)
		return nil, false
	}
	return binding, true
}

func (a *adapterHTTP) authorizeUserCheckout(
	writer http.ResponseWriter, claims *rs.Claims, input checkoutRequest,
) (*tenantBinding, bool) {
	binding := a.config.TenantBindings[input.TenantID]
	if claims.Subject == "" || rs.CheckScope(claims, scopeAdminWrite) != nil || binding == nil {
		writeCheckoutChallenge(writer, http.StatusForbidden, "insufficient_scope", scopeAdminWrite)
		return nil, false
	}
	return binding, true
}

func (a *adapterHTTP) validCheckoutRequest(request checkoutRequest) bool {
	return (request.TenantID == "" || validIdentity(request.TenantID)) && validIdentity(request.OrderID) &&
		a.validReturnURL(request.SuccessURL) && a.validReturnURL(request.CancelURL)
}

func (a *adapterHTTP) validReturnURL(raw string) bool {
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\r\n\x00") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && a.config.AllowInsecureLocal && loopbackHost(parsed.Hostname())) {
		return false
	}
	_, ok := a.config.ReturnOrigins[parsed.Scheme+"://"+parsed.Host]
	return ok
}

func (a *adapterHTTP) writeCheckoutStoreError(writer http.ResponseWriter, err error) {
	if errors.Is(err, errCheckoutConflict) {
		writeJSON(writer, http.StatusConflict, map[string]string{"error": ErrCheckoutConflict})
		return
	}
	writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": ErrUnavailable})
}

func (a *adapterHTTP) handleLive(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *adapterHTTP) handleReady(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), a.config.ReadyTimeout)
	defer cancel()
	if a.store.Ping(ctx) != nil || a.jwksUnavailable(ctx) {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (a *adapterHTTP) jwksUnavailable(ctx context.Context) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.JWKSURL, nil)
	if err != nil {
		return true
	}
	response, err := a.httpClient.Do(request)
	if err != nil {
		return true
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxJSONResponseBytes))
	return response.StatusCode != http.StatusOK
}

func (a *adapterHTTP) handleMetrics(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), a.config.ReadyTimeout)
	defer cancel()
	backlog, err := a.store.Backlog(ctx)
	if err != nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": ErrUnavailable})
		return
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(writer, a.metrics, backlog, a.backlogThresholdExceeded(backlog))
}

func (a *adapterHTTP) backlogThresholdExceeded(backlog backlogState) bool {
	if backlog.Count > a.config.MaxBacklog {
		return true
	}
	return !backlog.Oldest.IsZero() && a.now().Sub(backlog.Oldest) > a.config.MaxBacklogAge
}

func writeMetrics(writer io.Writer, metrics *adapterMetrics, backlog backlogState, degraded bool) {
	values := []struct {
		name  string
		value uint64
	}{
		{"snaplink_stripe_webhook_accepted_total", metrics.webhookAccepted.Load()},
		{"snaplink_stripe_webhook_ignored_total", metrics.webhookIgnored.Load()},
		{"snaplink_stripe_webhook_rejected_total", metrics.webhookRejected.Load()},
		{"snaplink_stripe_webhook_conflict_total", metrics.webhookConflict.Load()},
		{"snaplink_stripe_checkout_created_total", metrics.checkoutCreated.Load()},
		{"snaplink_stripe_checkout_replay_total", metrics.checkoutReplay.Load()},
		{"snaplink_stripe_checkout_expired_total", metrics.checkoutExpired.Load()},
		{"snaplink_stripe_checkout_failed_total", metrics.checkoutFailed.Load()},
		{"snaplink_stripe_relay_delivered_total", metrics.relayDelivered.Load()},
		{"snaplink_stripe_relay_retried_total", metrics.relayRetried.Load()},
		{"snaplink_stripe_relay_quarantined_total", metrics.relayQuarantined.Load()},
	}
	for _, metric := range values {
		_, _ = fmt.Fprintf(writer, "%s %d\n", metric.name, metric.value)
	}
	_, _ = fmt.Fprintf(writer, "snaplink_stripe_inbox_pending %d\n", backlog.Count)
	_, _ = fmt.Fprintf(writer, "snaplink_stripe_inbox_quarantined %d\n", backlog.Quarantined)
	_, _ = fmt.Fprintf(writer, "snaplink_stripe_backlog_threshold_exceeded %d\n", boolMetric(degraded))
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}

func decodeRequestJSON(writer http.ResponseWriter, request *http.Request, maximum int64, target any) error {
	if !isJSONRequest(request) {
		return errInvalidProviderFact
	}
	payload, err := readBoundedBody(writer, request, maximum)
	if err != nil {
		return err
	}
	return decodeStrictJSON(payload, target)
}

func readBoundedBody(writer http.ResponseWriter, request *http.Request, maximum int64) ([]byte, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximum)
	return io.ReadAll(request.Body)
}

func isJSONRequest(request *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func privateNoStore(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
}

func writeCheckoutChallenge(writer http.ResponseWriter, status int, code, scope string) {
	privateNoStore(writer)
	challenge := "Bearer realm=" + security.QuoteAuthParam("stripe-adapter")
	challenge += ", error=" + security.QuoteAuthParam(code)
	if scope != "" {
		challenge += ", scope=" + security.QuoteAuthParam(scope)
	}
	writer.Header().Set("WWW-Authenticate", challenge)
	writeJSON(writer, status, map[string]string{"error": code})
}

func writeCheckoutResponse(writer http.ResponseWriter, status int, reservation checkoutReservation) {
	writeJSON(writer, status, map[string]any{
		"session_id": reservation.SessionID, "redirect_url": reservation.RedirectURL,
		"expires_at": reservation.ExpiresAt,
	})
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}
