package main

import (
	"errors"
	"sync/atomic"
	"time"
)

const (
	programName           = "snaplink-stripe-adapter"
	providerStripe        = "stripe"
	paymentSourceStripe   = "payment:stripe"
	scopeCheckoutCreate   = "billing:checkout:create"
	scopeAdminWrite       = "admin:write"
	scopePaymentOrderRead = "billing:payment:order:read"
	scopePaymentWrite     = "billing:payment:write"
	pathCheckout          = "/api/v1/checkout/sessions"
	pathStripeWebhook     = "/webhooks/stripe"
	pathLive              = "/livez"
	pathReady             = "/readyz"
	pathMetrics           = "/metrics"
	stripeEventSucceeded  = "payment_intent.succeeded"
	stripeEventFailed     = "payment_intent.payment_failed"
	stripeEventRefund     = "refund.created"
	stripeEventRefundEdit = "refund.updated"
	stripeEventWithdrawn  = "charge.dispute.funds_withdrawn"
	stripeEventReinstated = "charge.dispute.funds_reinstated"
	eventCaptured         = "captured"
	eventRejectedLegacy   = "rejected"
	eventRefunded         = "refunded"
	eventChargeback       = "chargeback"
	eventChargebackRev    = "chargeback_reversed"
	metadataTenantID      = "snaplink_tenant_id"
	metadataOrderID       = "snaplink_order_id"
	maxWebhookBodyBytes   = int64(256 * 1024)
	maxJSONResponseBytes  = int64(256 * 1024)
	maxSignatureBytes     = 8 * 1024
	maxWebhookSecrets     = 16
	webhookTolerance      = 5 * time.Minute
)

// Wire error codes are exported so the repository contract gate can prove
// every documented adapter response remains backed by executable code.
const (
	ErrBillingUnavailable  = "billing_unavailable"
	ErrProviderUnavailable = "provider_unavailable"
	ErrOrderNotPending     = "order_not_pending"
	ErrCheckoutConflict    = "checkout_conflict"
	ErrInvalidSignature    = "invalid_signature"
	ErrInvalidEvent        = "invalid_event"
	ErrEventConflict       = "event_conflict"
	ErrUnavailable         = "unavailable"
)

var (
	errInvalidConfig       = errors.New("stripe adapter: invalid configuration")
	errInvalidSignature    = errors.New("stripe adapter: invalid webhook signature")
	errUnsupportedEvent    = errors.New("stripe adapter: unsupported Stripe event")
	errIgnoredEvent        = errors.New("stripe adapter: ignored Stripe event")
	errInvalidProviderFact = errors.New("stripe adapter: invalid provider fact")
	errInboxConflict       = errors.New("stripe adapter: event id digest conflict")
	errCheckoutConflict    = errors.New("stripe adapter: checkout mapping conflict")
	errMappingNotFound     = errors.New("stripe adapter: trusted checkout mapping not found")
	errDeliveryNotReady    = errors.New("stripe adapter: delivery predecessor not ready")
	errClaimLost           = errors.New("stripe adapter: inbox claim lost")
)

type tenantBinding struct {
	TenantID          string
	CheckoutClientIDs []string
	BillingClientID   string
	BillingSecret     string
}

type paymentOrder struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Provider        string    `json:"provider"`
	ProviderOrderID string    `json:"provider_order_id"`
	Currency        string    `json:"currency"`
	AmountMinor     int64     `json:"amount_minor"`
	PaidMinor       int64     `json:"paid_minor"`
	RefundedMinor   int64     `json:"refunded_minor"`
	Status          string    `json:"status"`
	Revision        uint64    `json:"revision"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type checkoutRequest struct {
	TenantID   string `json:"tenant_id,omitempty"`
	OrderID    string `json:"order_id"`
	SuccessURL string `json:"success_url"`
	CancelURL  string `json:"cancel_url"`
}

type checkoutReservation struct {
	TenantID       string
	OrderID        string
	Currency       string
	AmountMinor    int64
	IdempotencyKey string
	RequestDigest  []byte
	SessionID      string
	RedirectURL    string
	ExpiresAt      time.Time
	PaymentIntent  string
	Generation     int64
	Rotated        bool
}

func (r checkoutReservation) complete() bool {
	return r.SessionID != "" && r.RedirectURL != "" && !r.ExpiresAt.IsZero()
}

func (r checkoutReservation) available(at time.Time) bool {
	return r.complete() && at.Before(r.ExpiresAt)
}

type stripeCheckoutSession struct {
	ID            string
	URL           string
	ExpiresAt     time.Time
	PaymentIntent string
}

type providerFact struct {
	EventID               string
	EventType             string
	NormalizedType        string
	ProviderObjectID      string
	PaymentIntentID       string
	ChargeID              string
	MetadataTenantID      string
	MetadataOrderID       string
	Currency              string
	ProviderAmountMinor   int64
	NormalizedAmountMinor int64
	OccurredAt            time.Time
}

type inboxOutcome int

const (
	inboxInserted inboxOutcome = iota + 1
	inboxReplay
	inboxEffectReplay
)

type inboxClaim struct {
	providerFact
	Digest          []byte
	ClaimOwner      string
	ClaimGeneration int64
	AttemptCount    int64
}

type trustedDelivery struct {
	EventID         string
	TenantID        string
	OrderID         string
	ProviderOrderID string
	Type            string
	Currency        string
	AmountMinor     int64
	OccurredAt      time.Time
	ClaimOwner      string
	ClaimGeneration int64
}

type checkoutMapping struct {
	TenantID      string
	OrderID       string
	Currency      string
	AmountMinor   int64
	PaymentIntent string
	ChargeID      string
}

type backlogState struct {
	Count       int64
	Quarantined int64
	Oldest      time.Time
}

type deliveryError struct {
	category  string
	permanent bool
	err       error
}

func (e *deliveryError) Error() string { return e.category + ": " + e.err.Error() }
func (e *deliveryError) Unwrap() error { return e.err }

type adapterMetrics struct {
	webhookAccepted  atomic.Uint64
	webhookIgnored   atomic.Uint64
	webhookRejected  atomic.Uint64
	webhookConflict  atomic.Uint64
	checkoutCreated  atomic.Uint64
	checkoutReplay   atomic.Uint64
	checkoutExpired  atomic.Uint64
	checkoutFailed   atomic.Uint64
	relayDelivered   atomic.Uint64
	relayRetried     atomic.Uint64
	relayQuarantined atomic.Uint64
}
