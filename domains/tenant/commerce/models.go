// Package commerce owns tenant-scoped commercial contracts. It lives below
// tenant because domains/ is at its frozen fan-out ceiling and a subscription
// is part of the tenant business boundary, not authentication state.
package commerce

import (
	"errors"
	"strings"
	"time"
)

// FeatureKey is a stable product capability identifier shared with consoles
// and resource services. Custom keys are allowed for separately deployed apps.
type FeatureKey string

const (
	FeatureCoreSSO          FeatureKey = "core_sso"
	FeatureMultiTenant      FeatureKey = "multi_tenant"
	FeatureAuditGovernance  FeatureKey = "audit_governance"
	FeatureNotifications    FeatureKey = "notifications"
	FeatureIM               FeatureKey = "im"
	FeatureAccount          FeatureKey = "account"
	FeatureVault            FeatureKey = "vault"
	FeatureSCIM             FeatureKey = "scim"
	FeatureFederation       FeatureKey = "federation"
	FeatureHighAvailability FeatureKey = "high_availability"
)

// LimitKey identifies a stable quota dimension. A hard grant is authoritative
// only when the owning resource service enforces it atomically with mutation.
type LimitKey string

const (
	LimitUsers              LimitKey = "users"
	LimitClients            LimitKey = "clients"
	LimitSessions           LimitKey = "sessions"
	LimitTokenRate          LimitKey = "token_rate"
	LimitStorageBytes       LimitKey = "storage_bytes"
	LimitStorageObjects     LimitKey = "storage_objects"
	LimitStorageAllocated   LimitKey = "storage_bytes_allocated"
	LimitStorageReclaimed   LimitKey = "storage_bytes_reclaimed"
	LimitObjectsCreated     LimitKey = "storage_objects_created"
	LimitObjectsDeleted     LimitKey = "storage_objects_deleted"
	LimitMessagesPerMonth   LimitKey = "messages_per_month"
	LimitNotificationsMonth LimitKey = "notifications_per_month"
	LimitAuditEventsMonth   LimitKey = "audit_events_per_month"
	LimitAuditRetentionDays LimitKey = "audit_retention_days"
)

// LimitGrant removes the usual ambiguity around a numeric zero. Unlimited is
// explicit; otherwise Hard is the enforceable ceiling, including zero.
type LimitGrant struct {
	Soft      int64 `json:"soft"`
	Hard      int64 `json:"hard"`
	Unlimited bool  `json:"unlimited,omitempty"`
}

func (g LimitGrant) Validate() error {
	if g.Soft < 0 || g.Hard < 0 {
		return errors.Join(ErrInvalidPlan, errors.New("limits must be non-negative"))
	}
	if g.Unlimited && (g.Soft != 0 || g.Hard != 0) {
		return errors.Join(ErrInvalidPlan, errors.New("unlimited limit cannot set soft or hard"))
	}
	if !g.Unlimited && g.Soft > g.Hard {
		return errors.Join(ErrInvalidPlan, errors.New("soft limit exceeds hard limit"))
	}
	return nil
}

// Money stores integer minor units only. Floating point is never accepted on
// a financial boundary.
type Money struct {
	Currency   string `json:"currency"`
	MinorUnits int64  `json:"minor_units"`
}

func (m Money) Validate() error {
	if len(m.Currency) != 3 || m.Currency != strings.ToUpper(m.Currency) {
		return errors.Join(ErrInvalidMoney, errors.New("currency must be uppercase ISO-4217 code"))
	}
	if m.MinorUnits < 0 {
		return errors.Join(ErrInvalidMoney, errors.New("minor_units must be non-negative"))
	}
	return nil
}

// RenewalTerms is copied from the immutable plan version when a subscription
// is created or explicitly changes plan. Automatic settlement never consults
// a mutable catalog view for price or period semantics.
type RenewalTerms struct {
	Interval        BillingInterval `json:"billing_interval"`
	Price           Money           `json:"price"`
	GracePeriodDays int             `json:"grace_period_days,omitempty"`
}

func (terms RenewalTerms) Validate() error {
	if !validBillingInterval(terms.Interval) {
		return errors.Join(ErrInvalidSubscription, errors.New("invalid renewal interval"))
	}
	if err := terms.Price.Validate(); err != nil {
		return errors.Join(ErrInvalidSubscription, err)
	}
	if terms.GracePeriodDays < 0 {
		return errors.Join(ErrInvalidSubscription, errors.New("negative renewal grace period"))
	}
	return nil
}

type BillingInterval string

const (
	IntervalNone  BillingInterval = "none"
	IntervalMonth BillingInterval = "month"
	IntervalYear  BillingInterval = "year"
)

func validBillingInterval(interval BillingInterval) bool {
	return interval == IntervalNone || interval == IntervalMonth || interval == IntervalYear
}

type PlanStatus string

const (
	PlanActive  PlanStatus = "active"
	PlanRetired PlanStatus = "retired"
)

// Plan is immutable per (ID, Version). Publishing a changed commercial offer
// creates a new version so existing subscriptions remain reproducible.
type Plan struct {
	ID              string                  `json:"id"`
	Version         uint64                  `json:"version"`
	Name            string                  `json:"name"`
	Status          PlanStatus              `json:"status"`
	Interval        BillingInterval         `json:"billing_interval"`
	Price           Money                   `json:"price"`
	GracePeriodDays int                     `json:"grace_period_days,omitempty"`
	Features        map[FeatureKey]bool     `json:"features"`
	Limits          map[LimitKey]LimitGrant `json:"limits"`
	CreatedAt       time.Time               `json:"created_at"`
}

func (p *Plan) Validate() error {
	if p == nil || p.ID == "" || p.Version == 0 || strings.TrimSpace(p.Name) == "" {
		return errors.Join(ErrInvalidPlan, errors.New("id, version and name are required"))
	}
	if p.Status != PlanActive && p.Status != PlanRetired {
		return errors.Join(ErrInvalidPlan, errors.New("invalid plan status"))
	}
	if !validBillingInterval(p.Interval) {
		return errors.Join(ErrInvalidPlan, errors.New("invalid billing interval"))
	}
	if err := p.Price.Validate(); err != nil {
		return errors.Join(ErrInvalidPlan, err)
	}
	if p.GracePeriodDays < 0 {
		return errors.Join(ErrInvalidPlan, errors.New("grace_period_days must be non-negative"))
	}
	for key, grant := range p.Limits {
		if key == "" {
			return errors.Join(ErrInvalidPlan, errors.New("empty limit key"))
		}
		if err := grant.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// PlanRef pins a subscription and entitlement to an immutable catalog row.
type PlanRef struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

type SubscriptionStatus string

const (
	SubscriptionPending  SubscriptionStatus = "pending"
	SubscriptionTrialing SubscriptionStatus = "trialing"
	SubscriptionActive   SubscriptionStatus = "active"
	SubscriptionPastDue  SubscriptionStatus = "past_due"
	SubscriptionPaused   SubscriptionStatus = "paused"
	SubscriptionCanceled SubscriptionStatus = "canceled"
	SubscriptionExpired  SubscriptionStatus = "expired"
)

// Subscription is the contract lifecycle. Provider references are identifiers
// only; payment credentials and secrets never enter this aggregate.
type Subscription struct {
	ID                     string             `json:"id"`
	TenantID               string             `json:"tenant_id"`
	Plan                   PlanRef            `json:"plan"`
	Renewal                RenewalTerms       `json:"renewal"`
	Status                 SubscriptionStatus `json:"status"`
	CurrentPeriodStart     time.Time          `json:"current_period_start"`
	CurrentPeriodEnd       time.Time          `json:"current_period_end"`
	TrialEnd               time.Time          `json:"trial_end,omitempty"`
	GraceUntil             time.Time          `json:"grace_until,omitempty"`
	CancelAtPeriodEnd      bool               `json:"cancel_at_period_end,omitempty"`
	CanceledAt             time.Time          `json:"canceled_at,omitempty"`
	Provider               string             `json:"provider,omitempty"`
	ProviderSubscriptionID string             `json:"provider_subscription_id,omitempty"`
	RenewalNextAttemptAt   time.Time          `json:"renewal_next_attempt_at,omitempty"`
	Revision               uint64             `json:"revision"`
	CreatedAt              time.Time          `json:"created_at"`
	UpdatedAt              time.Time          `json:"updated_at"`
}

func (s *Subscription) Validate() error {
	if s == nil || s.ID == "" || s.TenantID == "" || s.Plan.ID == "" || s.Plan.Version == 0 {
		return errors.Join(ErrInvalidSubscription, errors.New("id, tenant_id and plan are required"))
	}
	if !validSubscriptionStatus(s.Status) || s.Revision == 0 {
		return errors.Join(ErrInvalidSubscription, errors.New("invalid status or revision"))
	}
	if err := s.Renewal.Validate(); err != nil {
		return err
	}
	if s.Renewal.Interval != IntervalNone && s.CurrentPeriodEnd.IsZero() {
		return errors.Join(ErrInvalidSubscription, errors.New("renewing subscription requires period end"))
	}
	if !s.CurrentPeriodEnd.IsZero() && s.CurrentPeriodEnd.Before(s.CurrentPeriodStart) {
		return errors.Join(ErrInvalidSubscription, errors.New("period end precedes start"))
	}
	return nil
}

func validSubscriptionStatus(status SubscriptionStatus) bool {
	switch status {
	case SubscriptionPending, SubscriptionTrialing, SubscriptionActive,
		SubscriptionPastDue, SubscriptionPaused, SubscriptionCanceled, SubscriptionExpired:
		return true
	default:
		return false
	}
}

// EntitlementSnapshot is a local, versioned projection used on request paths.
// Authentication never calls a payment provider to decide whether access is
// allowed.
type EntitlementSnapshot struct {
	TenantID       string                  `json:"tenant_id"`
	SubscriptionID string                  `json:"subscription_id"`
	Plan           PlanRef                 `json:"plan"`
	Revision       uint64                  `json:"revision"`
	Active         bool                    `json:"active"`
	Features       map[FeatureKey]bool     `json:"features"`
	Limits         map[LimitKey]LimitGrant `json:"limits"`
	EffectiveAt    time.Time               `json:"effective_at"`
	ExpiresAt      time.Time               `json:"expires_at,omitempty"`
	GeneratedAt    time.Time               `json:"generated_at"`
}

func (e *EntitlementSnapshot) FeatureEnabled(key FeatureKey, at time.Time) bool {
	return e != nil && e.effective(at) && e.Features[key]
}

func (e *EntitlementSnapshot) Limit(key LimitKey, at time.Time) (LimitGrant, bool) {
	if e == nil || !e.effective(at) {
		return LimitGrant{}, false
	}
	grant, ok := e.Limits[key]
	return grant, ok
}

func (e *EntitlementSnapshot) effective(at time.Time) bool {
	if !e.Active || at.Before(e.EffectiveAt) {
		return false
	}
	return e.ExpiresAt.IsZero() || at.Before(e.ExpiresAt)
}

type LedgerKind string

const (
	LedgerTopUp              LedgerKind = "top_up"
	LedgerUsage              LedgerKind = "usage"
	LedgerSubscriptionCharge LedgerKind = "subscription"
	LedgerRefund             LedgerKind = "refund"
	LedgerChargebackReversal LedgerKind = "chargeback_reversal"
	LedgerAdjustment         LedgerKind = "adjustment"
)

// Wallet is a materialized view; immutable LedgerEntry rows remain the source
// of truth and can always reconstruct this balance.
type WalletStatus string

const (
	WalletActive WalletStatus = "active"
	WalletFrozen WalletStatus = "frozen"
)

type Wallet struct {
	TenantID     string       `json:"tenant_id"`
	Currency     string       `json:"currency"`
	BalanceMinor int64        `json:"balance_minor"`
	Status       WalletStatus `json:"status"`
	Version      uint64       `json:"version"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

type LedgerEntry struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Currency       string     `json:"currency"`
	Kind           LedgerKind `json:"kind"`
	AmountMinor    int64      `json:"amount_minor"`
	BalanceAfter   int64      `json:"balance_after"`
	WalletVersion  uint64     `json:"wallet_version"`
	IdempotencyKey string     `json:"idempotency_key"`
	Reference      string     `json:"reference,omitempty"`
	OccurredAt     time.Time  `json:"occurred_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

func (e *LedgerEntry) Validate() error {
	if e == nil || e.ID == "" || e.TenantID == "" || e.IdempotencyKey == "" {
		return errors.Join(ErrInvalidLedgerEntry, errors.New("id, tenant_id and idempotency_key are required"))
	}
	if len(e.Currency) != 3 || e.Currency != strings.ToUpper(e.Currency) || e.AmountMinor == 0 {
		return errors.Join(ErrInvalidLedgerEntry, errors.New("currency or amount is invalid"))
	}
	if !validLedgerSign(e.Kind, e.AmountMinor) {
		return errors.Join(ErrInvalidLedgerEntry, errors.New("entry kind and amount sign disagree"))
	}
	return nil
}

func validLedgerSign(kind LedgerKind, amount int64) bool {
	switch kind {
	case LedgerTopUp, LedgerChargebackReversal:
		return amount > 0
	case LedgerUsage, LedgerSubscriptionCharge, LedgerRefund:
		return amount < 0
	case LedgerAdjustment:
		return amount != 0
	default:
		return false
	}
}

type PaymentOrderStatus string

const (
	PaymentPending           PaymentOrderStatus = "pending"
	PaymentSucceeded         PaymentOrderStatus = "succeeded"
	PaymentFailed            PaymentOrderStatus = "failed"
	PaymentCanceled          PaymentOrderStatus = "canceled"
	PaymentPartiallyRefunded PaymentOrderStatus = "partially_refunded"
	PaymentRefunded          PaymentOrderStatus = "refunded"
)

// PaymentOrder is the local top-up saga. It stores provider identifiers but no
// payment credential, card data, bearer token, or provider secret.
type PaymentOrder struct {
	ID              string             `json:"id"`
	TenantID        string             `json:"tenant_id"`
	Provider        string             `json:"provider"`
	ProviderOrderID string             `json:"provider_order_id,omitempty"`
	Currency        string             `json:"currency"`
	AmountMinor     int64              `json:"amount_minor"`
	PaidMinor       int64              `json:"paid_minor"`
	RefundedMinor   int64              `json:"refunded_minor"`
	Status          PaymentOrderStatus `json:"status"`
	IdempotencyKey  string             `json:"idempotency_key"`
	Revision        uint64             `json:"revision"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

func (o *PaymentOrder) Validate() error {
	if o == nil || o.ID == "" || o.TenantID == "" || o.Provider == "" || o.IdempotencyKey == "" {
		return errors.Join(ErrInvalidPayment, errors.New("order identity is required"))
	}
	if err := (Money{Currency: o.Currency, MinorUnits: o.AmountMinor}).Validate(); err != nil {
		return errors.Join(ErrInvalidPayment, err)
	}
	if o.AmountMinor == 0 || o.Revision == 0 || !validPaymentStatus(o.Status) {
		return errors.Join(ErrInvalidPayment, errors.New("amount, revision or status is invalid"))
	}
	if o.PaidMinor < 0 || o.RefundedMinor < 0 || o.RefundedMinor > o.PaidMinor || o.PaidMinor > o.AmountMinor {
		return errors.Join(ErrInvalidPayment, errors.New("payment totals are invalid"))
	}
	if !validPaymentTotals(o) {
		return errors.Join(ErrInvalidPayment, errors.New("payment status and totals disagree"))
	}
	return nil
}

func validPaymentTotals(order *PaymentOrder) bool {
	switch order.Status {
	case PaymentPending, PaymentFailed, PaymentCanceled:
		return order.PaidMinor == 0 && order.RefundedMinor == 0
	case PaymentSucceeded:
		return order.PaidMinor == order.AmountMinor && order.RefundedMinor == 0
	case PaymentPartiallyRefunded:
		return order.PaidMinor == order.AmountMinor && order.RefundedMinor > 0 &&
			order.RefundedMinor < order.PaidMinor
	case PaymentRefunded:
		return order.PaidMinor == order.AmountMinor && order.RefundedMinor == order.PaidMinor
	default:
		return false
	}
}

func validPaymentStatus(status PaymentOrderStatus) bool {
	switch status {
	case PaymentPending, PaymentSucceeded, PaymentFailed, PaymentCanceled,
		PaymentPartiallyRefunded, PaymentRefunded:
		return true
	default:
		return false
	}
}

type PaymentEventType string

const (
	PaymentCaptured           PaymentEventType = "captured"
	PaymentRejected           PaymentEventType = "rejected"
	PaymentRefundedEvent      PaymentEventType = "refunded"
	PaymentChargeback         PaymentEventType = "chargeback"
	PaymentChargebackReversed PaymentEventType = "chargeback_reversed"
)

// PaymentEvent is the normalized, signature-verified provider fact accepted
// from an authenticated out-of-process provider adapter.
type PaymentEvent struct {
	ID              string           `json:"id"`
	Provider        string           `json:"provider"`
	ProviderOrderID string           `json:"provider_order_id"`
	OrderID         string           `json:"order_id"`
	Type            PaymentEventType `json:"type"`
	Currency        string           `json:"currency"`
	AmountMinor     int64            `json:"amount_minor"`
	OccurredAt      time.Time        `json:"occurred_at"`
	AppliedAt       time.Time        `json:"applied_at"`
	LedgerEntryID   string           `json:"ledger_entry_id,omitempty"`
}

func (e *PaymentEvent) Validate() error {
	if e == nil || e.ID == "" || e.Provider == "" || e.ProviderOrderID == "" || e.OrderID == "" {
		return errors.Join(ErrInvalidPayment, errors.New("payment event identity is required"))
	}
	if len(e.Currency) != 3 || e.Currency != strings.ToUpper(e.Currency) {
		return errors.Join(ErrInvalidPayment, errors.New("payment event currency is invalid"))
	}
	if !validPaymentEventAmount(e.Type, e.AmountMinor) {
		return errors.Join(ErrInvalidPayment, errors.New("payment event type or amount is invalid"))
	}
	if e.OccurredAt.IsZero() {
		return errors.Join(ErrInvalidPayment, errors.New("payment event occurred_at is required"))
	}
	return nil
}

func validPaymentEventAmount(eventType PaymentEventType, amount int64) bool {
	switch eventType {
	case PaymentCaptured, PaymentRefundedEvent, PaymentChargeback, PaymentChargebackReversed:
		return amount > 0
	case PaymentRejected:
		return amount == 0
	default:
		return false
	}
}

type ReconciliationIssue struct {
	OrderID       string `json:"order_id"`
	ExpectedMinor int64  `json:"expected_minor"`
	LedgerMinor   int64  `json:"ledger_minor"`
}

type ReconciliationReport struct {
	TenantID      string                `json:"tenant_id"`
	OrdersChecked int                   `json:"orders_checked"`
	Issues        []ReconciliationIssue `json:"issues"`
}
