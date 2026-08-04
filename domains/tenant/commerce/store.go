package commerce

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrStoreRequired             = errors.New("commerce: store required")
	ErrInvalidPlan               = errors.New("commerce: invalid plan")
	ErrInvalidMoney              = errors.New("commerce: invalid money")
	ErrPlanNotFound              = errors.New("commerce: plan not found")
	ErrPlanConflict              = errors.New("commerce: plan version conflict")
	ErrPlanRetired               = errors.New("commerce: plan retired")
	ErrInvalidSubscription       = errors.New("commerce: invalid subscription")
	ErrSubscriptionNotFound      = errors.New("commerce: subscription not found")
	ErrEntitlementNotFound       = errors.New("commerce: entitlement not found")
	ErrTenantSubscribed          = errors.New("commerce: tenant already has a live subscription")
	ErrTransitionDenied          = errors.New("commerce: subscription transition denied")
	ErrRevisionConflict          = errors.New("commerce: revision conflict")
	ErrInvalidLedgerEntry        = errors.New("commerce: invalid ledger entry")
	ErrInsufficientFunds         = errors.New("commerce: insufficient wallet funds")
	ErrWalletOverflow            = errors.New("commerce: wallet balance overflow")
	ErrWalletFrozen              = errors.New("commerce: wallet frozen")
	ErrIdempotencyConflict       = errors.New("commerce: idempotency conflict")
	ErrInvalidPayment            = errors.New("commerce: invalid payment")
	ErrPaymentNotFound           = errors.New("commerce: payment order not found")
	ErrPaymentEventNotFound      = errors.New("commerce: payment event not found")
	ErrPaymentStateConflict      = errors.New("commerce: payment state conflict")
	ErrPaymentSourceUnauthorized = errors.New("commerce: payment source unauthorized")
	ErrInvalidRenewal            = errors.New("commerce: invalid renewal settlement")
	ErrRenewalClaimLost          = errors.New("commerce: renewal claim lost")
	ErrOutboxNotFound            = errors.New("commerce: outbox event not found")
	ErrOutboxLeaseLost           = errors.New("commerce: outbox lease lost")
	ErrQuotaProjectionLag        = errors.New("commerce: quota projection delivery lag exceeded")
)

type EventType string

const (
	EventSubscriptionCreated       EventType = "snaplink.billing.subscription.created"
	EventSubscriptionPlanChanged   EventType = "snaplink.billing.subscription.plan_changed"
	EventSubscriptionRenewed       EventType = "snaplink.billing.subscription.renewed"
	EventSubscriptionRenewalFailed EventType = "snaplink.billing.subscription.renewal_failed"
	EventSubscriptionStatusChanged EventType = "snaplink.billing.subscription.status_changed"
	EventEntitlementPublished      EventType = "snaplink.billing.entitlement.snapshot_published"
	EventWalletCreditPosted        EventType = "snaplink.billing.wallet.credit_posted"
	EventWalletDebitPosted         EventType = "snaplink.billing.wallet.debit_posted"
	EventWalletAdjustmentPosted    EventType = "snaplink.billing.wallet.adjustment_posted"
	EventWalletFrozen              EventType = "snaplink.billing.wallet.frozen"
	EventTopUpCreated              EventType = "snaplink.billing.topup.created"
	EventTopUpSucceeded            EventType = "snaplink.billing.topup.succeeded"
	EventTopUpFailed               EventType = "snaplink.billing.topup.failed"
	EventTopUpRefunded             EventType = "snaplink.billing.topup.refunded"
	EventTopUpChargeback           EventType = "snaplink.billing.topup.chargeback"
	EventTopUpChargebackReversed   EventType = "snaplink.billing.topup.chargeback_reversed"
	EventUsageRollupClosed         EventType = "snaplink.billing.usage.rollup_closed"
)

type OutboxStatus string

const (
	OutboxPending     OutboxStatus = "pending"
	OutboxLeased      OutboxStatus = "leased"
	OutboxDelivered   OutboxStatus = "delivered"
	OutboxQuarantined OutboxStatus = "quarantined"
	OutboxDead        OutboxStatus = "dead"
)

// OutboxEvent is written atomically with the business aggregate. Payload is a
// bounded, redacted projection; it must never contain credentials or PAN data.
type OutboxEvent struct {
	ID               string            `json:"event_id"`
	TenantID         string            `json:"tenant_id"`
	Type             EventType         `json:"event_type"`
	AggregateType    string            `json:"aggregate_type"`
	AggregateID      string            `json:"aggregate_id"`
	AggregateVersion uint64            `json:"aggregate_version"`
	IdempotencyKey   string            `json:"idempotency_key"`
	OccurredAt       time.Time         `json:"occurred_at"`
	Payload          map[string]string `json:"payload"`
	PayloadDigest    string            `json:"payload_digest"`
	Status           OutboxStatus      `json:"status"`
	Attempts         int               `json:"attempts"`
	NextAttemptAt    time.Time         `json:"next_attempt_at,omitempty"`
	LeaseOwner       string            `json:"lease_owner,omitempty"`
	LeaseUntil       time.Time         `json:"lease_until,omitempty"`
	LastError        string            `json:"last_error,omitempty"`
	DeliveredAt      time.Time         `json:"delivered_at,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

func (e *OutboxEvent) Validate() error {
	if e == nil || e.ID == "" || e.TenantID == "" || e.Type == "" || e.AggregateID == "" {
		return errors.New("commerce: invalid outbox event")
	}
	if e.AggregateType == "" || e.AggregateVersion == 0 || e.IdempotencyKey == "" {
		return errors.New("commerce: invalid outbox aggregate")
	}
	if e.Status != OutboxPending {
		return errors.New("commerce: new outbox event must be pending")
	}
	return nil
}

// SubscriptionMutation makes the contract and its entitlement projection one
// optimistic, atomic write together with the governance outbox fact.
type SubscriptionMutation struct {
	ExpectedRevision uint64
	Subscription     *Subscription
	Entitlement      *EntitlementSnapshot
	Events           []*OutboxEvent
}

// WalletMutation atomically appends an immutable entry, advances the balance,
// and records the governance outbox fact.
type WalletMutation struct {
	Entry  *LedgerEntry
	Events []*OutboxEvent
}

type PaymentMutation struct {
	ExpectedRevision uint64
	Order            *PaymentOrder
	PaymentEvent     *PaymentEvent
	LedgerEntry      *LedgerEntry
	Events           []*OutboxEvent
	Source           *PaymentSourceEvidence
}

const paymentSourcePrefix = "payment:"

// PaymentSourceEvidence pins the server-owned adapter binding observed by the
// transport. Durable stores recheck this revision in the payment transaction.
type PaymentSourceEvidence struct {
	BindingID    string
	ClientID     string
	TenantID     string
	SourceSystem string
	Revision     uint64
}

func (e PaymentSourceEvidence) Authorizes(tenantID, provider string) bool {
	expected, err := PaymentSourceSystem(provider)
	return err == nil && validPaymentSourceIdentity(e.BindingID) &&
		validPaymentSourceIdentity(e.ClientID) && validPaymentSourceIdentity(e.TenantID) &&
		validPaymentSourceIdentity(e.SourceSystem) && e.Revision > 0 &&
		e.TenantID == tenantID && e.SourceSystem == expected
}

func PaymentSourceSystem(provider string) (string, error) {
	if !validPaymentSourceIdentity(provider) || len(paymentSourcePrefix)+len(provider) > 256 {
		return "", ErrPaymentSourceUnauthorized
	}
	return paymentSourcePrefix + provider, nil
}

func validPaymentSourceIdentity(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 256
}

type RenewalOutcome string

const (
	RenewalRenewed  RenewalOutcome = "renewed"
	RenewalPastDue  RenewalOutcome = "past_due"
	RenewalCanceled RenewalOutcome = "canceled"
	RenewalExpired  RenewalOutcome = "expired"
)

// RenewalClaim is a bounded lease over one due subscription generation. A
// settlement must repeat the owner, revision and due period and commit before
// LeaseUntil; stale workers therefore cannot mutate a reclaimed subscription.
type RenewalClaim struct {
	Subscription *Subscription
	Owner        string
	LeaseUntil   time.Time
}

// RenewalMutation contains both deterministic financial outcomes. The store
// selects Insufficient only after locking the current wallet and finding its
// snapshotted renewal price unavailable; all writes share that transaction.
type RenewalMutation struct {
	Owner               string
	ClaimUntil          time.Time
	AttemptedAt         time.Time
	ExpectedRevision    uint64
	ExpectedPeriodEnd   time.Time
	Debit               *LedgerEntry
	Success             *SubscriptionMutation
	Insufficient        *SubscriptionMutation
	SuccessOutcome      RenewalOutcome
	InsufficientOutcome RenewalOutcome
}

func (mutation RenewalMutation) Validate() error {
	if mutation.Owner == "" || mutation.ClaimUntil.IsZero() || mutation.AttemptedAt.IsZero() ||
		mutation.ExpectedRevision == 0 || mutation.ExpectedPeriodEnd.IsZero() {
		return ErrInvalidRenewal
	}
	if err := validateRenewalBranch(mutation.Success, mutation.ExpectedRevision); err != nil {
		return err
	}
	if !validRenewalOutcome(mutation.SuccessOutcome) {
		return ErrInvalidRenewal
	}
	if mutation.Debit == nil {
		if mutation.SuccessOutcome == RenewalRenewed &&
			mutation.Success.Subscription.Renewal.Price.MinorUnits != 0 {
			return ErrInvalidRenewal
		}
		return nil
	}
	return validateRenewalDebit(mutation)
}

func validateRenewalDebit(mutation RenewalMutation) error {
	if err := mutation.Debit.Validate(); err != nil ||
		mutation.Debit.Kind != LedgerSubscriptionCharge || mutation.Debit.AmountMinor >= 0 {
		return ErrInvalidRenewal
	}
	if err := validateRenewalBranch(mutation.Insufficient, mutation.ExpectedRevision); err != nil {
		return err
	}
	if !validRenewalOutcome(mutation.InsufficientOutcome) {
		return ErrInvalidRenewal
	}
	if mutation.InsufficientOutcome != RenewalPastDue && mutation.InsufficientOutcome != RenewalExpired {
		return ErrInvalidRenewal
	}
	if !sameRenewalMutationIdentity(mutation.Success, mutation.Insufficient) {
		return ErrInvalidRenewal
	}
	subscription := mutation.Success.Subscription
	if mutation.Debit.TenantID != subscription.TenantID ||
		mutation.Debit.Currency != subscription.Renewal.Price.Currency ||
		mutation.Debit.AmountMinor != -subscription.Renewal.Price.MinorUnits {
		return ErrInvalidRenewal
	}
	return nil
}

func sameRenewalMutationIdentity(left, right *SubscriptionMutation) bool {
	first, second := left.Subscription, right.Subscription
	return first.ID == second.ID && first.TenantID == second.TenantID &&
		first.Plan == second.Plan && first.Renewal == second.Renewal &&
		first.CreatedAt.Equal(second.CreatedAt)
}

func validateRenewalBranch(branch *SubscriptionMutation, expected uint64) error {
	if branch == nil || branch.ExpectedRevision != expected {
		return ErrInvalidRenewal
	}
	if err := validateSubscriptionMutation(*branch); err != nil {
		return errors.Join(ErrInvalidRenewal, err)
	}
	if branch.Subscription.Revision != expected+1 {
		return ErrInvalidRenewal
	}
	return nil
}

func validRenewalOutcome(outcome RenewalOutcome) bool {
	switch outcome {
	case RenewalRenewed, RenewalPastDue, RenewalCanceled, RenewalExpired:
		return true
	default:
		return false
	}
}

type RenewalResult struct {
	Outcome      RenewalOutcome
	Subscription *Subscription
	Entitlement  *EntitlementSnapshot
	LedgerEntry  *LedgerEntry
	Wallet       *Wallet
}

type CatalogStore interface {
	PutPlan(ctx context.Context, plan *Plan) error
	GetPlan(ctx context.Context, id string, version uint64) (*Plan, error)
	ListPlans(ctx context.Context) ([]*Plan, error)
}

type SubscriptionStore interface {
	ApplySubscription(ctx context.Context, mutation SubscriptionMutation) error
	GetSubscription(ctx context.Context, id string) (*Subscription, error)
	ListSubscriptionsByTenant(ctx context.Context, tenantID string) ([]*Subscription, error)
	CurrentEntitlement(ctx context.Context, tenantID string) (*EntitlementSnapshot, error)
}

type WalletStore interface {
	PostLedgerEntry(ctx context.Context, mutation WalletMutation) (*LedgerEntry, *Wallet, error)
	GetWallet(ctx context.Context, tenantID, currency string) (*Wallet, error)
	ListLedgerEntries(ctx context.Context, tenantID, currency string, limit int) ([]*LedgerEntry, error)
}

type PaymentStore interface {
	CreatePaymentOrder(ctx context.Context, order *PaymentOrder, events []*OutboxEvent) (*PaymentOrder, error)
	GetPaymentOrder(ctx context.Context, id string) (*PaymentOrder, error)
	ListPaymentOrdersByTenant(ctx context.Context, tenantID string) ([]*PaymentOrder, error)
	ApplyPaymentEvent(ctx context.Context, mutation PaymentMutation) (*PaymentOrder, *LedgerEntry, *Wallet, error)
	GetPaymentEvent(ctx context.Context, provider, eventID string) (*PaymentEvent, error)
	ListPaymentEvents(ctx context.Context, orderID string) ([]*PaymentEvent, error)
	ReconcilePayments(ctx context.Context, tenantID string) (*ReconciliationReport, error)
}

type RenewalStore interface {
	ClaimDueRenewals(
		ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
	) ([]*RenewalClaim, error)
	ApplyRenewal(ctx context.Context, mutation RenewalMutation) (*RenewalResult, error)
	InspectRenewalBacklog(ctx context.Context, now time.Time) (RenewalBacklog, error)
}

// RenewalBacklog is a process-independent view of every subscription that is
// eligible for settlement, including rows currently leased by another worker.
// OldestDueAt is when the oldest row became eligible, not its original contract
// boundary when a later retry schedule applies.
type RenewalBacklog struct {
	DueCount    int64
	OldestDueAt time.Time
}

// PaymentProvider is the typed port implemented by an authenticated external
// provider process. Provider-specific SDKs and secrets stay outside Snaplink.
type PaymentProvider interface {
	Name() string
	CreateCheckout(ctx context.Context, request CheckoutRequest) (*CheckoutSession, error)
	Refund(ctx context.Context, request RefundRequest) error
	Lookup(ctx context.Context, providerOrderID string) (*ProviderPaymentState, error)
}

type CheckoutRequest struct {
	OrderID        string
	TenantID       string
	Amount         Money
	ReturnURL      string
	IdempotencyKey string
}

type CheckoutSession struct {
	ProviderOrderID string
	RedirectURL     string
	ExpiresAt       time.Time
}

type RefundRequest struct {
	OrderID         string
	ProviderOrderID string
	Amount          Money
	IdempotencyKey  string
}

type ProviderPaymentState struct {
	ProviderOrderID string
	Status          PaymentOrderStatus
	PaidMinor       int64
	RefundedMinor   int64
	ObservedAt      time.Time
}

type OutboxStore interface {
	ClaimOutbox(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]*OutboxEvent, error)
	CompleteOutbox(ctx context.Context, id, owner string, deliveredAt time.Time) error
	FailOutbox(ctx context.Context, id, owner, reason string, now, nextAttempt time.Time, maxAttempts int) error
	QuarantineOutbox(ctx context.Context, id, owner, reason string, now time.Time) error
	ListDeadOutbox(ctx context.Context, limit int) ([]*OutboxEvent, error)
	ReplayOutbox(ctx context.Context, id string, now time.Time) error
}

// QuotaProjectionDeliveryStore is the independent, durable delivery cursor
// for entitlement-to-SSO quota projection. Its lease and acknowledgement
// state never shares the governance OutboxStore status, so either destination
// may retry or complete without consuming the other destination's fact.
type QuotaProjectionDeliveryStore interface {
	ClaimQuotaProjectionDeliveries(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]*OutboxEvent, error)
	CompleteQuotaProjectionDelivery(ctx context.Context, eventID, owner string, projectionRevision uint64, deliveredAt time.Time) error
	FailQuotaProjectionDelivery(ctx context.Context, eventID, owner, reason string, now, nextAttempt time.Time) error
	QuotaProjectionDeliveryReady(ctx context.Context, now time.Time, maxLag time.Duration) error
}

type Store interface {
	CatalogStore
	SubscriptionStore
	WalletStore
	PaymentStore
	RenewalStore
	OutboxStore
	QuotaProjectionDeliveryStore
}
