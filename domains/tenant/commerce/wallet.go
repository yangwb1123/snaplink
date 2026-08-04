package commerce

import (
	"context"
	"errors"
	"strconv"
	"time"
)

type PostLedgerCommand struct {
	TenantID       string
	Currency       string
	Kind           LedgerKind
	AmountMinor    int64
	IdempotencyKey string
	Reference      string
	OccurredAt     time.Time
}

func (s *Service) PostLedgerEntry(
	ctx context.Context, command PostLedgerCommand,
) (*LedgerEntry, *Wallet, error) {
	id, err := s.newID("led")
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	entry := &LedgerEntry{
		ID: id, TenantID: command.TenantID, Currency: command.Currency, Kind: command.Kind,
		AmountMinor: command.AmountMinor, IdempotencyKey: command.IdempotencyKey,
		Reference: command.Reference, OccurredAt: command.OccurredAt, CreatedAt: now,
	}
	if entry.OccurredAt.IsZero() {
		entry.OccurredAt = now
	}
	if err := entry.Validate(); err != nil {
		return nil, nil, err
	}
	event, err := s.walletEvent(entry, now)
	if err != nil {
		return nil, nil, err
	}
	mutation := WalletMutation{Entry: entry, Events: []*OutboxEvent{event}}
	return s.store.PostLedgerEntry(ctx, mutation)
}

func (s *Service) walletEvent(entry *LedgerEntry, now time.Time) (*OutboxEvent, error) {
	id, err := s.newID("evt")
	if err != nil {
		return nil, err
	}
	payload := map[string]string{
		"kind": string(entry.Kind), "currency": entry.Currency,
		"amount_minor": strconv.FormatInt(entry.AmountMinor, 10), "reference": entry.Reference,
	}
	return &OutboxEvent{
		ID: id, TenantID: entry.TenantID, Type: walletEventType(entry.Kind), AggregateType: "wallet",
		AggregateID: entry.TenantID + ":" + entry.Currency, AggregateVersion: 1,
		IdempotencyKey: "wallet:" + entry.IdempotencyKey, OccurredAt: entry.OccurredAt,
		Payload: payload, PayloadDigest: digestPayload(payload), Status: OutboxPending, CreatedAt: now,
	}, nil
}

func walletEventType(kind LedgerKind) EventType {
	switch kind {
	case LedgerTopUp, LedgerChargebackReversal:
		return EventWalletCreditPosted
	case LedgerUsage, LedgerSubscriptionCharge, LedgerRefund:
		return EventWalletDebitPosted
	default:
		return EventWalletAdjustmentPosted
	}
}

type CreateTopUpCommand struct {
	ID              string
	TenantID        string
	Provider        string
	ProviderOrderID string
	Currency        string
	AmountMinor     int64
	IdempotencyKey  string
}

func (s *Service) CreateTopUpOrder(ctx context.Context, command CreateTopUpCommand) (*PaymentOrder, error) {
	id, err := s.commandID(command.ID, "pay")
	if err != nil {
		return nil, err
	}
	now := s.now()
	order := &PaymentOrder{
		ID: id, TenantID: command.TenantID, Provider: command.Provider,
		ProviderOrderID: command.ProviderOrderID, Currency: command.Currency,
		AmountMinor: command.AmountMinor, Status: PaymentPending,
		IdempotencyKey: command.IdempotencyKey, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := order.Validate(); err != nil {
		return nil, err
	}
	event, err := s.paymentOrderEvent(order, EventTopUpCreated, "", now)
	if err != nil {
		return nil, err
	}
	return s.store.CreatePaymentOrder(ctx, order, []*OutboxEvent{event})
}

func (s *Service) ApplyPaymentEvent(
	ctx context.Context, incoming *PaymentEvent,
) (*PaymentOrder, *LedgerEntry, *Wallet, error) {
	return s.applyPaymentEvent(ctx, nil, incoming)
}

func (s *Service) ApplyAuthorizedPaymentEvent(
	ctx context.Context, source PaymentSourceEvidence, incoming *PaymentEvent,
) (*PaymentOrder, *LedgerEntry, *Wallet, error) {
	return s.applyPaymentEvent(ctx, &source, incoming)
}

func (s *Service) applyPaymentEvent(
	ctx context.Context, source *PaymentSourceEvidence, incoming *PaymentEvent,
) (*PaymentOrder, *LedgerEntry, *Wallet, error) {
	if err := incoming.Validate(); err != nil {
		return nil, nil, nil, err
	}
	if replay, done, err := s.paymentReplay(ctx, incoming); done || err != nil {
		return replay.order, nil, replay.wallet, err
	}
	current, err := s.store.GetPaymentOrder(ctx, incoming.OrderID)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validatePaymentBinding(current, incoming); err != nil {
		return nil, nil, nil, err
	}
	if source != nil && !source.Authorizes(current.TenantID, incoming.Provider) {
		return nil, nil, nil, ErrPaymentSourceUnauthorized
	}
	now := s.now()
	next, applied, entry, err := s.projectPaymentMutation(current, incoming, now)
	if err != nil {
		if errors.Is(err, ErrPaymentStateConflict) {
			replay, done, replayErr := s.paymentReplay(ctx, incoming)
			if done || replayErr != nil {
				return replay.order, nil, replay.wallet, replayErr
			}
		}
		return nil, nil, nil, err
	}
	events, err := s.paymentEvents(next, applied, entry, now)
	if err != nil {
		return nil, nil, nil, err
	}
	mutation := PaymentMutation{
		ExpectedRevision: current.Revision, Order: next, PaymentEvent: applied,
		LedgerEntry: entry, Events: events, Source: source,
	}
	return s.store.ApplyPaymentEvent(ctx, mutation)
}

type paymentReplayResult struct {
	order  *PaymentOrder
	wallet *Wallet
}

func (s *Service) paymentReplay(
	ctx context.Context, incoming *PaymentEvent,
) (paymentReplayResult, bool, error) {
	recorded, err := s.store.GetPaymentEvent(ctx, incoming.Provider, incoming.ID)
	if errors.Is(err, ErrPaymentEventNotFound) {
		return paymentReplayResult{}, false, nil
	}
	if err != nil {
		return paymentReplayResult{}, false, err
	}
	if !samePaymentFact(recorded, incoming) {
		return paymentReplayResult{}, true, ErrIdempotencyConflict
	}
	order, err := s.store.GetPaymentOrder(ctx, recorded.OrderID)
	if err != nil {
		return paymentReplayResult{}, true, err
	}
	wallet, err := s.store.GetWallet(ctx, order.TenantID, order.Currency)
	return paymentReplayResult{order: order, wallet: wallet}, true, err
}

func (s *Service) projectPaymentMutation(
	current *PaymentOrder, incoming *PaymentEvent, now time.Time,
) (*PaymentOrder, *PaymentEvent, *LedgerEntry, error) {
	next := clonePaymentOrder(current)
	applied := clonePaymentEvent(incoming)
	applied.AppliedAt = now
	next.ProviderOrderID = incoming.ProviderOrderID
	var entry *LedgerEntry
	var err error
	switch incoming.Type {
	case PaymentCaptured:
		entry, err = s.capturePayment(next, applied, now)
	case PaymentRejected:
		err = rejectPayment(next)
	case PaymentRefundedEvent, PaymentChargeback:
		entry, err = s.refundPayment(next, applied, now)
	case PaymentChargebackReversed:
		entry, err = s.reverseChargeback(next, applied, now)
	default:
		err = ErrInvalidPayment
	}
	if err != nil {
		return nil, nil, nil, err
	}
	next.Revision++
	next.UpdatedAt = now
	return next, applied, entry, nil
}

func (s *Service) capturePayment(
	order *PaymentOrder, event *PaymentEvent, now time.Time,
) (*LedgerEntry, error) {
	if order.Status != PaymentPending || event.AmountMinor != order.AmountMinor {
		return nil, ErrPaymentStateConflict
	}
	order.Status, order.PaidMinor = PaymentSucceeded, event.AmountMinor
	return s.newPaymentLedger(order, event, LedgerTopUp, event.AmountMinor, now)
}

func rejectPayment(order *PaymentOrder) error {
	if order.Status != PaymentPending {
		return ErrPaymentStateConflict
	}
	order.Status = PaymentFailed
	return nil
}

func (s *Service) refundPayment(
	order *PaymentOrder, event *PaymentEvent, now time.Time,
) (*LedgerEntry, error) {
	if order.Status != PaymentSucceeded && order.Status != PaymentPartiallyRefunded {
		return nil, ErrPaymentStateConflict
	}
	if event.AmountMinor > order.PaidMinor-order.RefundedMinor {
		return nil, ErrPaymentStateConflict
	}
	order.RefundedMinor += event.AmountMinor
	order.Status = PaymentPartiallyRefunded
	if order.RefundedMinor == order.PaidMinor {
		order.Status = PaymentRefunded
	}
	return s.newPaymentLedger(order, event, LedgerRefund, -event.AmountMinor, now)
}

func (s *Service) reverseChargeback(
	order *PaymentOrder, event *PaymentEvent, now time.Time,
) (*LedgerEntry, error) {
	if order.Status != PaymentPartiallyRefunded && order.Status != PaymentRefunded {
		return nil, ErrPaymentStateConflict
	}
	if event.AmountMinor > order.RefundedMinor {
		return nil, ErrPaymentStateConflict
	}
	order.RefundedMinor -= event.AmountMinor
	order.Status = PaymentPartiallyRefunded
	if order.RefundedMinor == 0 {
		order.Status = PaymentSucceeded
	}
	return s.newPaymentLedger(order, event, LedgerChargebackReversal, event.AmountMinor, now)
}

func (s *Service) newPaymentLedger(
	order *PaymentOrder, event *PaymentEvent, kind LedgerKind, amount int64, now time.Time,
) (*LedgerEntry, error) {
	id, err := s.newID("led")
	if err != nil {
		return nil, err
	}
	return &LedgerEntry{
		ID: id, TenantID: order.TenantID, Currency: order.Currency, Kind: kind,
		AmountMinor: amount, IdempotencyKey: "provider:" + event.Provider + ":" + event.ID,
		Reference: order.ID, OccurredAt: event.OccurredAt, CreatedAt: now,
	}, nil
}

func (s *Service) paymentEvents(
	order *PaymentOrder, event *PaymentEvent, entry *LedgerEntry, now time.Time,
) ([]*OutboxEvent, error) {
	orderEvent, err := s.paymentOrderEvent(order, paymentEventType(event.Type), event.ID, now)
	if err != nil {
		return nil, err
	}
	events := []*OutboxEvent{orderEvent}
	if entry == nil {
		return events, nil
	}
	walletEvent, err := s.walletEvent(entry, now)
	if err != nil {
		return nil, err
	}
	return append(events, walletEvent), nil
}

func (s *Service) paymentOrderEvent(
	order *PaymentOrder, eventType EventType, providerEventID string, now time.Time,
) (*OutboxEvent, error) {
	id, err := s.newID("evt")
	if err != nil {
		return nil, err
	}
	payload := map[string]string{
		"status": string(order.Status), "currency": order.Currency,
		"amount_minor": strconv.FormatInt(order.AmountMinor, 10), "provider": order.Provider,
	}
	if providerEventID != "" {
		payload["provider_event_id"] = providerEventID
	}
	key := "payment_order:" + order.ID + ":" + strconv.FormatUint(order.Revision, 10) + ":" + string(eventType)
	return &OutboxEvent{
		ID: id, TenantID: order.TenantID, Type: eventType, AggregateType: "payment_order",
		AggregateID: order.ID, AggregateVersion: order.Revision, IdempotencyKey: key,
		OccurredAt: now, Payload: payload, PayloadDigest: digestPayload(payload),
		Status: OutboxPending, CreatedAt: now,
	}, nil
}

func paymentEventType(eventType PaymentEventType) EventType {
	switch eventType {
	case PaymentCaptured:
		return EventTopUpSucceeded
	case PaymentRejected:
		return EventTopUpFailed
	case PaymentChargeback:
		return EventTopUpChargeback
	case PaymentChargebackReversed:
		return EventTopUpChargebackReversed
	default:
		return EventTopUpRefunded
	}
}

func validatePaymentBinding(order *PaymentOrder, event *PaymentEvent) error {
	if order.Provider != event.Provider || order.Currency != event.Currency {
		return ErrPaymentStateConflict
	}
	if order.ProviderOrderID != "" && order.ProviderOrderID != event.ProviderOrderID {
		return ErrPaymentStateConflict
	}
	return nil
}

func samePaymentFact(left, right *PaymentEvent) bool {
	return left.ID == right.ID && left.Provider == right.Provider &&
		left.ProviderOrderID == right.ProviderOrderID && left.OrderID == right.OrderID &&
		left.Type == right.Type && left.Currency == right.Currency && left.AmountMinor == right.AmountMinor &&
		left.OccurredAt.Equal(right.OccurredAt)
}
