package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

const paymentOrderColumns = `id, tenant_id, provider, provider_order_id, currency,
amount_minor, paid_minor, refunded_minor, status, idempotency_key, revision,
created_at_ns, updated_at_ns`

const paymentEventColumns = `provider, id, provider_order_id, order_id, type,
currency, amount_minor, occurred_at_ns, applied_at_ns, ledger_entry_id`

func (s *Store) CreatePaymentOrder(
	ctx context.Context, order *commerce.PaymentOrder, events []*commerce.OutboxEvent,
) (*commerce.PaymentOrder, error) {
	if err := validatePaymentOrderWrite(order, events); err != nil {
		return nil, err
	}
	var stored *commerce.PaymentOrder
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		current, findErr := findPaymentOrderByKeyTx(ctx, tx, order, true)
		if findErr != nil {
			return findErr
		}
		if current != nil {
			if !samePaymentOrderCommand(current, order) {
				return commerce.ErrIdempotencyConflict
			}
			stored = current
			return nil
		}
		if _, getErr := getPaymentOrderTx(ctx, tx, order.ID, true); getErr == nil {
			return commerce.ErrIdempotencyConflict
		} else if !errors.Is(getErr, commerce.ErrPaymentNotFound) {
			return getErr
		}
		if err := insertPaymentOrderTx(ctx, tx, order); err != nil {
			return err
		}
		if err := insertOutboxEventsTx(ctx, tx, events); err != nil {
			return err
		}
		copy := *order
		stored = &copy
		return nil
	})
	if uniqueConstraint(err) != "" {
		current, replayErr := findPaymentOrderByKeyTx(ctx, s.db, order, false)
		if replayErr == nil && current != nil && samePaymentOrderCommand(current, order) {
			return current, nil
		}
		return nil, commerce.ErrIdempotencyConflict
	}
	return stored, err
}

func validatePaymentOrderWrite(order *commerce.PaymentOrder, events []*commerce.OutboxEvent) error {
	if err := order.Validate(); err != nil {
		return err
	}
	if len(events) == 0 {
		return errors.New("tenantcommerce/postgres: payment order outbox event required")
	}
	return validateOutboxEvents(events)
}

func findPaymentOrderByKeyTx(
	ctx context.Context, query subscriptionQuery, order *commerce.PaymentOrder, lock bool,
) (*commerce.PaymentOrder, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	row := query.QueryRowContext(ctx, `SELECT `+paymentOrderColumns+` FROM tenant_commerce_payment_orders
WHERE tenant_id=$1 AND provider=$2 AND idempotency_key=$3`+suffix,
		order.TenantID, order.Provider, order.IdempotencyKey)
	current, err := scanPaymentOrder(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return current, err
}

func samePaymentOrderCommand(left, right *commerce.PaymentOrder) bool {
	return left != nil && left.TenantID == right.TenantID && left.Provider == right.Provider &&
		left.ProviderOrderID == right.ProviderOrderID && left.Currency == right.Currency &&
		left.AmountMinor == right.AmountMinor
}

func insertPaymentOrderTx(ctx context.Context, tx *sql.Tx, order *commerce.PaymentOrder) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_payment_orders (
id, tenant_id, provider, provider_order_id, currency, amount_minor, paid_minor,
refunded_minor, status, idempotency_key, revision, created_at_ns, updated_at_ns
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, paymentOrderArgs(order)...)
	return wrapWrite("insert payment order", err)
}

func paymentOrderArgs(order *commerce.PaymentOrder) []any {
	return []any{
		order.ID, order.TenantID, order.Provider, order.ProviderOrderID, order.Currency,
		order.AmountMinor, order.PaidMinor, order.RefundedMinor, order.Status, order.IdempotencyKey,
		order.Revision, timeNano(order.CreatedAt), timeNano(order.UpdatedAt),
	}
}

func (s *Store) GetPaymentOrder(ctx context.Context, id string) (*commerce.PaymentOrder, error) {
	order, err := getPaymentOrderTx(ctx, s.db, id, false)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: get payment order: %w", err)
	}
	return order, nil
}

func getPaymentOrderTx(
	ctx context.Context, query subscriptionQuery, id string, lock bool,
) (*commerce.PaymentOrder, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	row := query.QueryRowContext(ctx, `SELECT `+paymentOrderColumns+`
FROM tenant_commerce_payment_orders WHERE id=$1`+suffix, id)
	order, err := scanPaymentOrder(row)
	return order, notFound(err, commerce.ErrPaymentNotFound)
}

func (s *Store) ListPaymentOrdersByTenant(
	ctx context.Context, tenantID string,
) ([]*commerce.PaymentOrder, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+paymentOrderColumns+` FROM tenant_commerce_payment_orders
WHERE tenant_id=$1 ORDER BY created_at_ns, id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: list payment orders: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.PaymentOrder, 0)
	for rows.Next() {
		order, scanErr := scanPaymentOrder(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, order)
	}
	return result, rows.Err()
}

func (s *Store) ApplyPaymentEvent(
	ctx context.Context, mutation commerce.PaymentMutation,
) (*commerce.PaymentOrder, *commerce.LedgerEntry, *commerce.Wallet, error) {
	if err := validatePaymentMutation(mutation); err != nil {
		return nil, nil, nil, err
	}
	var order *commerce.PaymentOrder
	var entry *commerce.LedgerEntry
	var wallet *commerce.Wallet
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		var applyErr error
		order, entry, wallet, applyErr = s.applyPaymentEventTx(ctx, tx, mutation)
		return applyErr
	})
	if uniqueConstraint(err) != "" {
		return s.paymentReplayAfterConflict(ctx, mutation.PaymentEvent, mutation.Source)
	}
	return order, entry, wallet, err
}

func validatePaymentMutation(mutation commerce.PaymentMutation) error {
	if err := mutation.Order.Validate(); err != nil {
		return err
	}
	if err := mutation.PaymentEvent.Validate(); err != nil {
		return err
	}
	if mutation.PaymentEvent.OrderID != mutation.Order.ID || len(mutation.Events) == 0 {
		return commerce.ErrInvalidPayment
	}
	if mutation.PaymentEvent.AppliedAt.IsZero() {
		return commerce.ErrInvalidPayment
	}
	if mutation.Source != nil && !mutation.Source.Authorizes(mutation.Order.TenantID, mutation.Order.Provider) {
		return commerce.ErrPaymentSourceUnauthorized
	}
	if mutation.LedgerEntry != nil {
		if err := mutation.LedgerEntry.Validate(); err != nil {
			return err
		}
	}
	return validateOutboxEvents(mutation.Events)
}

func (s *Store) applyPaymentEventTx(
	ctx context.Context, tx *sql.Tx, mutation commerce.PaymentMutation,
) (*commerce.PaymentOrder, *commerce.LedgerEntry, *commerce.Wallet, error) {
	if err := verifyPaymentSourceBindingTx(ctx, tx, mutation.Source, mutation.Order); err != nil {
		return nil, nil, nil, err
	}
	if replay, err := findPaymentEventTx(ctx, tx, mutation.PaymentEvent.Provider, mutation.PaymentEvent.ID, true); err != nil {
		return nil, nil, nil, err
	} else if replay != nil {
		return s.paymentReplayTx(ctx, tx, replay, mutation.PaymentEvent)
	}
	current, err := getPaymentOrderTx(ctx, tx, mutation.Order.ID, true)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validatePaymentRevision(current, mutation); err != nil {
		return nil, nil, nil, err
	}
	entry, wallet, err := s.applyPaymentWalletTx(ctx, tx, mutation)
	if err != nil {
		return nil, nil, nil, err
	}
	event := *mutation.PaymentEvent
	if entry != nil {
		event.LedgerEntryID = entry.ID
	}
	if err := updatePaymentOrderTx(ctx, tx, mutation.Order); err != nil {
		return nil, nil, nil, err
	}
	if err := insertPaymentEventTx(ctx, tx, &event); err != nil {
		return nil, nil, nil, err
	}
	events := mutation.Events
	if wallet != nil {
		events = versionedOutboxEvents(events, wallet.Version)
	}
	if err := insertOutboxEventsTx(ctx, tx, events); err != nil {
		return nil, nil, nil, err
	}
	copy := *mutation.Order
	return &copy, entry, wallet, nil
}

func validatePaymentRevision(current *commerce.PaymentOrder, mutation commerce.PaymentMutation) error {
	if current.Revision != mutation.ExpectedRevision || mutation.Order.Revision != current.Revision+1 {
		return commerce.ErrRevisionConflict
	}
	if current.ID != mutation.Order.ID || current.TenantID != mutation.Order.TenantID ||
		current.Provider != mutation.Order.Provider || current.Currency != mutation.Order.Currency ||
		current.AmountMinor != mutation.Order.AmountMinor ||
		current.IdempotencyKey != mutation.Order.IdempotencyKey ||
		!current.CreatedAt.Equal(mutation.Order.CreatedAt) {
		return commerce.ErrPaymentStateConflict
	}
	return validatePaymentTransition(current, mutation)
}

func validatePaymentTransition(current *commerce.PaymentOrder, mutation commerce.PaymentMutation) error {
	event, next := mutation.PaymentEvent, mutation.Order
	if !paymentTransitionBound(current, next, event) {
		return commerce.ErrPaymentStateConflict
	}
	switch event.Type {
	case commerce.PaymentCaptured:
		return validateCapturedTransition(current, next, event, mutation)
	case commerce.PaymentRejected:
		return validateRejectedTransition(current, next, mutation)
	case commerce.PaymentRefundedEvent, commerce.PaymentChargeback:
		if err := validateRefundTransition(current, next, event); err != nil {
			return err
		}
		return validatePaymentLedgerBinding(mutation)
	case commerce.PaymentChargebackReversed:
		if err := validateChargebackReversal(current, next, event); err != nil {
			return err
		}
		return validatePaymentLedgerBinding(mutation)
	default:
		return commerce.ErrPaymentStateConflict
	}
}

func paymentTransitionBound(
	current, next *commerce.PaymentOrder, event *commerce.PaymentEvent,
) bool {
	return event.OrderID == current.ID && event.Provider == current.Provider &&
		event.Currency == current.Currency && next.ProviderOrderID == event.ProviderOrderID &&
		(current.ProviderOrderID == "" || current.ProviderOrderID == event.ProviderOrderID)
}

func validateCapturedTransition(
	current, next *commerce.PaymentOrder, event *commerce.PaymentEvent, mutation commerce.PaymentMutation,
) error {
	if current.Status != commerce.PaymentPending || next.Status != commerce.PaymentSucceeded ||
		event.AmountMinor != current.AmountMinor || next.PaidMinor != event.AmountMinor || next.RefundedMinor != 0 {
		return commerce.ErrPaymentStateConflict
	}
	return validatePaymentLedgerBinding(mutation)
}

func validateRejectedTransition(
	current, next *commerce.PaymentOrder, mutation commerce.PaymentMutation,
) error {
	if current.Status != commerce.PaymentPending || next.Status != commerce.PaymentFailed ||
		next.PaidMinor != current.PaidMinor || next.RefundedMinor != current.RefundedMinor {
		return commerce.ErrPaymentStateConflict
	}
	return validatePaymentLedgerBinding(mutation)
}

func validateRefundTransition(
	current, next *commerce.PaymentOrder, event *commerce.PaymentEvent,
) error {
	if current.Status != commerce.PaymentSucceeded && current.Status != commerce.PaymentPartiallyRefunded {
		return commerce.ErrPaymentStateConflict
	}
	if next.PaidMinor != current.PaidMinor || next.RefundedMinor != current.RefundedMinor+event.AmountMinor ||
		next.RefundedMinor > next.PaidMinor {
		return commerce.ErrPaymentStateConflict
	}
	expected := commerce.PaymentPartiallyRefunded
	if next.RefundedMinor == next.PaidMinor {
		expected = commerce.PaymentRefunded
	}
	if next.Status != expected {
		return commerce.ErrPaymentStateConflict
	}
	return nil
}

func validateChargebackReversal(
	current, next *commerce.PaymentOrder, event *commerce.PaymentEvent,
) error {
	if current.Status != commerce.PaymentPartiallyRefunded && current.Status != commerce.PaymentRefunded {
		return commerce.ErrPaymentStateConflict
	}
	if next.PaidMinor != current.PaidMinor || event.AmountMinor > current.RefundedMinor ||
		next.RefundedMinor != current.RefundedMinor-event.AmountMinor {
		return commerce.ErrPaymentStateConflict
	}
	expected := commerce.PaymentPartiallyRefunded
	if next.RefundedMinor == 0 {
		expected = commerce.PaymentSucceeded
	}
	if next.Status != expected {
		return commerce.ErrPaymentStateConflict
	}
	return nil
}

func validatePaymentLedgerBinding(mutation commerce.PaymentMutation) error {
	event, entry := mutation.PaymentEvent, mutation.LedgerEntry
	if event.Type == commerce.PaymentRejected {
		if entry != nil {
			return commerce.ErrPaymentStateConflict
		}
		return nil
	}
	if entry == nil || entry.TenantID != mutation.Order.TenantID ||
		entry.Currency != mutation.Order.Currency || entry.Reference != mutation.Order.ID {
		return commerce.ErrPaymentStateConflict
	}
	expectedKind, expectedAmount := commerce.LedgerRefund, -event.AmountMinor
	if event.Type == commerce.PaymentCaptured {
		expectedKind, expectedAmount = commerce.LedgerTopUp, event.AmountMinor
	}
	if event.Type == commerce.PaymentChargebackReversed {
		expectedKind, expectedAmount = commerce.LedgerChargebackReversal, event.AmountMinor
	}
	if entry.Kind != expectedKind || entry.AmountMinor != expectedAmount {
		return commerce.ErrPaymentStateConflict
	}
	return nil
}

func (s *Store) applyPaymentWalletTx(
	ctx context.Context, tx *sql.Tx, mutation commerce.PaymentMutation,
) (*commerce.LedgerEntry, *commerce.Wallet, error) {
	if mutation.LedgerEntry == nil {
		return nil, nil, nil
	}
	if replay, err := findLedgerReplayTx(ctx, tx, mutation.LedgerEntry, true); err != nil || replay != nil {
		if err == nil {
			err = commerce.ErrIdempotencyConflict
		}
		return nil, nil, err
	}
	wallet, err := lockWalletTx(ctx, tx, mutation.LedgerEntry.TenantID, mutation.LedgerEntry.Currency)
	if err != nil {
		return nil, nil, err
	}
	balance, err := nextSignedBalance(wallet.BalanceMinor, mutation.LedgerEntry.AmountMinor)
	if err != nil {
		return nil, nil, err
	}
	entry, next := nextWalletState(mutation.LedgerEntry, wallet, balance)
	if mutation.PaymentEvent.Type == commerce.PaymentChargeback || next.BalanceMinor < 0 {
		next.Status = commerce.WalletFrozen
	} else if mutation.PaymentEvent.Type == commerce.PaymentChargebackReversed {
		next.Status = commerce.WalletActive
	}
	if err := updateWalletTx(ctx, tx, next); err != nil {
		return nil, nil, err
	}
	if err := insertLedgerTx(ctx, tx, entry); err != nil {
		return nil, nil, err
	}
	return entry, next, nil
}

func nextSignedBalance(balance, amount int64) (int64, error) {
	if amount > 0 && balance > math.MaxInt64-amount {
		return 0, commerce.ErrWalletOverflow
	}
	if amount < 0 && balance < math.MinInt64-amount {
		return 0, commerce.ErrWalletOverflow
	}
	return balance + amount, nil
}

func updatePaymentOrderTx(ctx context.Context, tx *sql.Tx, order *commerce.PaymentOrder) error {
	_, err := tx.ExecContext(ctx, `UPDATE tenant_commerce_payment_orders SET
tenant_id=$2, provider=$3, provider_order_id=$4, currency=$5, amount_minor=$6,
paid_minor=$7, refunded_minor=$8, status=$9, idempotency_key=$10, revision=$11,
created_at_ns=$12, updated_at_ns=$13 WHERE id=$1`, paymentOrderArgs(order)...)
	return wrapWrite("update payment order", err)
}

func insertPaymentEventTx(ctx context.Context, tx *sql.Tx, event *commerce.PaymentEvent) error {
	var ledgerID any
	if event.LedgerEntryID != "" {
		ledgerID = event.LedgerEntryID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_payment_events (
provider, id, provider_order_id, order_id, type, currency, amount_minor,
occurred_at_ns, applied_at_ns, ledger_entry_id
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, event.Provider, event.ID,
		event.ProviderOrderID, event.OrderID, event.Type, event.Currency, event.AmountMinor,
		timeNano(event.OccurredAt), timeNano(event.AppliedAt), ledgerID)
	return wrapWrite("insert payment event", err)
}

func (s *Store) paymentReplayTx(
	ctx context.Context, tx *sql.Tx, current, requested *commerce.PaymentEvent,
) (*commerce.PaymentOrder, *commerce.LedgerEntry, *commerce.Wallet, error) {
	if !samePaymentFact(current, requested) {
		return nil, nil, nil, commerce.ErrIdempotencyConflict
	}
	order, err := getPaymentOrderTx(ctx, tx, current.OrderID, false)
	if err != nil {
		return nil, nil, nil, err
	}
	var entry *commerce.LedgerEntry
	if current.LedgerEntryID != "" {
		entry, err = getLedgerByIDTx(ctx, tx, current.LedgerEntryID)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	wallet, walletErr := getOptionalWalletTx(ctx, tx, order.TenantID, order.Currency)
	return order, entry, wallet, walletErr
}

func samePaymentFact(left, right *commerce.PaymentEvent) bool {
	return left.ID == right.ID && left.Provider == right.Provider &&
		left.ProviderOrderID == right.ProviderOrderID && left.OrderID == right.OrderID &&
		left.Type == right.Type && left.Currency == right.Currency && left.AmountMinor == right.AmountMinor &&
		left.OccurredAt.Equal(right.OccurredAt)
}

func getLedgerByIDTx(ctx context.Context, query subscriptionQuery, id string) (*commerce.LedgerEntry, error) {
	entry, err := scanLedger(query.QueryRowContext(ctx, `SELECT `+ledgerColumns+`
FROM tenant_commerce_ledger WHERE id=$1`, id))
	return entry, err
}

func getOptionalWalletTx(
	ctx context.Context, tx *sql.Tx, tenantID, currency string,
) (*commerce.Wallet, error) {
	wallet, err := getWalletTx(ctx, tx, tenantID, currency, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return wallet, err
}
