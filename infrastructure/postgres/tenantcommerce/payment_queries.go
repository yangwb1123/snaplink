package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

func (s *Store) paymentReplayAfterConflict(
	ctx context.Context, requested *commerce.PaymentEvent, source *commerce.PaymentSourceEvidence,
) (*commerce.PaymentOrder, *commerce.LedgerEntry, *commerce.Wallet, error) {
	var order *commerce.PaymentOrder
	var entry *commerce.LedgerEntry
	var wallet *commerce.Wallet
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		current, findErr := findPaymentEventTx(ctx, tx, requested.Provider, requested.ID, true)
		if findErr != nil {
			return findErr
		}
		if current == nil || !samePaymentFact(current, requested) {
			return commerce.ErrIdempotencyConflict
		}
		var replayErr error
		order, entry, wallet, replayErr = s.paymentReplayTx(ctx, tx, current, requested)
		if replayErr != nil {
			return replayErr
		}
		return verifyPaymentSourceBindingTx(ctx, tx, source, order)
	})
	return order, entry, wallet, err
}

func (s *Store) GetPaymentEvent(
	ctx context.Context, provider, eventID string,
) (*commerce.PaymentEvent, error) {
	event, err := findPaymentEventTx(ctx, s.db, provider, eventID, false)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: get payment event: %w", err)
	}
	if event == nil {
		return nil, commerce.ErrPaymentEventNotFound
	}
	return event, nil
}

func findPaymentEventTx(
	ctx context.Context, query subscriptionQuery, provider, eventID string, lock bool,
) (*commerce.PaymentEvent, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	row := query.QueryRowContext(ctx, `SELECT `+paymentEventColumns+`
FROM tenant_commerce_payment_events WHERE provider=$1 AND id=$2`+suffix, provider, eventID)
	event, err := scanPaymentEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return event, err
}

func (s *Store) ListPaymentEvents(
	ctx context.Context, orderID string,
) ([]*commerce.PaymentEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+paymentEventColumns+`
FROM tenant_commerce_payment_events WHERE order_id=$1 ORDER BY occurred_at_ns, id`, orderID)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: list payment events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.PaymentEvent, 0)
	for rows.Next() {
		event, scanErr := scanPaymentEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) ReconcilePayments(
	ctx context.Context, tenantID string,
) (*commerce.ReconciliationReport, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.paid_minor-p.refunded_minor,
COALESCE(SUM(l.amount_minor),0) FROM tenant_commerce_payment_orders p
LEFT JOIN tenant_commerce_ledger l ON l.tenant_id=p.tenant_id AND l.currency=p.currency AND l.reference=p.id
WHERE p.tenant_id=$1 GROUP BY p.id, p.paid_minor, p.refunded_minor ORDER BY p.id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: reconcile payments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	report := &commerce.ReconciliationReport{TenantID: tenantID, Issues: []commerce.ReconciliationIssue{}}
	for rows.Next() {
		var issue commerce.ReconciliationIssue
		if err := rows.Scan(&issue.OrderID, &issue.ExpectedMinor, &issue.LedgerMinor); err != nil {
			return nil, err
		}
		report.OrdersChecked++
		if issue.ExpectedMinor != issue.LedgerMinor {
			report.Issues = append(report.Issues, issue)
		}
	}
	return report, rows.Err()
}
