package tenantcommerce

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type rowScanner interface {
	Scan(dest ...any) error
}

func encodeJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("tenantcommerce/postgres: encode JSON: %w", err)
	}
	return string(encoded), nil
}

func decodeJSON(encoded []byte, target any) error {
	if err := json.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf("tenantcommerce/postgres: decode JSON: %w", err)
	}
	return nil
}

func timeNano(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}

func nanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

func scanPlan(scanner rowScanner) (*commerce.Plan, error) {
	plan := &commerce.Plan{}
	var status, interval string
	var features, limits []byte
	var created int64
	err := scanner.Scan(
		&plan.ID, &plan.Version, &plan.Name, &status, &interval, &plan.Price.Currency,
		&plan.Price.MinorUnits, &plan.GracePeriodDays, &features, &limits, &created,
	)
	if err != nil {
		return nil, err
	}
	plan.Status, plan.Interval, plan.CreatedAt = commerce.PlanStatus(status), commerce.BillingInterval(interval), nanoTime(created)
	if err := decodeJSON(features, &plan.Features); err != nil {
		return nil, err
	}
	if err := decodeJSON(limits, &plan.Limits); err != nil {
		return nil, err
	}
	return plan, nil
}

func scanSubscription(scanner rowScanner) (*commerce.Subscription, error) {
	subscription := &commerce.Subscription{}
	var status string
	var start, end, trial, grace, canceled, nextAttempt, created, updated int64
	err := scanner.Scan(
		&subscription.ID, &subscription.TenantID, &subscription.Plan.ID, &subscription.Plan.Version,
		&subscription.Renewal.Interval, &subscription.Renewal.Price.Currency,
		&subscription.Renewal.Price.MinorUnits, &subscription.Renewal.GracePeriodDays,
		&status, &start, &end, &trial, &grace, &subscription.CancelAtPeriodEnd, &canceled,
		&subscription.Provider, &subscription.ProviderSubscriptionID, &nextAttempt,
		&subscription.Revision, &created, &updated,
	)
	if err != nil {
		return nil, err
	}
	subscription.Status = commerce.SubscriptionStatus(status)
	subscription.CurrentPeriodStart, subscription.CurrentPeriodEnd = nanoTime(start), nanoTime(end)
	subscription.TrialEnd, subscription.GraceUntil = nanoTime(trial), nanoTime(grace)
	subscription.CanceledAt = nanoTime(canceled)
	subscription.RenewalNextAttemptAt = nanoTime(nextAttempt)
	subscription.CreatedAt, subscription.UpdatedAt = nanoTime(created), nanoTime(updated)
	return subscription, nil
}

func scanEntitlement(scanner rowScanner) (*commerce.EntitlementSnapshot, error) {
	entitlement := &commerce.EntitlementSnapshot{}
	var features, limits []byte
	var effective, expires, generated int64
	err := scanner.Scan(
		&entitlement.TenantID, &entitlement.SubscriptionID, &entitlement.Plan.ID, &entitlement.Plan.Version,
		&entitlement.Revision, &entitlement.Active, &features, &limits, &effective, &expires, &generated,
	)
	if err != nil {
		return nil, err
	}
	if err := decodeJSON(features, &entitlement.Features); err != nil {
		return nil, err
	}
	if err := decodeJSON(limits, &entitlement.Limits); err != nil {
		return nil, err
	}
	entitlement.EffectiveAt, entitlement.ExpiresAt = nanoTime(effective), nanoTime(expires)
	entitlement.GeneratedAt = nanoTime(generated)
	return entitlement, nil
}

func scanWallet(scanner rowScanner) (*commerce.Wallet, error) {
	wallet := &commerce.Wallet{}
	var status string
	var updated int64
	if err := scanner.Scan(
		&wallet.TenantID, &wallet.Currency, &wallet.BalanceMinor, &status, &wallet.Version, &updated,
	); err != nil {
		return nil, err
	}
	wallet.Status = commerce.WalletStatus(status)
	wallet.UpdatedAt = nanoTime(updated)
	return wallet, nil
}

func scanLedger(scanner rowScanner) (*commerce.LedgerEntry, error) {
	entry := &commerce.LedgerEntry{}
	var kind string
	var occurred, created int64
	err := scanner.Scan(
		&entry.ID, &entry.TenantID, &entry.Currency, &kind, &entry.AmountMinor,
		&entry.BalanceAfter, &entry.WalletVersion, &entry.IdempotencyKey, &entry.Reference,
		&occurred, &created,
	)
	if err != nil {
		return nil, err
	}
	entry.Kind, entry.OccurredAt, entry.CreatedAt = commerce.LedgerKind(kind), nanoTime(occurred), nanoTime(created)
	return entry, nil
}

func scanPaymentOrder(scanner rowScanner) (*commerce.PaymentOrder, error) {
	order := &commerce.PaymentOrder{}
	var status string
	var created, updated int64
	err := scanner.Scan(
		&order.ID, &order.TenantID, &order.Provider, &order.ProviderOrderID, &order.Currency,
		&order.AmountMinor, &order.PaidMinor, &order.RefundedMinor, &status, &order.IdempotencyKey,
		&order.Revision, &created, &updated,
	)
	if err != nil {
		return nil, err
	}
	order.Status = commerce.PaymentOrderStatus(status)
	order.CreatedAt, order.UpdatedAt = nanoTime(created), nanoTime(updated)
	return order, nil
}

func scanPaymentEvent(scanner rowScanner) (*commerce.PaymentEvent, error) {
	event := &commerce.PaymentEvent{}
	var eventType string
	var ledgerID sql.NullString
	var occurred, applied int64
	err := scanner.Scan(
		&event.Provider, &event.ID, &event.ProviderOrderID, &event.OrderID, &eventType,
		&event.Currency, &event.AmountMinor, &occurred, &applied, &ledgerID,
	)
	if err != nil {
		return nil, err
	}
	event.Type = commerce.PaymentEventType(eventType)
	event.LedgerEntryID = ledgerID.String
	event.OccurredAt, event.AppliedAt = nanoTime(occurred), nanoTime(applied)
	return event, nil
}

func scanOutbox(scanner rowScanner) (*commerce.OutboxEvent, error) {
	event := &commerce.OutboxEvent{}
	var eventType, status string
	var payload []byte
	var occurred, next, lease, delivered, created int64
	err := scanner.Scan(
		&event.ID, &event.TenantID, &eventType, &event.AggregateType, &event.AggregateID,
		&event.AggregateVersion, &event.IdempotencyKey, &occurred, &payload, &event.PayloadDigest,
		&status, &event.Attempts, &next, &event.LeaseOwner, &lease, &event.LastError, &delivered, &created,
	)
	if err != nil {
		return nil, err
	}
	if err := decodeJSON(payload, &event.Payload); err != nil {
		return nil, err
	}
	event.Type, event.Status = commerce.EventType(eventType), commerce.OutboxStatus(status)
	event.OccurredAt, event.NextAttemptAt, event.LeaseUntil = nanoTime(occurred), nanoTime(next), nanoTime(lease)
	event.DeliveredAt, event.CreatedAt = nanoTime(delivered), nanoTime(created)
	return event, nil
}

func notFound(err, sentinel error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return sentinel
	}
	return err
}

func uniqueConstraint(err error) string {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return postgresError.ConstraintName
	}
	return ""
}
