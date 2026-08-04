package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func classifyStoreConflict(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return errors.Join(errCheckoutConflict, err)
	}
	return err
}

func (s *adapterStore) ReserveCheckout(
	ctx context.Context, order paymentOrder, request checkoutRequest,
) (checkoutReservation, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return checkoutReservation{}, err
	}
	defer tx.Rollback()
	digest := checkoutRequestDigest(request)
	key := checkoutIdempotencyKey(order.TenantID, order.ID, 1)
	if err := insertCheckoutReservation(ctx, tx, order, digest, key); err != nil {
		return checkoutReservation{}, err
	}
	current, err := getCheckoutQuery(ctx, tx, order.TenantID, order.ID, true)
	if err != nil {
		return checkoutReservation{}, err
	}
	if !validCheckoutReservation(current, order, digest) {
		return checkoutReservation{}, errCheckoutConflict
	}
	current, err = rotateExpiredCheckout(ctx, tx, current, time.Now())
	if err != nil {
		return checkoutReservation{}, err
	}
	return current, tx.Commit()
}

func insertCheckoutReservation(
	ctx context.Context, tx *sql.Tx, order paymentOrder, digest []byte, key string,
) error {
	_, err := tx.ExecContext(ctx, `
	INSERT INTO stripe_checkout_mappings (
	    tenant_id, order_id, currency, amount_minor, request_digest, stripe_idempotency_key
	) VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (tenant_id, order_id) DO NOTHING
	`, order.TenantID, order.ID, order.Currency, order.AmountMinor, digest, key)
	if err != nil {
		return fmt.Errorf("reserve checkout: %w", classifyStoreConflict(err))
	}
	return nil
}

func validCheckoutReservation(current checkoutReservation, order paymentOrder, digest []byte) bool {
	expectedKey := checkoutIdempotencyKey(order.TenantID, order.ID, current.Generation)
	return current.Generation > 0 && current.Currency == order.Currency &&
		current.AmountMinor == order.AmountMinor && current.IdempotencyKey == expectedKey &&
		bytes.Equal(current.RequestDigest, digest)
}

func rotateExpiredCheckout(
	ctx context.Context, tx *sql.Tx, current checkoutReservation, now time.Time,
) (checkoutReservation, error) {
	if !current.complete() || current.available(now) {
		return current, nil
	}
	current.Generation++
	current.IdempotencyKey = checkoutIdempotencyKey(current.TenantID, current.OrderID, current.Generation)
	_, err := tx.ExecContext(ctx, `
	UPDATE stripe_checkout_mappings SET checkout_generation = $3, stripe_idempotency_key = $4,
	    stripe_session_id = '', redirect_url = '', session_expires_at = NULL,
	    payment_intent_id = '', charge_id = '', updated_at = clock_timestamp()
	WHERE tenant_id = $1 AND order_id = $2
	`, current.TenantID, current.OrderID, current.Generation, current.IdempotencyKey)
	if err != nil {
		return checkoutReservation{}, fmt.Errorf("rotate expired checkout: %w", classifyStoreConflict(err))
	}
	current.SessionID, current.RedirectURL, current.PaymentIntent = "", "", ""
	current.ExpiresAt, current.Rotated = time.Time{}, true
	return current, nil
}

func (s *adapterStore) InsertInbox(
	ctx context.Context, fact providerFact, digest []byte,
) (inboxOutcome, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	effectKey := fact.NormalizedType + ":" + fact.ProviderObjectID
	replay, err := insertEventReceipt(ctx, tx, fact.EventID, effectKey, digest)
	if err != nil || replay {
		return replayOutcome(tx, replay, err)
	}
	result, err := insertEffectInbox(ctx, tx, fact, effectKey, digest)
	if err != nil {
		return 0, err
	}
	outcome := inboxEffectReplay
	if affected, _ := result.RowsAffected(); affected == 1 {
		outcome = inboxInserted
	}
	return outcome, tx.Commit()
}

func insertEventReceipt(
	ctx context.Context, tx *sql.Tx, eventID, effectKey string, digest []byte,
) (bool, error) {
	result, err := tx.ExecContext(ctx, `
	INSERT INTO stripe_event_receipts (event_id, payload_digest, effect_key)
	VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING
	`, eventID, digest, effectKey)
	if err != nil {
		return false, fmt.Errorf("insert Stripe receipt: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return false, nil
	}
	var stored []byte
	if err := tx.QueryRowContext(ctx,
		`SELECT payload_digest FROM stripe_event_receipts WHERE event_id = $1`, eventID).Scan(&stored); err != nil {
		return false, fmt.Errorf("read Stripe receipt replay: %w", err)
	}
	if !bytes.Equal(stored, digest) {
		return false, errInboxConflict
	}
	return true, nil
}

func insertEffectInbox(
	ctx context.Context, tx *sql.Tx, fact providerFact, effectKey string, digest []byte,
) (sql.Result, error) {
	result, err := tx.ExecContext(ctx, `
	INSERT INTO stripe_event_inbox (
	    event_id, payload_digest, stripe_event_type, normalized_type,
	    provider_object_id, payment_intent_id, charge_id,
	    metadata_tenant_id, metadata_order_id, currency,
	    provider_amount_minor, normalized_amount_minor, occurred_at, effect_key
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	ON CONFLICT (effect_key) DO NOTHING
	`, fact.EventID, digest, fact.EventType, fact.NormalizedType, fact.ProviderObjectID,
		fact.PaymentIntentID, fact.ChargeID, fact.MetadataTenantID, fact.MetadataOrderID,
		fact.Currency, fact.ProviderAmountMinor, fact.NormalizedAmountMinor, fact.OccurredAt, effectKey)
	if err != nil {
		return nil, fmt.Errorf("insert Stripe inbox: %w", err)
	}
	return result, nil
}

func replayOutcome(tx *sql.Tx, replay bool, err error) (inboxOutcome, error) {
	if err != nil {
		return 0, err
	}
	if !replay {
		return 0, errors.New("Stripe receipt outcome is inconsistent")
	}
	return inboxReplay, tx.Commit()
}

func checkoutRequestDigest(request checkoutRequest) []byte {
	digest := sha256.Sum256([]byte(request.SuccessURL + "\x00" + request.CancelURL))
	return digest[:]
}

func checkoutIdempotencyKey(tenantID, orderID string, generation int64) string {
	material := tenantID + "\x00" + orderID
	if generation > 1 {
		material += fmt.Sprintf("\x00%d", generation)
	}
	digest := sha256.Sum256([]byte(material))
	return "snaplink-checkout-" + hex.EncodeToString(digest[:])
}
