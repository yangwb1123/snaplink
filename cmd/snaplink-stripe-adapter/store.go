package main

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

//go:embed stripe_adapter.sql
var stripeAdapterMigration string

const stripeAdapterMigrationLock int64 = 0x5354524950450002

type adapterStore struct {
	db *sql.DB
}

func openAdapterStore(config runtimeConfig) (*adapterStore, error) {
	database, err := postgresbackend.Open(postgresbackend.Config{
		DSN: config.PostgresDSN, Dialect: postgresbackend.DialectPostgres,
		MaxOpenConns: 20, MaxIdleConns: 5,
		ConnMaxLifetime: 30 * time.Minute, ConnMaxIdleTime: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	return &adapterStore{db: database}, nil
}

func (s *adapterStore) Close() error { return s.db.Close() }

func (s *adapterStore) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("stripe adapter migrate begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, stripeAdapterMigrationLock); err != nil {
		return fmt.Errorf("stripe adapter migrate lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, stripeAdapterMigration); err != nil {
		return fmt.Errorf("stripe adapter migrate schema: %w", err)
	}
	var version int
	if err := tx.QueryRowContext(ctx,
		`SELECT version FROM stripe_adapter_schema_version WHERE singleton = TRUE`).Scan(&version); err != nil || version != 2 {
		return fmt.Errorf("stripe adapter migrate version: %w", errors.Join(err, errInvalidConfig))
	}
	return tx.Commit()
}

func (s *adapterStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *adapterStore) SaveCheckout(
	ctx context.Context, reservation checkoutReservation, session stripeCheckoutSession,
) (checkoutReservation, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return checkoutReservation{}, err
	}
	defer tx.Rollback()
	current, err := getCheckoutQuery(ctx, tx, reservation.TenantID, reservation.OrderID, true)
	if err != nil {
		return checkoutReservation{}, err
	}
	if current.Generation != reservation.Generation || current.IdempotencyKey != reservation.IdempotencyKey {
		return checkoutReservation{}, errCheckoutConflict
	}
	if !checkoutSessionCompatible(current, session) {
		return checkoutReservation{}, errCheckoutConflict
	}
	if !current.complete() {
		_, err = tx.ExecContext(ctx, `
UPDATE stripe_checkout_mappings
SET stripe_session_id = $3, redirect_url = $4, session_expires_at = $5,
    payment_intent_id = $6, updated_at = clock_timestamp()
WHERE tenant_id = $1 AND order_id = $2
`, current.TenantID, current.OrderID, session.ID, session.URL, session.ExpiresAt, session.PaymentIntent)
		if err != nil {
			return checkoutReservation{}, fmt.Errorf("save checkout: %w", classifyStoreConflict(err))
		}
		current.SessionID, current.RedirectURL = session.ID, session.URL
		current.ExpiresAt, current.PaymentIntent = session.ExpiresAt, session.PaymentIntent
	}
	if err := tx.Commit(); err != nil {
		return checkoutReservation{}, err
	}
	return current, nil
}

func checkoutSessionCompatible(current checkoutReservation, session stripeCheckoutSession) bool {
	if !current.complete() {
		return current.PaymentIntent == "" || session.PaymentIntent == "" || current.PaymentIntent == session.PaymentIntent
	}
	return current.SessionID == session.ID && current.RedirectURL == session.URL &&
		current.ExpiresAt.Equal(session.ExpiresAt) &&
		(current.PaymentIntent == "" || session.PaymentIntent == "" || current.PaymentIntent == session.PaymentIntent)
}

func (s *adapterStore) getCheckout(
	ctx context.Context, tenantID, orderID string, lock bool,
) (checkoutReservation, error) {
	return getCheckoutQuery(ctx, s.db, tenantID, orderID, lock)
}

func getCheckoutQuery(
	ctx context.Context, query interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}, tenantID, orderID string, lock bool,
) (checkoutReservation, error) {
	statement := `
SELECT tenant_id, order_id, currency, amount_minor, request_digest,
       stripe_idempotency_key, stripe_session_id, redirect_url,
       session_expires_at, payment_intent_id, checkout_generation
FROM stripe_checkout_mappings WHERE tenant_id = $1 AND order_id = $2`
	if lock {
		statement += ` FOR UPDATE`
	}
	var result checkoutReservation
	var expires sql.NullTime
	err := query.QueryRowContext(ctx, statement, tenantID, orderID).Scan(
		&result.TenantID, &result.OrderID, &result.Currency, &result.AmountMinor,
		&result.RequestDigest, &result.IdempotencyKey, &result.SessionID,
		&result.RedirectURL, &expires, &result.PaymentIntent, &result.Generation,
	)
	if err != nil {
		return checkoutReservation{}, fmt.Errorf("get checkout: %w", err)
	}
	if result.SessionID != "" {
		result.ExpiresAt = expires.Time
	}
	return result, nil
}

func (s *adapterStore) ClaimInbox(
	ctx context.Context, owner string, lease time.Duration, limit int,
) ([]inboxClaim, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH candidates AS (
    SELECT event_id FROM stripe_event_inbox
	    WHERE delivered_at IS NULL AND quarantined_at IS NULL
	      AND available_at <= clock_timestamp()
      AND (claim_until IS NULL OR claim_until <= clock_timestamp())
    ORDER BY occurred_at, event_id
    FOR UPDATE SKIP LOCKED
    LIMIT $1
)
UPDATE stripe_event_inbox AS inbox
SET claim_owner = $2, claim_generation = inbox.claim_generation + 1,
    claim_until = clock_timestamp() + ($3 * interval '1 second')
FROM candidates WHERE inbox.event_id = candidates.event_id
RETURNING inbox.event_id, inbox.payload_digest, inbox.stripe_event_type,
    inbox.normalized_type, inbox.provider_object_id, inbox.payment_intent_id,
    inbox.charge_id, inbox.metadata_tenant_id, inbox.metadata_order_id,
    inbox.currency, inbox.provider_amount_minor, inbox.normalized_amount_minor,
    inbox.occurred_at, inbox.claim_owner, inbox.claim_generation, inbox.attempt_count
`, limit, owner, int64(lease/time.Second))
	if err != nil {
		return nil, fmt.Errorf("claim Stripe inbox: %w", err)
	}
	defer rows.Close()
	var claims []inboxClaim
	for rows.Next() {
		claim, err := scanInboxClaim(rows)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}
	return claims, rows.Err()
}

func scanInboxClaim(scanner interface{ Scan(...any) error }) (inboxClaim, error) {
	var claim inboxClaim
	err := scanner.Scan(
		&claim.EventID, &claim.Digest, &claim.EventType, &claim.NormalizedType,
		&claim.ProviderObjectID, &claim.PaymentIntentID, &claim.ChargeID,
		&claim.MetadataTenantID, &claim.MetadataOrderID, &claim.Currency,
		&claim.ProviderAmountMinor, &claim.NormalizedAmountMinor, &claim.OccurredAt,
		&claim.ClaimOwner, &claim.ClaimGeneration, &claim.AttemptCount,
	)
	if err != nil {
		return inboxClaim{}, fmt.Errorf("scan Stripe inbox claim: %w", err)
	}
	return claim, nil
}

func (s *adapterStore) ResolveClaim(ctx context.Context, claim inboxClaim) (trustedDelivery, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return trustedDelivery{}, err
	}
	defer tx.Rollback()
	if err := verifyClaimFence(ctx, tx, claim); err != nil {
		return trustedDelivery{}, err
	}
	mapping, err := resolveCheckoutMapping(ctx, tx, claim)
	if err != nil {
		return trustedDelivery{}, err
	}
	if err := validateFactMapping(claim.providerFact, mapping); err != nil {
		return trustedDelivery{}, err
	}
	mapping = mergeProviderIDs(mapping, claim.providerFact)
	if mapping.PaymentIntent == "" {
		return trustedDelivery{}, errMappingNotFound
	}
	if err := persistResolvedMapping(ctx, tx, claim, mapping); err != nil {
		return trustedDelivery{}, err
	}
	if err := tx.Commit(); err != nil {
		return trustedDelivery{}, err
	}
	return trustedDelivery{
		EventID: claim.EventID, TenantID: mapping.TenantID, OrderID: mapping.OrderID,
		ProviderOrderID: mapping.PaymentIntent, Type: claim.NormalizedType,
		Currency: claim.Currency, AmountMinor: claim.NormalizedAmountMinor,
		OccurredAt: claim.OccurredAt, ClaimOwner: claim.ClaimOwner,
		ClaimGeneration: claim.ClaimGeneration,
	}, nil
}

func verifyClaimFence(ctx context.Context, tx *sql.Tx, claim inboxClaim) error {
	var exists bool
	err := tx.QueryRowContext(ctx, `
SELECT TRUE FROM stripe_event_inbox
	WHERE event_id = $1 AND delivered_at IS NULL AND quarantined_at IS NULL AND claim_owner = $2
  AND claim_generation = $3 AND claim_until > clock_timestamp()
FOR UPDATE
`, claim.EventID, claim.ClaimOwner, claim.ClaimGeneration).Scan(&exists)
	if err != nil || !exists {
		return errClaimLost
	}
	return nil
}

func resolveCheckoutMapping(ctx context.Context, tx *sql.Tx, claim inboxClaim) (checkoutMapping, error) {
	var candidates []checkoutMapping
	selectors := []struct{ column, value string }{
		{"payment_intent_id", claim.PaymentIntentID},
		{"charge_id", claim.ChargeID},
	}
	if claim.MetadataTenantID != "" {
		mapping, err := mappingByOrder(ctx, tx, claim.MetadataTenantID, claim.MetadataOrderID)
		if err != nil {
			return checkoutMapping{}, err
		}
		candidates = append(candidates, mapping)
	}
	for _, selector := range selectors {
		if selector.value == "" {
			continue
		}
		mapping, found, err := mappingByProviderID(ctx, tx, selector.column, selector.value)
		if err != nil {
			return checkoutMapping{}, err
		}
		if found {
			candidates = append(candidates, mapping)
		}
	}
	return chooseMapping(candidates)
}

func mappingByOrder(
	ctx context.Context, tx *sql.Tx, tenantID, orderID string,
) (checkoutMapping, error) {
	return scanMapping(tx.QueryRowContext(ctx, `
SELECT tenant_id, order_id, currency, amount_minor, payment_intent_id, charge_id
FROM stripe_checkout_mappings WHERE tenant_id = $1 AND order_id = $2 FOR UPDATE
`, tenantID, orderID))
}

func mappingByProviderID(
	ctx context.Context, tx *sql.Tx, column, value string,
) (checkoutMapping, bool, error) {
	statement := `SELECT tenant_id, order_id, currency, amount_minor, payment_intent_id, charge_id
FROM stripe_checkout_mappings WHERE payment_intent_id = $1 FOR UPDATE`
	if column == "charge_id" {
		statement = `SELECT tenant_id, order_id, currency, amount_minor, payment_intent_id, charge_id
FROM stripe_checkout_mappings WHERE charge_id = $1 FOR UPDATE`
	}
	mapping, err := scanMapping(tx.QueryRowContext(ctx, statement, value))
	if errors.Is(err, sql.ErrNoRows) {
		return checkoutMapping{}, false, nil
	}
	return mapping, err == nil, err
}

func scanMapping(scanner interface{ Scan(...any) error }) (checkoutMapping, error) {
	var mapping checkoutMapping
	err := scanner.Scan(&mapping.TenantID, &mapping.OrderID, &mapping.Currency,
		&mapping.AmountMinor, &mapping.PaymentIntent, &mapping.ChargeID)
	return mapping, err
}

func chooseMapping(candidates []checkoutMapping) (checkoutMapping, error) {
	if len(candidates) == 0 {
		return checkoutMapping{}, errMappingNotFound
	}
	selected := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.TenantID != selected.TenantID || candidate.OrderID != selected.OrderID {
			return checkoutMapping{}, errCheckoutConflict
		}
	}
	return selected, nil
}

func validateFactMapping(fact providerFact, mapping checkoutMapping) error {
	if err := validateMappingIdentity(fact, mapping); err != nil {
		return err
	}
	return validateMappingAmount(fact, mapping)
}

func validateMappingIdentity(fact providerFact, mapping checkoutMapping) error {
	if fact.Currency != mapping.Currency || fact.ProviderAmountMinor <= 0 {
		return errCheckoutConflict
	}
	if fact.MetadataTenantID != "" &&
		(fact.MetadataTenantID != mapping.TenantID || fact.MetadataOrderID != mapping.OrderID) {
		return errCheckoutConflict
	}
	if mapping.PaymentIntent != "" && fact.PaymentIntentID != "" && mapping.PaymentIntent != fact.PaymentIntentID {
		return errCheckoutConflict
	}
	if mapping.ChargeID != "" && fact.ChargeID != "" && mapping.ChargeID != fact.ChargeID {
		return errCheckoutConflict
	}
	return nil
}

func validateMappingAmount(fact providerFact, mapping checkoutMapping) error {
	if (fact.NormalizedType == eventCaptured || fact.NormalizedType == eventRejectedLegacy) &&
		fact.ProviderAmountMinor != mapping.AmountMinor {
		return errCheckoutConflict
	}
	if fact.NormalizedAmountMinor > mapping.AmountMinor {
		return errCheckoutConflict
	}
	return nil
}

func mergeProviderIDs(mapping checkoutMapping, fact providerFact) checkoutMapping {
	if mapping.PaymentIntent == "" {
		mapping.PaymentIntent = fact.PaymentIntentID
	}
	if mapping.ChargeID == "" {
		mapping.ChargeID = fact.ChargeID
	}
	return mapping
}

func persistResolvedMapping(
	ctx context.Context, tx *sql.Tx, claim inboxClaim, mapping checkoutMapping,
) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE stripe_checkout_mappings SET payment_intent_id = $3, charge_id = $4,
    updated_at = clock_timestamp() WHERE tenant_id = $1 AND order_id = $2
`, mapping.TenantID, mapping.OrderID, mapping.PaymentIntent, mapping.ChargeID); err != nil {
		return fmt.Errorf("bind Stripe provider identifiers: %w", classifyStoreConflict(err))
	}
	result, err := tx.ExecContext(ctx, `
UPDATE stripe_event_inbox SET trusted_tenant_id = $4, trusted_order_id = $5,
    provider_order_id = $6
WHERE event_id = $1 AND claim_owner = $2 AND claim_generation = $3
  AND claim_until > clock_timestamp()
`, claim.EventID, claim.ClaimOwner, claim.ClaimGeneration,
		mapping.TenantID, mapping.OrderID, mapping.PaymentIntent)
	if err != nil {
		return fmt.Errorf("bind Stripe inbox fact: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return errClaimLost
	}
	return nil
}

func (s *adapterStore) AckInbox(ctx context.Context, delivery trustedDelivery) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE stripe_event_inbox SET delivered_at = clock_timestamp(), claim_owner = '', claim_until = NULL,
    last_error_code = '' WHERE event_id = $1 AND delivered_at IS NULL
    AND claim_owner = $2 AND claim_generation = $3 AND claim_until > clock_timestamp()
`, delivery.EventID, delivery.ClaimOwner, delivery.ClaimGeneration)
	return fencedResult("ack Stripe inbox", result, err)
}

func (s *adapterStore) NackInbox(
	ctx context.Context, claim inboxClaim, delay time.Duration, category string,
) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE stripe_event_inbox SET attempt_count = attempt_count + 1,
    available_at = clock_timestamp() + ($4 * interval '1 second'),
    claim_owner = '', claim_until = NULL, last_error_code = $5
WHERE event_id = $1 AND delivered_at IS NULL
  AND claim_owner = $2 AND claim_generation = $3
  AND claim_until > clock_timestamp()
`, claim.EventID, claim.ClaimOwner, claim.ClaimGeneration, int64(delay/time.Second), category)
	return fencedResult("nack Stripe inbox", result, err)
}

func (s *adapterStore) QuarantineInbox(ctx context.Context, claim inboxClaim, category string) error {
	result, err := s.db.ExecContext(ctx, `
	UPDATE stripe_event_inbox SET quarantined_at = clock_timestamp(), quarantine_code = $4,
	    claim_owner = '', claim_until = NULL, last_error_code = $4
	WHERE event_id = $1 AND delivered_at IS NULL AND quarantined_at IS NULL
	  AND claim_owner = $2 AND claim_generation = $3 AND claim_until > clock_timestamp()
	`, claim.EventID, claim.ClaimOwner, claim.ClaimGeneration, category)
	return fencedResult("quarantine Stripe inbox", result, err)
}

func fencedResult(operation string, result sql.Result, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows: %w", operation, err)
	}
	if affected != 1 {
		return errClaimLost
	}
	return nil
}

func (s *adapterStore) Backlog(ctx context.Context) (backlogState, error) {
	var state backlogState
	var oldest sql.NullTime
	err := s.db.QueryRowContext(ctx, `
	SELECT count(*) FILTER (WHERE delivered_at IS NULL AND quarantined_at IS NULL),
	       min(received_at) FILTER (WHERE delivered_at IS NULL AND quarantined_at IS NULL),
	       count(*) FILTER (WHERE quarantined_at IS NOT NULL)
	FROM stripe_event_inbox
	`).Scan(&state.Count, &oldest, &state.Quarantined)
	if oldest.Valid {
		state.Oldest = oldest.Time
	}
	return state, err
}
