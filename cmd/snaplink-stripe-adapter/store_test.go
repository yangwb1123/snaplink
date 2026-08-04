package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAdapterSchemaExcludesRawProviderMaterial(t *testing.T) {
	lower := strings.ToLower(stripeAdapterMigration)
	for _, forbidden := range []string{"raw_payload", "stripe_signature", "api_key", "card_number", "client_secret"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("adapter schema contains forbidden provider material column %q", forbidden)
		}
	}
}

func TestPostgresInboxIdempotencyAndDigestConflict(t *testing.T) {
	store := integrationAdapterStore(t)
	fact := testCaptureFact("evt_idempotent", time.Now().UTC())
	digest := bytes.Repeat([]byte{1}, 32)
	if outcome, err := store.InsertInbox(context.Background(), fact, digest); err != nil || outcome != inboxInserted {
		t.Fatalf("first insert outcome=%v error=%v", outcome, err)
	}
	if outcome, err := store.InsertInbox(context.Background(), fact, digest); err != nil || outcome != inboxReplay {
		t.Fatalf("replay outcome=%v error=%v", outcome, err)
	}
	_, err := store.InsertInbox(context.Background(), fact, bytes.Repeat([]byte{2}, 32))
	if !errors.Is(err, errInboxConflict) {
		t.Fatalf("digest conflict error=%v", err)
	}
}

func TestPostgresInboxDeduplicatesProviderEffectAcrossEventIDs(t *testing.T) {
	store := integrationAdapterStore(t)
	first := testCaptureFact("evt_effect_one", time.Now().UTC())
	second := first
	second.EventID = "evt_effect_two"
	if outcome, err := store.InsertInbox(context.Background(), first, bytes.Repeat([]byte{1}, 32)); err != nil || outcome != inboxInserted {
		t.Fatalf("first effect outcome=%v error=%v", outcome, err)
	}
	if outcome, err := store.InsertInbox(context.Background(), second, bytes.Repeat([]byte{2}, 32)); err != nil || outcome != inboxEffectReplay {
		t.Fatalf("duplicate effect outcome=%v error=%v", outcome, err)
	}
	var inboxCount, receiptCount int
	if err := store.db.QueryRow(`SELECT count(*) FROM stripe_event_inbox`).Scan(&inboxCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT count(*) FROM stripe_event_receipts`).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if inboxCount != 1 || receiptCount != 2 {
		t.Fatalf("inbox=%d receipts=%d", inboxCount, receiptCount)
	}
}

func TestPostgresMigrationPreservesV1EffectsAndQuarantinesLegacyRows(t *testing.T) {
	store := v1MigrationAdapterStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var version, receipts, activeRefunds, quarantined int
	if err := store.db.QueryRowContext(ctx, `SELECT version FROM stripe_adapter_schema_version WHERE singleton`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	query := `SELECT count(*), count(*) FILTER (WHERE normalized_type = 'refunded' AND quarantined_at IS NULL),
		count(*) FILTER (WHERE quarantined_at IS NOT NULL) FROM stripe_event_inbox`
	if err := store.db.QueryRowContext(ctx, query).Scan(&receipts, &activeRefunds, &quarantined); err != nil {
		t.Fatal(err)
	}
	var receiptCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM stripe_event_receipts`).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if version != 2 || receipts != 5 || receiptCount != 5 || activeRefunds != 0 || quarantined != 5 {
		t.Fatalf("version=%d rows=%d receipts=%d active_refunds=%d quarantined=%d", version, receipts, receiptCount, activeRefunds, quarantined)
	}
}

func TestPostgresConcurrentMigrationIsSerialized(t *testing.T) {
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping Stripe adapter PostgreSQL migration test")
	}
	base, err := openAdapterStore(runtimeConfig{PostgresDSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("stripe_adapter_concurrent_%d", time.Now().UnixNano())
	if _, err := base.db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = base.db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = base.Close()
	})
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	scopedDSN := dsn + separator + "search_path=" + schema
	stores := make([]*adapterStore, 2)
	for index := range stores {
		stores[index], err = openAdapterStore(runtimeConfig{PostgresDSN: scopedDSN})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stores[index].Close() })
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make(chan error, len(stores))
	for _, store := range stores {
		go func() { results <- store.Migrate(ctx) }()
	}
	for range stores {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	var version int
	if err := stores[0].db.QueryRowContext(ctx,
		`SELECT version FROM stripe_adapter_schema_version WHERE singleton`).Scan(&version); err != nil || version != 2 {
		t.Fatalf("schema version=%d error=%v", version, err)
	}
}

func TestPostgresCheckoutReservationIsImmutableAndIdempotent(t *testing.T) {
	store := integrationAdapterStore(t)
	order := testPaymentOrder()
	request := checkoutRequest{
		OrderID: order.ID, SuccessURL: "https://console.example.test/s", CancelURL: "https://console.example.test/c",
	}
	reserved, err := store.ReserveCheckout(context.Background(), order, request)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.ReserveCheckout(context.Background(), order, request); err != nil || replay.IdempotencyKey != reserved.IdempotencyKey {
		t.Fatalf("reservation replay=%+v error=%v", replay, err)
	}
	request.CancelURL = "https://console.example.test/different"
	if _, err := store.ReserveCheckout(context.Background(), order, request); !errors.Is(err, errCheckoutConflict) {
		t.Fatalf("mutated checkout error=%v", err)
	}
	saved, err := store.SaveCheckout(context.Background(), reserved, testStripeSession())
	if err != nil || !saved.complete() {
		t.Fatalf("saved reservation=%+v error=%v", saved, err)
	}
	conflict := testStripeSession()
	conflict.ID = "cs_other"
	if _, err := store.SaveCheckout(context.Background(), saved, conflict); !errors.Is(err, errCheckoutConflict) {
		t.Fatalf("provider response conflict error=%v", err)
	}
	otherOrder := order
	otherOrder.ID = "order-two"
	otherRequest := request
	otherRequest.OrderID = otherOrder.ID
	otherRequest.CancelURL = "https://console.example.test/other"
	other, err := store.ReserveCheckout(context.Background(), otherOrder, otherRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveCheckout(context.Background(), other, testStripeSession()); !errors.Is(err, errCheckoutConflict) {
		t.Fatalf("cross-order provider id conflict error=%v", err)
	}
}

func TestPostgresCheckoutRotatesExpiredSessionAndFencesStaleSave(t *testing.T) {
	store := integrationAdapterStore(t)
	order := testPaymentOrder()
	request := checkoutRequest{OrderID: order.ID, SuccessURL: "https://console.example.test/s", CancelURL: "https://console.example.test/c"}
	reserved, err := store.ReserveCheckout(context.Background(), order, request)
	if err != nil {
		t.Fatal(err)
	}
	expired := testStripeSession()
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	saved, err := store.SaveCheckout(context.Background(), reserved, expired)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := store.ReserveCheckout(context.Background(), order, request)
	if err != nil {
		t.Fatal(err)
	}
	if !rotated.Rotated || rotated.complete() || rotated.Generation != saved.Generation+1 || rotated.IdempotencyKey == saved.IdempotencyKey {
		t.Fatalf("rotated reservation=%+v saved=%+v", rotated, saved)
	}
	if _, err := store.SaveCheckout(context.Background(), saved, expired); !errors.Is(err, errCheckoutConflict) {
		t.Fatalf("stale generation save error=%v", err)
	}
	if refreshed, err := store.SaveCheckout(context.Background(), rotated, testStripeSession()); err != nil || !refreshed.complete() {
		t.Fatalf("refreshed reservation=%+v error=%v", refreshed, err)
	}
}

func TestPostgresNackRejectsExpiredLease(t *testing.T) {
	store := integrationAdapterStore(t)
	fact := testCaptureFact("evt_expired_claim", time.Now().UTC())
	insertFact(t, store, fact, 5)
	claim := claimOne(t, store, "owner-expired")
	if _, err := store.db.Exec(`UPDATE stripe_event_inbox SET claim_until = clock_timestamp() - interval '1 second' WHERE event_id = $1`, fact.EventID); err != nil {
		t.Fatal(err)
	}
	if err := store.NackInbox(context.Background(), claim, time.Second, "test"); !errors.Is(err, errClaimLost) {
		t.Fatalf("expired nack error=%v", err)
	}
}

func TestPostgresRelayRecoversOutOfOrderRefundAndFencesClaims(t *testing.T) {
	store := integrationAdapterStore(t)
	reserveMappingWithoutIntent(t, store)
	refund := testRefundFact("evt_refund_first", time.Now().Add(-time.Minute).UTC())
	insertFact(t, store, refund, 3)
	first := claimOne(t, store, "owner-one")
	if _, err := store.ResolveClaim(context.Background(), first); !errors.Is(err, errMappingNotFound) {
		t.Fatalf("unresolved refund error=%v", err)
	}
	if err := store.NackInbox(context.Background(), first, time.Hour, "mapping"); err != nil {
		t.Fatal(err)
	}
	if err := store.AckInbox(context.Background(), trustedFromClaim(first)); !errors.Is(err, errClaimLost) {
		t.Fatalf("stale acknowledgement error=%v", err)
	}

	capture := testCaptureFact("evt_capture_second", time.Now().UTC())
	insertFact(t, store, capture, 4)
	captureDelivery := resolveAndAck(t, store, claimOne(t, store, "owner-two"))
	if captureDelivery.ProviderOrderID != "pi_one" || captureDelivery.Type != eventCaptured {
		t.Fatalf("capture delivery=%+v", captureDelivery)
	}
	if _, err := store.db.Exec(`UPDATE stripe_event_inbox SET available_at = clock_timestamp() WHERE event_id = $1`, refund.EventID); err != nil {
		t.Fatal(err)
	}
	refundDelivery := resolveAndAck(t, store, claimOne(t, store, "owner-three"))
	if refundDelivery.OrderID != "order-one" || refundDelivery.AmountMinor != 400 || refundDelivery.Type != eventRefunded {
		t.Fatalf("refund delivery=%+v", refundDelivery)
	}
}

func integrationAdapterStore(t *testing.T) *adapterStore {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping Stripe adapter PostgreSQL integration test")
	}
	store, err := openAdapterStore(runtimeConfig{PostgresDSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `TRUNCATE stripe_event_receipts, stripe_event_inbox, stripe_checkout_mappings`); err != nil {
		t.Fatal(err)
	}
	return store
}

func v1MigrationAdapterStore(t *testing.T) *adapterStore {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping Stripe adapter PostgreSQL migration test")
	}
	base, err := openAdapterStore(runtimeConfig{PostgresDSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("stripe_adapter_v1_%d", time.Now().UnixNano())
	if _, err := base.db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		_ = base.Close()
		t.Fatal(err)
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	store, err := openAdapterStore(runtimeConfig{PostgresDSN: dsn + separator + "search_path=" + schema})
	if err != nil {
		_, _ = base.db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = base.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
		_, _ = base.db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = base.Close()
	})
	if _, err := store.db.Exec(v1StripeAdapterSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(v1StripeAdapterSeed); err != nil {
		t.Fatal(err)
	}
	return store
}

func reserveMappingWithoutIntent(t *testing.T, store *adapterStore) {
	t.Helper()
	request := checkoutRequest{
		OrderID: "order-one", SuccessURL: "https://console.example.test/s", CancelURL: "https://console.example.test/c",
	}
	reservation, err := store.ReserveCheckout(context.Background(), testPaymentOrder(), request)
	if err != nil {
		t.Fatal(err)
	}
	session := testStripeSession()
	session.PaymentIntent = ""
	if _, err := store.SaveCheckout(context.Background(), reservation, session); err != nil {
		t.Fatal(err)
	}
}

func insertFact(t *testing.T, store *adapterStore, fact providerFact, fill byte) {
	t.Helper()
	if _, err := store.InsertInbox(context.Background(), fact, bytes.Repeat([]byte{fill}, 32)); err != nil {
		t.Fatal(err)
	}
}

func claimOne(t *testing.T, store *adapterStore, owner string) inboxClaim {
	t.Helper()
	claims, err := store.ClaimInbox(context.Background(), owner, 30*time.Second, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims=%+v error=%v", claims, err)
	}
	return claims[0]
}

func resolveAndAck(t *testing.T, store *adapterStore, claim inboxClaim) trustedDelivery {
	t.Helper()
	delivery, err := store.ResolveClaim(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AckInbox(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	return delivery
}

func trustedFromClaim(claim inboxClaim) trustedDelivery {
	return trustedDelivery{
		EventID: claim.EventID, ClaimOwner: claim.ClaimOwner, ClaimGeneration: claim.ClaimGeneration,
	}
}

func testCaptureFact(eventID string, occurredAt time.Time) providerFact {
	return providerFact{
		EventID: eventID, EventType: stripeEventSucceeded, NormalizedType: eventCaptured,
		ProviderObjectID: "pi_one", PaymentIntentID: "pi_one", ChargeID: "ch_one",
		MetadataTenantID: "tenant-one", MetadataOrderID: "order-one", Currency: "USD",
		ProviderAmountMinor: 1250, NormalizedAmountMinor: 1250, OccurredAt: occurredAt,
	}
}

func testRefundFact(eventID string, occurredAt time.Time) providerFact {
	return providerFact{
		EventID: eventID, EventType: stripeEventRefund, NormalizedType: eventRefunded,
		ProviderObjectID: "re_one", PaymentIntentID: "pi_one", ChargeID: "ch_one", Currency: "USD",
		ProviderAmountMinor: 400, NormalizedAmountMinor: 400, OccurredAt: occurredAt,
	}
}

const v1StripeAdapterSchema = `
CREATE TABLE stripe_adapter_schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version INTEGER NOT NULL CHECK (version = 1), applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO stripe_adapter_schema_version (singleton, version) VALUES (TRUE, 1);
CREATE TABLE stripe_event_inbox (
    event_id TEXT PRIMARY KEY CHECK (event_id <> '' AND length(event_id) <= 255),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    stripe_event_type TEXT NOT NULL CONSTRAINT stripe_event_inbox_stripe_event_type_check CHECK (
        stripe_event_type IN ('payment_intent.succeeded', 'payment_intent.payment_failed', 'refund.created', 'charge.dispute.created')
    ),
    normalized_type TEXT NOT NULL CONSTRAINT stripe_event_inbox_normalized_type_check CHECK (
        normalized_type IN ('captured', 'rejected', 'refunded', 'chargeback')
    ),
    provider_object_id TEXT NOT NULL CHECK (provider_object_id <> '' AND length(provider_object_id) <= 255),
    payment_intent_id TEXT NOT NULL DEFAULT '' CHECK (length(payment_intent_id) <= 255),
    charge_id TEXT NOT NULL DEFAULT '' CHECK (length(charge_id) <= 255),
    metadata_tenant_id TEXT NOT NULL DEFAULT '' CHECK (length(metadata_tenant_id) <= 256),
    metadata_order_id TEXT NOT NULL DEFAULT '' CHECK (length(metadata_order_id) <= 256),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    provider_amount_minor BIGINT NOT NULL CHECK (provider_amount_minor > 0),
    normalized_amount_minor BIGINT NOT NULL CHECK (normalized_amount_minor >= 0),
    occurred_at TIMESTAMPTZ NOT NULL,
    trusted_tenant_id TEXT NOT NULL DEFAULT '' CHECK (length(trusted_tenant_id) <= 256),
    trusted_order_id TEXT NOT NULL DEFAULT '' CHECK (length(trusted_order_id) <= 256),
    provider_order_id TEXT NOT NULL DEFAULT '' CHECK (length(provider_order_id) <= 255),
    available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    claim_owner TEXT NOT NULL DEFAULT '' CHECK (length(claim_owner) <= 256),
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claim_until TIMESTAMPTZ, delivered_at TIMESTAMPTZ,
    last_error_code TEXT NOT NULL DEFAULT '' CHECK (length(last_error_code) <= 64),
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((metadata_tenant_id = '') = (metadata_order_id = ''))
);`

const v1StripeAdapterSeed = `
INSERT INTO stripe_event_inbox (
    event_id, payload_digest, stripe_event_type, normalized_type, provider_object_id,
    payment_intent_id, charge_id, currency, provider_amount_minor, normalized_amount_minor,
    occurred_at, received_at, delivered_at
) VALUES
    ('evt_refund_old', decode(repeat('01', 32), 'hex'), 'refund.created', 'refunded', 're_one',
     'pi_one', 'ch_one', 'USD', 400, 400, clock_timestamp() - interval '3 minutes',
     clock_timestamp() - interval '3 minutes', NULL),
    ('evt_refund_duplicate', decode(repeat('02', 32), 'hex'), 'refund.created', 'refunded', 're_one',
     'pi_one', 'ch_one', 'USD', 400, 400, clock_timestamp() - interval '2 minutes',
     clock_timestamp() - interval '2 minutes', NULL),
    ('evt_failed_legacy', decode(repeat('03', 32), 'hex'), 'payment_intent.payment_failed', 'rejected', 'pi_failed',
     'pi_failed', '', 'USD', 1250, 0, clock_timestamp() - interval '1 minute',
     clock_timestamp() - interval '1 minute', NULL),
    ('evt_failed_duplicate', decode(repeat('04', 32), 'hex'), 'payment_intent.payment_failed', 'rejected', 'pi_failed',
     'pi_failed', '', 'USD', 1250, 0, clock_timestamp() - interval '30 seconds',
     clock_timestamp() - interval '30 seconds', NULL),
    ('evt_dispute_created', decode(repeat('05', 32), 'hex'), 'charge.dispute.created', 'chargeback', 'dp_old',
     'pi_one', 'ch_one', 'USD', 700, 700, clock_timestamp() - interval '20 seconds',
     clock_timestamp() - interval '20 seconds', NULL);`
