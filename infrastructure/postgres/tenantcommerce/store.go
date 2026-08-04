// Package tenantcommerce provides the shared PostgreSQL/CockroachDB adapter
// for tenant commercial contracts, wallet ledger, payments, and relay outbox.
package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

const schema = `
CREATE TABLE IF NOT EXISTS tenant_commerce_plans (
    id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'retired')),
    billing_interval TEXT NOT NULL CHECK (billing_interval IN ('none', 'month', 'year')),
    currency TEXT NOT NULL CHECK (length(currency) = 3),
    price_minor BIGINT NOT NULL CHECK (price_minor >= 0),
    grace_period_days INTEGER NOT NULL CHECK (grace_period_days >= 0),
    features JSONB NOT NULL,
    limits JSONB NOT NULL,
    created_at_ns BIGINT NOT NULL,
    PRIMARY KEY (id, version)
);
CREATE TABLE IF NOT EXISTS tenant_commerce_subscriptions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_version BIGINT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'trialing', 'active', 'past_due', 'paused', 'canceled', 'expired')),
    current_period_start_ns BIGINT NOT NULL,
    current_period_end_ns BIGINT NOT NULL,
    trial_end_ns BIGINT NOT NULL,
    grace_until_ns BIGINT NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL,
    canceled_at_ns BIGINT NOT NULL,
    provider TEXT NOT NULL,
    provider_subscription_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at_ns BIGINT NOT NULL,
    updated_at_ns BIGINT NOT NULL,
    FOREIGN KEY (plan_id, plan_version) REFERENCES tenant_commerce_plans(id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_commerce_one_live_subscription
    ON tenant_commerce_subscriptions(tenant_id)
    WHERE status NOT IN ('canceled', 'expired');
CREATE INDEX IF NOT EXISTS idx_tenant_commerce_subscriptions_history
    ON tenant_commerce_subscriptions(tenant_id, created_at_ns, id);
CREATE TABLE IF NOT EXISTS tenant_commerce_entitlements (
    tenant_id TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL REFERENCES tenant_commerce_subscriptions(id),
    plan_id TEXT NOT NULL,
    plan_version BIGINT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    active BOOLEAN NOT NULL,
    features JSONB NOT NULL,
    limits JSONB NOT NULL,
    effective_at_ns BIGINT NOT NULL,
    expires_at_ns BIGINT NOT NULL,
    generated_at_ns BIGINT NOT NULL,
    FOREIGN KEY (plan_id, plan_version) REFERENCES tenant_commerce_plans(id, version)
);
CREATE TABLE IF NOT EXISTS tenant_commerce_wallets (
    tenant_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (length(currency) = 3),
    balance_minor BIGINT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'frozen')),
    version BIGINT NOT NULL CHECK (version >= 0),
    updated_at_ns BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, currency)
);
CREATE TABLE IF NOT EXISTS tenant_commerce_ledger (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (length(currency) = 3),
    kind TEXT NOT NULL CHECK (kind IN ('top_up', 'usage', 'subscription', 'refund', 'chargeback_reversal', 'adjustment')),
    amount_minor BIGINT NOT NULL CHECK (amount_minor <> 0),
    balance_after BIGINT NOT NULL,
    wallet_version BIGINT NOT NULL CHECK (wallet_version > 0),
    idempotency_key TEXT NOT NULL,
    reference TEXT NOT NULL,
    occurred_at_ns BIGINT NOT NULL,
    created_at_ns BIGINT NOT NULL,
    UNIQUE (tenant_id, currency, idempotency_key),
    UNIQUE (tenant_id, currency, wallet_version),
    FOREIGN KEY (tenant_id, currency) REFERENCES tenant_commerce_wallets(tenant_id, currency)
);
CREATE INDEX IF NOT EXISTS idx_tenant_commerce_ledger_history
    ON tenant_commerce_ledger(tenant_id, currency, wallet_version DESC);
CREATE TABLE IF NOT EXISTS tenant_commerce_payment_orders (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_order_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (length(currency) = 3),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    paid_minor BIGINT NOT NULL CHECK (paid_minor >= 0),
    refunded_minor BIGINT NOT NULL CHECK (refunded_minor >= 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'canceled', 'partially_refunded', 'refunded')),
    idempotency_key TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at_ns BIGINT NOT NULL,
    updated_at_ns BIGINT NOT NULL,
    UNIQUE (tenant_id, provider, idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_commerce_provider_order
    ON tenant_commerce_payment_orders(provider, provider_order_id)
    WHERE provider_order_id <> '';
CREATE INDEX IF NOT EXISTS idx_tenant_commerce_payment_history
    ON tenant_commerce_payment_orders(tenant_id, created_at_ns, id);
CREATE TABLE IF NOT EXISTS tenant_commerce_payment_events (
    provider TEXT NOT NULL,
    id TEXT NOT NULL,
    provider_order_id TEXT NOT NULL,
    order_id TEXT NOT NULL REFERENCES tenant_commerce_payment_orders(id),
    type TEXT NOT NULL CHECK (type IN ('captured', 'rejected', 'refunded', 'chargeback', 'chargeback_reversed')),
    currency TEXT NOT NULL CHECK (length(currency) = 3),
    amount_minor BIGINT NOT NULL CHECK (amount_minor >= 0),
    occurred_at_ns BIGINT NOT NULL,
    applied_at_ns BIGINT NOT NULL,
    ledger_entry_id TEXT REFERENCES tenant_commerce_ledger(id),
    PRIMARY KEY (provider, id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_commerce_payment_events_order
    ON tenant_commerce_payment_events(order_id, occurred_at_ns, id);
CREATE TABLE IF NOT EXISTS tenant_commerce_outbox (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_version BIGINT NOT NULL CHECK (aggregate_version > 0),
    idempotency_key TEXT NOT NULL,
    occurred_at_ns BIGINT NOT NULL,
    payload JSONB NOT NULL,
    payload_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'delivered', 'quarantined', 'dead')),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    next_attempt_at_ns BIGINT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_until_ns BIGINT NOT NULL,
    last_error TEXT NOT NULL,
    delivered_at_ns BIGINT NOT NULL,
    created_at_ns BIGINT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_tenant_commerce_outbox_claim
    ON tenant_commerce_outbox(status, next_attempt_at_ns, lease_until_ns, created_at_ns, id);
`

const renewalSchema = `
ALTER TABLE tenant_commerce_subscriptions
    ADD COLUMN billing_interval TEXT NOT NULL DEFAULT 'none'
        CHECK (billing_interval IN ('none', 'month', 'year'));
ALTER TABLE tenant_commerce_subscriptions
    ADD COLUMN renewal_currency TEXT NOT NULL DEFAULT 'USD'
        CHECK (length(renewal_currency) = 3);
ALTER TABLE tenant_commerce_subscriptions
    ADD COLUMN renewal_price_minor BIGINT NOT NULL DEFAULT 0
        CHECK (renewal_price_minor >= 0);
ALTER TABLE tenant_commerce_subscriptions
    ADD COLUMN renewal_grace_days INTEGER NOT NULL DEFAULT 0
        CHECK (renewal_grace_days >= 0);
ALTER TABLE tenant_commerce_subscriptions
    ADD COLUMN renewal_next_attempt_at_ns BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tenant_commerce_subscriptions
    ADD COLUMN renewal_lease_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE tenant_commerce_subscriptions
    ADD COLUMN renewal_lease_until_ns BIGINT NOT NULL DEFAULT 0;
UPDATE tenant_commerce_subscriptions AS subscription SET
    billing_interval = plan.billing_interval,
    renewal_currency = plan.currency,
    renewal_price_minor = plan.price_minor,
    renewal_grace_days = plan.grace_period_days,
    renewal_next_attempt_at_ns = subscription.current_period_end_ns
FROM tenant_commerce_plans AS plan
WHERE subscription.plan_id = plan.id AND subscription.plan_version = plan.version;
CREATE INDEX IF NOT EXISTS idx_tenant_commerce_renewal_claim
    ON tenant_commerce_subscriptions(status, renewal_next_attempt_at_ns,
        current_period_end_ns, renewal_lease_until_ns, id);
ALTER TABLE tenant_commerce_ledger DROP CONSTRAINT IF EXISTS tenant_commerce_ledger_kind_check;
ALTER TABLE tenant_commerce_ledger ADD CONSTRAINT tenant_commerce_ledger_kind_check
    CHECK (kind IN ('top_up', 'usage', 'subscription', 'refund', 'adjustment'));
`

const quotaProjectionOutboxSchema = `
CREATE TABLE IF NOT EXISTS tenant_commerce_quota_outbox (
    event_id TEXT PRIMARY KEY REFERENCES tenant_commerce_outbox(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    projection_revision BIGINT NOT NULL CHECK (projection_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'delivered')),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    next_attempt_at_ns BIGINT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_until_ns BIGINT NOT NULL,
    last_error TEXT NOT NULL,
    delivered_revision BIGINT NOT NULL CHECK (delivered_revision >= 0),
    delivered_at_ns BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenant_commerce_quota_outbox_claim
    ON tenant_commerce_quota_outbox(status, next_attempt_at_ns, lease_until_ns, event_id);
INSERT INTO tenant_commerce_quota_outbox (
    event_id, tenant_id, projection_revision, status, attempts,
    next_attempt_at_ns, lease_owner, lease_until_ns, last_error,
    delivered_revision, delivered_at_ns
)
SELECT id, tenant_id, aggregate_version, 'pending', 0, 0, '', 0, '', 0, 0
FROM tenant_commerce_outbox
WHERE event_type = 'snaplink.billing.entitlement.snapshot_published'
ON CONFLICT (event_id) DO NOTHING;
`

const chargebackReversalSchema = `
ALTER TABLE tenant_commerce_ledger DROP CONSTRAINT IF EXISTS tenant_commerce_ledger_kind_check;
ALTER TABLE tenant_commerce_ledger ADD CONSTRAINT tenant_commerce_ledger_kind_check
    CHECK (kind IN ('top_up', 'usage', 'subscription', 'refund', 'chargeback_reversal', 'adjustment'));
ALTER TABLE tenant_commerce_payment_events
    DROP CONSTRAINT IF EXISTS tenant_commerce_payment_events_type_check;
ALTER TABLE tenant_commerce_payment_events ADD CONSTRAINT tenant_commerce_payment_events_type_check
    CHECK (type IN ('captured', 'rejected', 'refunded', 'chargeback', 'chargeback_reversed'));
`

var migrations = []migrate.Migration{
	{Version: 1, Name: "tenant commerce baseline", SQL: schema},
	{Version: 2, Name: "subscription renewal settlement", SQL: renewalSchema},
	{Version: 3, Name: "independent quota projection outbox", SQL: quotaProjectionOutboxSchema},
	{Version: 4, Name: "chargeback reversal settlement", SQL: chargebackReversalSchema},
}

type Store struct {
	db *sql.DB
}

func NewWithDB(db *sql.DB, dialect postgresbackend.Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("tenantcommerce/postgres: database is required")
	}
	if err := postgresbackend.Run(context.Background(), db, "tenant_commerce", migrations, dialect); err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("tenantcommerce/postgres: store closed")
	}
	return s.db.PingContext(ctx)
}

func MaxVersion() int { return migrate.MaxVersion(migrations) }

var _ commerce.Store = (*Store)(nil)
var _ commerce.QuotaProjectionDeliveryStore = (*Store)(nil)
