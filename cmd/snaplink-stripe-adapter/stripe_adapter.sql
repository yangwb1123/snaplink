CREATE TABLE IF NOT EXISTS stripe_adapter_schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO stripe_adapter_schema_version (singleton, version)
VALUES (TRUE, 1)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS stripe_checkout_mappings (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> '' AND length(tenant_id) <= 256),
    order_id TEXT NOT NULL CHECK (order_id <> '' AND length(order_id) <= 256),
    currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    stripe_idempotency_key TEXT NOT NULL UNIQUE CHECK (
        stripe_idempotency_key <> '' AND length(stripe_idempotency_key) <= 255
    ),
    checkout_generation BIGINT NOT NULL DEFAULT 1 CHECK (checkout_generation > 0),
    stripe_session_id TEXT NOT NULL DEFAULT '' CHECK (length(stripe_session_id) <= 255),
    redirect_url TEXT NOT NULL DEFAULT '' CHECK (length(redirect_url) <= 4096),
    session_expires_at TIMESTAMPTZ,
    payment_intent_id TEXT NOT NULL DEFAULT '' CHECK (length(payment_intent_id) <= 255),
    charge_id TEXT NOT NULL DEFAULT '' CHECK (length(charge_id) <= 255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, order_id),
    CHECK ((stripe_session_id = '' AND redirect_url = '' AND session_expires_at IS NULL)
        OR (stripe_session_id <> '' AND redirect_url <> '' AND session_expires_at IS NOT NULL))
);

ALTER TABLE stripe_checkout_mappings
    ADD COLUMN IF NOT EXISTS checkout_generation BIGINT NOT NULL DEFAULT 1;
ALTER TABLE stripe_checkout_mappings
    DROP CONSTRAINT IF EXISTS stripe_checkout_mappings_checkout_generation_check;
ALTER TABLE stripe_checkout_mappings
    ADD CONSTRAINT stripe_checkout_mappings_checkout_generation_check CHECK (checkout_generation > 0);

CREATE UNIQUE INDEX IF NOT EXISTS stripe_checkout_session_unique
    ON stripe_checkout_mappings (stripe_session_id) WHERE stripe_session_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS stripe_checkout_payment_intent_unique
    ON stripe_checkout_mappings (payment_intent_id) WHERE payment_intent_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS stripe_checkout_charge_unique
    ON stripe_checkout_mappings (charge_id) WHERE charge_id <> '';

CREATE TABLE IF NOT EXISTS stripe_event_inbox (
    event_id TEXT PRIMARY KEY CHECK (event_id <> '' AND length(event_id) <= 255),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    stripe_event_type TEXT NOT NULL,
    normalized_type TEXT NOT NULL,
    provider_object_id TEXT NOT NULL CHECK (
        provider_object_id <> '' AND length(provider_object_id) <= 255
    ),
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
    claim_until TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    last_error_code TEXT NOT NULL DEFAULT '' CHECK (length(last_error_code) <= 64),
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    effect_key TEXT NOT NULL DEFAULT '',
    quarantined_at TIMESTAMPTZ,
    quarantine_code TEXT NOT NULL DEFAULT '',
    CHECK ((metadata_tenant_id = '') = (metadata_order_id = ''))
);

ALTER TABLE stripe_event_inbox ADD COLUMN IF NOT EXISTS effect_key TEXT NOT NULL DEFAULT '';
ALTER TABLE stripe_event_inbox ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMPTZ;
ALTER TABLE stripe_event_inbox ADD COLUMN IF NOT EXISTS quarantine_code TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS stripe_event_receipts (
    event_id TEXT PRIMARY KEY CHECK (event_id <> '' AND length(event_id) <= 255),
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    effect_key TEXT NOT NULL CHECK (effect_key <> ''),
    received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO stripe_event_receipts (event_id, payload_digest, effect_key, received_at)
SELECT event_id, payload_digest, normalized_type || ':' || provider_object_id, received_at
FROM stripe_event_inbox
ON CONFLICT (event_id) DO NOTHING;

UPDATE stripe_event_inbox
SET quarantined_at = COALESCE(quarantined_at, clock_timestamp()),
    quarantine_code = 'obsolete_payment_failed',
    effect_key = normalized_type || ':' || provider_object_id || ':obsolete:' || event_id
WHERE normalized_type = 'rejected' AND quarantined_at IS NULL;

UPDATE stripe_event_inbox
SET quarantined_at = COALESCE(quarantined_at, clock_timestamp()),
    quarantine_code = 'obsolete_dispute_created',
    effect_key = normalized_type || ':' || provider_object_id || ':obsolete:' || event_id
WHERE stripe_event_type = 'charge.dispute.created' AND quarantined_at IS NULL;

UPDATE stripe_event_inbox
SET quarantined_at = clock_timestamp(), quarantine_code = 'legacy_refund_status_unverified',
    effect_key = normalized_type || ':' || provider_object_id || ':legacy:' || event_id
WHERE stripe_event_type = 'refund.created' AND effect_key = '' AND quarantined_at IS NULL;

UPDATE stripe_event_inbox
SET effect_key = normalized_type || ':' || provider_object_id
WHERE effect_key = '';

WITH duplicate_effects AS (
    SELECT event_id, effect_key,
           row_number() OVER (
               PARTITION BY effect_key
               ORDER BY (delivered_at IS NOT NULL) DESC, received_at, event_id
           ) AS position
    FROM stripe_event_inbox
    WHERE normalized_type <> 'rejected' AND quarantined_at IS NULL
)
UPDATE stripe_event_inbox AS inbox
SET quarantined_at = COALESCE(inbox.quarantined_at, clock_timestamp()),
    quarantine_code = 'duplicate_effect_migration',
    effect_key = inbox.effect_key || ':duplicate:' || inbox.event_id
FROM duplicate_effects AS duplicate
WHERE inbox.event_id = duplicate.event_id AND duplicate.position > 1;

DROP INDEX IF EXISTS stripe_event_inbox_effect_unique;
CREATE UNIQUE INDEX stripe_event_inbox_effect_unique ON stripe_event_inbox (effect_key);

ALTER TABLE stripe_event_inbox DROP CONSTRAINT IF EXISTS stripe_event_inbox_stripe_event_type_check;
ALTER TABLE stripe_event_inbox ADD CONSTRAINT stripe_event_inbox_stripe_event_type_check CHECK (
    stripe_event_type IN (
        'payment_intent.succeeded', 'payment_intent.payment_failed',
        'refund.created', 'refund.updated', 'charge.dispute.created',
        'charge.dispute.funds_withdrawn', 'charge.dispute.funds_reinstated'
    )
);
ALTER TABLE stripe_event_inbox DROP CONSTRAINT IF EXISTS stripe_event_inbox_normalized_type_check;
ALTER TABLE stripe_event_inbox ADD CONSTRAINT stripe_event_inbox_normalized_type_check CHECK (
    normalized_type IN ('captured', 'rejected', 'refunded', 'chargeback', 'chargeback_reversed')
);
ALTER TABLE stripe_event_inbox DROP CONSTRAINT IF EXISTS stripe_event_inbox_check1;
ALTER TABLE stripe_event_inbox DROP CONSTRAINT IF EXISTS stripe_event_inbox_effect_amount_check;
ALTER TABLE stripe_event_inbox ADD CONSTRAINT stripe_event_inbox_effect_amount_check CHECK (
    (normalized_type = 'rejected' AND normalized_amount_minor = 0)
    OR (normalized_type <> 'rejected' AND normalized_amount_minor > 0)
);

DROP INDEX IF EXISTS stripe_event_inbox_claimable;
CREATE INDEX stripe_event_inbox_claimable
    ON stripe_event_inbox (available_at, occurred_at, event_id)
    WHERE delivered_at IS NULL AND quarantined_at IS NULL;

ALTER TABLE stripe_adapter_schema_version
    DROP CONSTRAINT IF EXISTS stripe_adapter_schema_version_version_check;
ALTER TABLE stripe_adapter_schema_version
    ADD CONSTRAINT stripe_adapter_schema_version_version_check CHECK (version BETWEEN 1 AND 2);
UPDATE stripe_adapter_schema_version
SET version = 2, applied_at = clock_timestamp()
WHERE singleton = TRUE;
