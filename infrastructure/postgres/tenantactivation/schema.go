package tenantactivation

import "github.com/yangwb1123/snaplink/platform/migrate"

const schema = `
CREATE TABLE IF NOT EXISTS tenant_activation_codes (
    id TEXT PRIMARY KEY CHECK (id <> '' AND id = btrim(id)),
    product_id TEXT NOT NULL CHECK (product_id <> '' AND product_id = btrim(product_id)),
    tenant_id TEXT NOT NULL CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    key_digest TEXT NOT NULL DEFAULT '',
    invitation_digest TEXT NOT NULL DEFAULT '',
    entitlement JSONB,
    expires_at_ns BIGINT NOT NULL DEFAULT 0,
    max_claims INTEGER NOT NULL DEFAULT 1 CHECK (max_claims > 0),
    created_at_ns BIGINT NOT NULL,
    CHECK ((key_digest <> '') <> (invitation_digest <> ''))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_activation_key_digest
    ON tenant_activation_codes(key_digest) WHERE key_digest <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_activation_invitation_digest
    ON tenant_activation_codes(invitation_digest) WHERE invitation_digest <> '';
CREATE TABLE IF NOT EXISTS tenant_activation_tickets (
    ticket_digest TEXT PRIMARY KEY CHECK (ticket_digest <> ''),
    code_id TEXT NOT NULL REFERENCES tenant_activation_codes(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL CHECK (client_id <> ''),
    product_id TEXT NOT NULL CHECK (product_id <> ''),
    tenant_hint TEXT NOT NULL DEFAULT '',
    expires_at_ns BIGINT NOT NULL,
    created_at_ns BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenant_activation_ticket_expiry
    ON tenant_activation_tickets(expires_at_ns);
CREATE TABLE IF NOT EXISTS tenant_activation_claims (
    client_id TEXT NOT NULL CHECK (client_id <> ''),
    product_id TEXT NOT NULL CHECK (product_id <> ''),
    subject TEXT NOT NULL CHECK (subject <> ''),
    code_id TEXT NOT NULL REFERENCES tenant_activation_codes(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL CHECK (tenant_id <> ''),
    entitlement JSONB,
    claimed_at_ns BIGINT NOT NULL,
    PRIMARY KEY (client_id, product_id, subject)
);
CREATE INDEX IF NOT EXISTS idx_tenant_activation_claim_code
    ON tenant_activation_claims(code_id, subject);
`

var migrations = []migrate.Migration{
	{Version: 1, Name: "tenant activation baseline", SQL: schema},
}
