package sqlite

import "github.com/yangwb1123/snaplink/platform/migrate"

// clientMigrations is the versioned schema history for the clients store.
// v1: baseline schema (the original 10-column table).
// v2: ADD COLUMN for security-load-bearing fields: JWKS, AllowedResources,
//
//	AllowedRequestURIs, RegistrationAccessToken, JWE alg/enc,
//	Federation, PostLogoutRedirectURIs, FrontchannelLogoutURI,
//	RequireSignedRequestObject, RequirePAR, AllowedAuthorizationDetailsTypes,
//	BackchannelLogoutURI, SubjectType, SectorIdentifierURI, TTL overrides,
//	Attributes, AllowedPKCEMethods, UserinfoSignedResponseAlg, CAEP attrs.
//
// All new columns default to empty/0 so existing rows are backward-compatible.
var clientMigrations = []migrate.Migration{
	{
		Version: 1,
		SQL: `
CREATE TABLE IF NOT EXISTS clients (
    id                      TEXT    PRIMARY KEY,
    secret                  TEXT    NOT NULL,
    name                    TEXT    NOT NULL DEFAULT '',
    redirect_uris           TEXT    NOT NULL DEFAULT '[]',
    allowed_scopes          TEXT    NOT NULL DEFAULT '[]',
    allowed_authenticators  TEXT    NOT NULL DEFAULT '[]',
    token_strategy          TEXT    NOT NULL DEFAULT '',
    active                  INTEGER NOT NULL DEFAULT 1,
    tenant_id               TEXT    NOT NULL DEFAULT '',
    require_pkce            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_clients_tenant
    ON clients(tenant_id)
    WHERE tenant_id <> '';`,
	},
	{
		Version: 2,
		SQL: `
ALTER TABLE clients ADD COLUMN jwks                            TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_resources               TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_request_uris            TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN registration_access_token       TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris       TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN allowed_authorization_details   TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN refresh_token_ttl               INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN access_token_ttl                INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN allowed_pkce_methods            TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE clients ADD COLUMN require_signed_request_object   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN require_par                     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN device_code_ttl                 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN device_code_poll_interval       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN userinfo_signed_response_alg    TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN idtoken_encrypted_response_alg  TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN idtoken_encrypted_response_enc  TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_alg TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_enc TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_uri          TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN subject_type                    TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN sector_identifier_uri           TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN frontchannel_logout_uri         TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN federation                      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN attributes                      TEXT    NOT NULL DEFAULT '{}';`,
	},
	{
		// v3 tracks scheduled rotation. Zero keeps legacy rows out of sweeps.
		Version: 3,
		SQL:     `ALTER TABLE clients ADD COLUMN secret_rotated_at INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		// v4: client_trust_score / client_trust_set_at back the rule-based
		// client trust scorer (platform/lifecycle/clienttrust). Default 0
		// on existing rows means every pre-migration client reads as
		// "never scored" (client_trust_set_at == 0), never as an actively
		// distrusted score of 0.0 — see core.Client.ClientTrustSetAt.
		Version: 4,
		SQL: `
ALTER TABLE clients ADD COLUMN client_trust_score   REAL    NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN client_trust_set_at  INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		Version: 5,
		SQL: `
ALTER TABLE clients ADD COLUMN previous_secret      TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN secret_overlap_until INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		Version: 6,
		SQL:     `ALTER TABLE clients ADD COLUMN secret_expires_at INTEGER NOT NULL DEFAULT 0;`,
	},
}
