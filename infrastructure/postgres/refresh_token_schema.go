package postgres

import (
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// refreshTokenSchema is the Postgres-dialect baseline for the rotating
// refresh-token store. refresh_token_families is the OAuth Security BCP
// §4.13 reuse-detection ledger: every Issue mirrors the (token, family_id)
// pair here AND keeps it after Consume removed the active row, so a
// presented-after-rotation token is recognized as a replay and the family
// killed. refresh_rotation_windows backs the optional per-family velocity
// cap. One baseline migration carries the full column set (the SQLite v1-v8
// backfill ladder exists only for legacy SQLite databases); the
// (user_id, client_id) subject index is part of the baseline since the
// namespace is new.
const refreshTokenSchema = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token                  TEXT    PRIMARY KEY,
    user_id                TEXT    NOT NULL,
    client_id              TEXT    NOT NULL,
    provider               TEXT    NOT NULL DEFAULT '',
    scopes                 TEXT    NOT NULL DEFAULT '[]',
    attributes             TEXT    NOT NULL DEFAULT '{}',
    issued_at              BIGINT  NOT NULL,
    expires_at             BIGINT  NOT NULL,
    family_id              TEXT    NOT NULL DEFAULT '',
    jti                    TEXT    NOT NULL DEFAULT '',
    resources              TEXT    NOT NULL DEFAULT '[]',
    authorization_details  TEXT    NOT NULL DEFAULT '',
    sid                    TEXT    NOT NULL DEFAULT '',
    amr                    TEXT    NOT NULL DEFAULT '[]',
    acr                    TEXT    NOT NULL DEFAULT '',
    auth_time              BIGINT  NOT NULL DEFAULT 0,
    confirmation_jkt       TEXT    NOT NULL DEFAULT '',
    generation             BIGINT  NOT NULL DEFAULT 0,
    family_created_at      BIGINT  NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client
    ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_subject_client
    ON refresh_tokens(user_id, client_id);

CREATE TABLE IF NOT EXISTS refresh_token_families (
    token      TEXT PRIMARY KEY,
    family_id  TEXT    NOT NULL,
    expires_at BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_token_families_family
    ON refresh_token_families(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token_families_expires
    ON refresh_token_families(expires_at);

CREATE TABLE IF NOT EXISTS refresh_rotation_windows (
    family_id    TEXT    PRIMARY KEY,
    count        BIGINT  NOT NULL DEFAULT 0,
    window_start BIGINT  NOT NULL DEFAULT 0
);
`

var refreshTokenMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: refreshTokenSchema},
}

// RefreshTokensMaxVersion returns the highest migration version declared for
// the refresh_tokens namespace — the boot-gate input for the postgres branch.
func RefreshTokensMaxVersion() int { return migrate.MaxVersion(refreshTokenMigrations) }
