package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/yangwb1123/snaplink/platform/migrate"
)

// refreshTokenSchema mirrors the in-memory contract — same fields,
// JSON-encoded scope + attribute blobs, single table. Tokens live
// for days/weeks (30 day default) so the table can grow large for
// big fleets; the (expires_at) index is there for periodic
// background GC, not currently invoked by the store itself.
//
// refresh_token_families is the OAuth Security BCP §4.13 reuse-
// detection ledger: every Issue mirrors the (token, family_id) pair
// here AND keeps it after Consume removed the active row, so a
// presented-after-rotation token can be recognized as a replay and
// the entire family killed.
// refreshTokensTableDDL creates the table with the full current column
// set. Kept separate from the index DDL so the Func migration can run
// it BEFORE backfilling columns on a legacy DB — an index that
// references a not-yet-added column (family_id) can't be created first.
const refreshTokensTableDDL = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token                  TEXT    PRIMARY KEY,
    user_id                TEXT    NOT NULL,
    client_id              TEXT    NOT NULL,
    provider               TEXT    NOT NULL DEFAULT '',
    scopes                 TEXT    NOT NULL DEFAULT '[]',
    attributes             TEXT    NOT NULL DEFAULT '{}',
    issued_at              INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    family_id              TEXT    NOT NULL DEFAULT '',
    jti                    TEXT    NOT NULL DEFAULT '',
    resources              TEXT    NOT NULL DEFAULT '[]',
    authorization_details  TEXT    NOT NULL DEFAULT '',
    sid                    TEXT    NOT NULL DEFAULT '',
    amr                    TEXT    NOT NULL DEFAULT '[]',
    acr                    TEXT    NOT NULL DEFAULT '',
    auth_time              INTEGER NOT NULL DEFAULT 0,
    confirmation_jkt       TEXT    NOT NULL DEFAULT '',
    generation             INTEGER NOT NULL DEFAULT 0,
    family_created_at      INTEGER NOT NULL DEFAULT 0
);`

// refreshTokensIndexDDL creates indexes + the family ledger. Runs AFTER
// the column backfill so idx_refresh_tokens_family(family_id) is valid
// even on a database upgraded from the pre-family-tracker schema.
const refreshTokensIndexDDL = `
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client
    ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS refresh_token_families (
    token      TEXT PRIMARY KEY,
    family_id  TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_token_families_family
    ON refresh_token_families(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token_families_expires
    ON refresh_token_families(expires_at);
`

// refreshTokenMigrations is the schema history. v1 is a Func migration
// rather than plain SQL because legacy databases predate the
// family_id / resources / authorization_details / sid columns and
// SQLite has no ADD COLUMN IF NOT EXISTS: the func creates the table
// then adds each column only when it's missing. Fresh databases get the
// full table from the CREATE and skip every add; pre-family-tracker
// databases get the missing columns backfilled — the same outcome the
// old error-tolerant ALTER dance produced, now version-tracked + atomic.
var refreshTokenMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline_refresh_tokens", Func: ensureRefreshTokenSchema},
	{
		Version: 2,
		SQL: `CREATE TABLE IF NOT EXISTS refresh_rotation_windows (
    family_id    TEXT    PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL DEFAULT 0
);`,
	},
	// v3 backfills the RFC 9068 authentication-context columns onto databases
	// that already ran v1 (which can't be re-triggered). A Func — not plain SQL
	// — so the adds stay idempotent (SQLite has no ADD COLUMN IF NOT EXISTS);
	// fresh DBs whose baseline DDL already carries the columns skip every add.
	{Version: 3, Name: "refresh_token_auth_context", Func: addRefreshTokenAuthContext},
	// v4 backfills the RFC 9449 DPoP key-binding column. Fresh DBs get it from
	// the baseline DDL; pre-v4 DBs get it here. Existing rows default to ''
	// (unbound), preserving the pre-feature behavior exactly.
	{Version: 4, Name: "refresh_token_dpop_binding", Func: addRefreshTokenDPoPBinding},
	// v5 backfills the rotation-generation column (token-policy max_refresh_depth
	// input). Fresh DBs get it from the baseline DDL; pre-v5 DBs get it here.
	// Existing rows default to 0 — a pre-feature token reads generation 0, so an
	// un-capped fleet is byte-identical to before the feature.
	{Version: 5, Name: "refresh_token_generation", Func: addRefreshTokenGeneration},
	// v6 backfills family_created_at (the absolute-max-lifetime cap's input —
	// see oauthspi.RefreshToken.FamilyCreatedAt). Fresh DBs get it from the
	// baseline DDL; pre-v6 DBs get it here. Existing rows default to 0 (the
	// same "unset" sentinel auth_time uses), which SKIPS the cap check for
	// those families rather than fabricating a start time — an additive
	// migration that never retroactively kills a pre-existing family.
	{Version: 6, Name: "refresh_token_family_created_at", Func: addRefreshTokenFamilyCreatedAt},
	// v7 bounds the consumed-token reuse ledger. Legacy consumed rows cannot
	// recover their original expiry, so retain them for 30 days from migration
	// (security-safe widening); active rows inherit their exact expiry.
	{Version: 7, Name: "refresh_token_family_expiry", Func: addRefreshTokenFamilyExpiry},
	// v8 backfills the jti column (the refresh-introspect thumbprint
	// correlation id — see oauthspi.RefreshToken.JTI). Fresh DBs get it from
	// the baseline DDL; pre-v8 DBs get it here. Existing rows default to '' —
	// a pre-feature token reads JTI "", so its introspection Offer stays
	// thumbprint-less (Thumbprint("") => no observation) and the per-token
	// geo table sees byte-identical behavior to before the feature.
	{Version: 8, Name: "refresh_token_jti", Func: addRefreshTokenJTI},
}

func addRefreshTokenFamilyExpiry(ctx context.Context, x migrate.Execer) error {
	has, err := refreshTokenFamilyColumnExists(ctx, x, "expires_at")
	if err != nil {
		return err
	}
	if !has {
		if _, err := x.ExecContext(ctx,
			`ALTER TABLE refresh_token_families ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if _, err := x.ExecContext(ctx, `
        UPDATE refresh_token_families
           SET expires_at = COALESCE(
               (SELECT expires_at FROM refresh_tokens
                 WHERE refresh_tokens.token = refresh_token_families.token),
               (CAST(strftime('%s','now') AS INTEGER) + 2592000) * 1000000000
           )
         WHERE expires_at = 0`); err != nil {
		return err
	}
	_, err = x.ExecContext(ctx, `
        CREATE INDEX IF NOT EXISTS idx_refresh_token_families_expires
            ON refresh_token_families(expires_at)`)
	return err
}

// addRefreshTokenAuthContext adds amr/acr/auth_time (preserve original
// authentication event across rotation — RFC 9068 §2.2) to a pre-existing
// refresh_tokens table, each only when missing.
func addRefreshTokenAuthContext(ctx context.Context, x migrate.Execer) error {
	addColumns := []struct{ name, ddl string }{
		{"amr", `ALTER TABLE refresh_tokens ADD COLUMN amr TEXT NOT NULL DEFAULT '[]'`},
		{"acr", `ALTER TABLE refresh_tokens ADD COLUMN acr TEXT NOT NULL DEFAULT ''`},
		{"auth_time", `ALTER TABLE refresh_tokens ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0`},
	}
	for _, c := range addColumns {
		has, err := refreshTokenColumnExists(ctx, x, c.name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := x.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("add column %s: %w", c.name, err)
		}
	}
	return nil
}

func ensureRefreshTokenSchema(ctx context.Context, x migrate.Execer) error {
	// 1. Table first (fresh DBs get all columns; legacy DBs no-op here).
	if _, err := x.ExecContext(ctx, refreshTokensTableDDL); err != nil {
		return err
	}
	// 2. Backfill columns a pre-family-tracker DB is missing.
	addColumns := []struct{ name, ddl string }{
		{"family_id", `ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT ''`},
		{"resources", `ALTER TABLE refresh_tokens ADD COLUMN resources TEXT NOT NULL DEFAULT '[]'`},
		{"authorization_details", `ALTER TABLE refresh_tokens ADD COLUMN authorization_details TEXT NOT NULL DEFAULT ''`},
		{"sid", `ALTER TABLE refresh_tokens ADD COLUMN sid TEXT NOT NULL DEFAULT ''`},
	}
	for _, c := range addColumns {
		has, err := refreshTokenColumnExists(ctx, x, c.name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := x.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("add column %s: %w", c.name, err)
		}
	}
	// 3. Indexes + family ledger last — idx_refresh_tokens_family needs
	// family_id to exist, which step 2 guarantees.
	if _, err := x.ExecContext(ctx, refreshTokensIndexDDL); err != nil {
		return err
	}
	return nil
}

// addRefreshTokenGeneration adds the generation column (token-policy
// max_refresh_depth rotation counter) to a pre-existing refresh_tokens table.
// Idempotent via the column-exists check; existing rows default to 0 so a
// token issued before the feature reads generation 0.
func addRefreshTokenGeneration(ctx context.Context, x migrate.Execer) error {
	has, err := refreshTokenColumnExists(ctx, x, "generation")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = x.ExecContext(ctx,
		`ALTER TABLE refresh_tokens ADD COLUMN generation INTEGER NOT NULL DEFAULT 0`)
	return err
}

// addRefreshTokenDPoPBinding adds confirmation_jkt (RFC 9449 DPoP key binding)
// to a pre-existing refresh_tokens table. Idempotent via the column-exists check.
func addRefreshTokenDPoPBinding(ctx context.Context, x migrate.Execer) error {
	has, err := refreshTokenColumnExists(ctx, x, "confirmation_jkt")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = x.ExecContext(ctx,
		`ALTER TABLE refresh_tokens ADD COLUMN confirmation_jkt TEXT NOT NULL DEFAULT ''`)
	return err
}

// addRefreshTokenFamilyCreatedAt adds family_created_at (the absolute-max-
// lifetime cap's input) to a pre-existing refresh_tokens table. Idempotent
// via the column-exists check; existing rows default to 0 (unset — cap
// check skipped, same discipline as auth_time's 0 sentinel).
func addRefreshTokenFamilyCreatedAt(ctx context.Context, x migrate.Execer) error {
	has, err := refreshTokenColumnExists(ctx, x, "family_created_at")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = x.ExecContext(ctx,
		`ALTER TABLE refresh_tokens ADD COLUMN family_created_at INTEGER NOT NULL DEFAULT 0`)
	return err
}

// addRefreshTokenJTI adds the jti column (refresh-introspect thumbprint
// correlation id) to a pre-existing refresh_tokens table. Idempotent via the
// column-exists check; existing rows default to ” so a token issued before
// the feature reads JTI "" (thumbprint-less, pre-feature behavior).
func addRefreshTokenJTI(ctx context.Context, x migrate.Execer) error {
	has, err := refreshTokenColumnExists(ctx, x, "jti")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = x.ExecContext(ctx,
		`ALTER TABLE refresh_tokens ADD COLUMN jti TEXT NOT NULL DEFAULT ''`)
	return err
}

// refreshTokenColumnExists reports whether refresh_tokens already has the
// named column, via PRAGMA table_info (the table name is a constant, not
// user input).
func refreshTokenColumnExists(ctx context.Context, x migrate.Execer, column string) (bool, error) {
	return sqliteColumnExists(ctx, x, `PRAGMA table_info(refresh_tokens)`, column)
}

func refreshTokenFamilyColumnExists(ctx context.Context, x migrate.Execer, column string) (bool, error) {
	return sqliteColumnExists(ctx, x, `PRAGMA table_info(refresh_token_families)`, column)
}

func sqliteColumnExists(ctx context.Context, x migrate.Execer, query, column string) (bool, error) {
	rows, err := x.QueryContext(ctx, query)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notnull, pk int
			dflt        sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
