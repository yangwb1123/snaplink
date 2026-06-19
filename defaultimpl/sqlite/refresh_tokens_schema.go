package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/snaplink/sso/migrate"
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
    resources              TEXT    NOT NULL DEFAULT '[]',
    authorization_details  TEXT    NOT NULL DEFAULT '',
    sid                    TEXT    NOT NULL DEFAULT ''
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
    token     TEXT PRIMARY KEY,
    family_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_token_families_family
    ON refresh_token_families(family_id);
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

// refreshTokenColumnExists reports whether refresh_tokens already has the
// named column, via PRAGMA table_info (the table name is a constant, not
// user input).
func refreshTokenColumnExists(ctx context.Context, x migrate.Execer, column string) (bool, error) {
	rows, err := x.QueryContext(ctx, `PRAGMA table_info(refresh_tokens)`)
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
