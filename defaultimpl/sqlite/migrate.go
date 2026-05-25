package sqlite

import (
	"context"
	"database/sql"

	"github.com/snaplink/sso/migrate"
)

// ensureSchema runs a store's baseline schema through the migration
// runner under its own namespace, recording schema version 1. Each
// store gets its own namespace because the §4 backend toggles let
// different stores live in different databases — a store's New must
// only create its own tables + version table.
//
// A store that later needs to evolve its schema replaces this call with
// an explicit migrate.Run carrying a v2+ Migration slice (see
// refresh_tokens.go's column history for the kind of change that
// motivates it).
func ensureSchema(db *sql.DB, namespace, schema string) error {
	return migrate.Run(context.Background(), db, namespace, []migrate.Migration{
		{Version: 1, Name: "baseline", SQL: schema},
	})
}
