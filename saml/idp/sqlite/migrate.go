// Package sqlite holds the pure-Go (modernc.org/sqlite) SHARED-backend peers
// for the cross-replica-relevant saml/idp stores — the IdP-side LogoutRequest-ID
// replay dedup and the SAML session index that drives the SLO fan-out. It
// mirrors the SDK's defaultimpl/sqlite pattern EXACTLY: each store routes
// New/NewWithDB through migrate.Run under its own namespace (v1 = the baseline
// schema), uses race-free SQLite atomics (INSERT ... ON CONFLICT for the replay
// dedup + the index upsert; DELETE for Remove/RemoveAll), and stores Unix-ns
// INTEGER timestamps.
//
// modernc.org/sqlite is pure-Go and ALREADY a (transitive) dependency of this
// module via the core sso module, so promoting it to a direct dependency of the
// saml submodule adds NO new external dependency and keeps the ROOT
// go.mod/go.sum byte-unchanged — it lives only in saml/go.mod.
//
// These peers are OPT-IN: an operator constructs them and passes them through
// the existing seams (idp.Deps.LogoutReplayStore / saml.Deps.SAMLSessionIndex).
// Unwired, the in-memory defaults are unchanged (byte-identical), so a
// single-replica IdP pays nothing for this package.
package sqlite

import (
	"context"
	"database/sql"

	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite" // register the pure-Go "sqlite" driver name (sql.Open).
)

// ensureSchema runs a store's baseline schema through the migration runner under
// its own namespace, recording schema version 1. Mirrors
// defaultimpl/sqlite.ensureSchema (package-private to the core module, so the
// submodule carries its own copy).
func ensureSchema(db *sql.DB, namespace, schema string) error {
	return migrate.Run(context.Background(), db, namespace, []migrate.Migration{
		{Version: 1, Name: "baseline", SQL: schema},
	})
}
