package postgres

import (
	"context"
	"fmt"

	"github.com/yangwb1123/snaplink/platform/migrate"
)

// auditMigrationNamespace is the schema-migration namespace the audit
// store uses (the same "audit" namespace NewAuditSinkWithDB migrates).
const auditMigrationNamespace = "audit"

// OpenAuditReadOnly opens cfg.DSN for QUERY-ONLY audit access and returns
// the sink WITHOUT running migrations. Unlike NewAuditSink /
// NewAuditSinkWithDB it never invokes Run (no advisory lock, no DDL, no
// version-table writes), so a read-only database role works and a live
// production audit store is never schema-mutated by an offline export or
// verification tool. It is the constructor an offline tool MUST use
// against a production audit database.
//
// The schema is verified, not migrated: before any paging, the recorded
// schema_migrations_audit version must equal this binary's expected audit
// migration version. A mismatch fails closed with a found-vs-expected
// diagnostic naming the store (mirroring the sqlite peer's
// checkSchemaCurrent); the tool NEVER migrates — rollback here is
// restore-from-snapshot, not a schema op. Operators additionally enforce
// server-side read-only via a read-only role or
// default_transaction_read_only: there is no ?mode=ro equivalent for
// postgres (documented in the sso-ctl usage banners).
//
// The returned *AuditSink's Query/Get paths are SELECT-only
// (audit_query.go). Caller owns Close().
func OpenAuditReadOnly(cfg Config) (*AuditSink, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	// CurrentVersion is THIS package's postgres reader (SELECT-only; the
	// platform/migrate peer is sqlite-specific and must never run here).
	live, err := CurrentVersion(ctx, db, auditMigrationNamespace)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: audit schema version: %w", err)
	}
	want := migrate.MaxVersion(auditMigrations)
	if live != want {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: audit schema version mismatch: database at v%d, binary expects v%d (use a matching binary version; the read-only opener never migrates)", live, want)
	}
	return &AuditSink{db: db, dialect: cfg.Dialect.normalized()}, nil
}
