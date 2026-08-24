// Package auditstore is the shared read-only audit-store accessor for the
// sso-ctl audit tools (audit-verify, audit-export). It owns the single
// DSN dialect classifier, the read-only opener over both durable backends
// (sqlite + postgres), and the paginate-and-reverse chain reader, so no
// tool carries its own copy (REQ-5 coordination: exactly one opener).
//
// The package lives at cmd/auditstore (a composition-layer sibling of the
// cmd/sso-ctl subcommands) rather than under cmd/sso-ctl/ because that
// directory is at its 16-subdirectory ceiling; composition → composition
// imports are same-layer.
//
// Read-only discipline: every opener is QUERY-ONLY and NEVER migrates.
// sqlite uses auditsqlite.OpenReadOnly (fail-closed checkSchemaCurrent);
// postgres uses postgres.OpenAuditReadOnly (fail-closed
// schema_migrations_audit version check). A schema whose version does not
// match the binary is reported, never migrated, never guessed. The tool
// itself never executes DDL or DML; postgres read-only enforcement is the
// operator's job (a read-only role or default_transaction_read_only).
package auditstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/audit"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// Dialect classifies an audit-store DSN.
type Dialect int

const (
	// DialectSQLite is a sqlite DSN (a file path or file: URI).
	DialectSQLite Dialect = iota
	// DialectPostgres is a postgres:// or postgresql:// connection string.
	DialectPostgres
)

// Classify reports the store dialect for dsn: postgres iff the string
// begins with "postgres://" or "postgresql://" (case-insensitive);
// everything else is a sqlite DSN (file path or file: URI). Rationale:
// postgres connection strings always carry a scheme in this repo
// (postgres.Open consumers, importcmd examples); sqlite DSNs never do —
// auto-detection avoids a second state flag and the classifier is total
// and unambiguous.
func Classify(dsn string) Dialect {
	lower := strings.ToLower(dsn)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return DialectPostgres
	}
	return DialectSQLite
}

// Store is the read-only slice of an audit store the sso-ctl audit tools
// share: a QueryPager plus Close. Both auditsqlite.OpenReadOnly and
// postgres.OpenAuditReadOnly satisfy it structurally.
type Store interface {
	Query(ctx context.Context, q audit.Query) ([]*audit.Event, error)
	Close() error
}

// OpenReadOnly opens dsn for QUERY-ONLY access and returns a Store,
// dispatching on Classify: sqlite via auditsqlite.OpenReadOnly (never
// migrates, fail-closed checkSchemaCurrent), postgres via
// postgres.OpenAuditReadOnly (never migrates, fail-closed
// schema_migrations_audit version check). Open errors and schema-version
// mismatches are exit-1 diagnostics naming the store; a broken chain is
// reported only by the verification step, never by the reader. Caller
// owns Close().
func OpenReadOnly(dsn string) (Store, error) {
	switch Classify(dsn) {
	case DialectPostgres:
		return postgres.OpenAuditReadOnly(postgres.Config{DSN: dsn})
	default:
		return auditsqlite.OpenReadOnly(dsn)
	}
}

// ReadChain pages st newest-first (both sinks and the audit API return
// newest-first) and returns the events in CHAIN ORDER (oldest first),
// mirroring the audit-verify --from-url discipline. truncated reports
// whether the --limit cap cut the chain short. --limit 0 never
// truncates; pageSize <= 0 falls back to 500 and values above
// audit.MaxQueryLimit are clamped.
//
// A --limit cap keeps the OLDEST `limit` events — the genesis-anchored
// prefix audit.VerifyChain accepts — matching the --from-file semantics
// (the newest-side truncation of the URL pager cannot verify unanchored:
// its first event's PrevHash is a mid-chain hash, not genesis). The
// prefix is honestly reported as truncated and never asserted to be the
// chain tip.
func ReadChain(ctx context.Context, st Store, limit, pageSize int) ([]*audit.Event, bool, error) {
	if pageSize <= 0 {
		pageSize = 500
	}
	if pageSize > audit.MaxQueryLimit {
		pageSize = audit.MaxQueryLimit
	}
	var collected []*audit.Event
	offset := 0
	for {
		page, err := st.Query(ctx, audit.Query{Limit: pageSize, Offset: offset})
		if err != nil {
			return nil, false, fmt.Errorf("auditstore: query (offset=%d): %w", offset, err)
		}
		collected = append(collected, page...)
		if len(page) < pageSize {
			break
		}
		offset += len(page)
	}
	truncated := false
	if limit > 0 && len(collected) > limit {
		truncated = true
		// Oldest `limit`: the tail of the newest-first stream.
		collected = collected[len(collected)-limit:]
	}
	// Store returns newest-first; flip for chain-order verification.
	reverseEvents(collected)
	return collected, truncated, nil
}

func reverseEvents(s []*audit.Event) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
