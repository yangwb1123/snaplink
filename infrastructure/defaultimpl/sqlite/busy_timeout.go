// SQLite runtime busy_timeout. modernc.org/sqlite does NOT honor the
// mattn-style `_busy_timeout` DSN query param (only `_pragma=busy_timeout(N)`),
// and busy_timeout is a PER-CONNECTION setting: a PRAGMA run once at migration
// time does not carry to the pool connections that serve runtime traffic. So
// without this, a deployment whose DSN omits the `_pragma` form runs every
// pool connection with busy_timeout=0 — a contended writer returns SQLITE_BUSY
// immediately instead of waiting, surfacing as spurious 5xx under load against
// a single WAL writer.
//
// Registering a connection hook on modernc's shared driver singleton applies
// the default to EVERY connection the driver opens, process-wide, across every
// store package (audit/sqlite, permissions/sqlite, ...), without threading a
// DSN change through ~17 store constructors. The cmd binary imports this
// package, so the init runs and the hook covers the whole process.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	sqlited "modernc.org/sqlite"
)

// defaultBusyTimeoutMS is the runtime busy_timeout applied to any connection
// whose DSN did not already specify one. 5s matches the production DSN
// examples in config.yaml; long enough to ride out a brief writer convoy on
// the single WAL writer, short enough that a genuinely stuck lock still fails
// the request rather than hanging it. Migrations use their own (longer) value.
const defaultBusyTimeoutMS = 5000

func init() {
	// Called after each connection is fully set up. Only the `_pragma=
	// busy_timeout(N)` DSN form is one modernc actually applies, so skip the
	// default solely for that form (operator config wins). The mattn-style
	// `_busy_timeout=N` is a modernc no-op — matching it here would leave the
	// operator silently at 0; instead the hook supplies a working value. The
	// `(` also avoids a false match on a db filename containing the word.
	sqlited.RegisterConnectionHook(func(conn sqlited.ExecQuerierContext, dsn string) error {
		if strings.Contains(dsn, "busy_timeout(") {
			return nil
		}
		_, err := conn.ExecContext(
			context.Background(),
			fmt.Sprintf("PRAGMA busy_timeout=%d", defaultBusyTimeoutMS),
			nil,
		)
		return err
	})
}

// beginImmediateRMW pins a connection from db's pool and issues a REAL
// BEGIN IMMEDIATE — the write lock is acquired up front, not lazily on the
// first write. db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
// does NOT achieve this under modernc.org/sqlite: the driver has no SQL
// isolation-level concept and silently starts a plain DEFERRED transaction
// regardless of the requested level, leaving a lost-update race window
// between a read-modify-write's SELECT and its later INSERT/UPDATE (see
// account_lockout.go's RegisterFailure and refresh_tokens_rotation.go's
// RecordRotation, both concurrent-safety-critical). busy_timeout is already
// applied process-wide by this file's connection hook, so callers don't need
// to re-issue the PRAGMA.
//
// Caller MUST issue "COMMIT" via the returned conn on success and defer both
// a "ROLLBACK" (a no-op once already committed) and conn.Close().
func beginImmediateRMW(ctx context.Context, db *sql.DB) (*sql.Conn, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
