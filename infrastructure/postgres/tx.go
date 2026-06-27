package postgres

import (
	"context"
	"database/sql"
)

// runTx runs fn inside a fresh transaction and retries the WHOLE unit of work on
// a 40001 serialization failure. It is the runtime counterpart of migrate.go's
// withRetry: migrations were the only path wrapped before, leaving every runtime
// transaction exposed on a cluster.
//
// Pass opts with Isolation: sql.LevelSerializable for any read-modify-write. That
// is what makes a SELECT-then-write safe on BOTH cluster dialects:
//   - plain PostgreSQL defaults to READ COMMITTED, under which a SELECT (no FOR
//     UPDATE) followed by a write does NOT serialize against a concurrent writer
//     — both read the same snapshot and the last COMMIT silently drops the other
//     update. SERIALIZABLE (SSI) detects the read/write dependency and aborts one
//     side with SQLSTATE 40001, which this retry re-runs against the winner's
//     now-committed state.
//   - CockroachDB is always SERIALIZABLE and emits the same 40001 under
//     contention; without a retry it propagates to the caller as a 500.
//
// Each attempt opens a NEW transaction (a failed serializable txn is aborted), so
// fn MUST re-read inside the supplied tx and be a pure function of that re-read
// state — never carry a value computed in a prior attempt. The 40001 can surface
// from a statement OR be deferred to Commit (common on PG SSI); both are caught
// because the closure returns the Commit error. nil opts uses the default
// isolation and is correct for append-only work (no lost-update risk) that still
// needs the CockroachDB 40001 retry.
func runTx(ctx context.Context, db *sql.DB, opts *sql.TxOptions, fn func(*sql.Tx) error) error {
	return withRetry(func() error {
		tx, err := db.BeginTx(ctx, opts)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }() // no-op after a successful Commit
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	})
}

// serializable is the TxOptions every read-modify-write store path passes to
// runTx. Declared once so the intent reads the same at every call site.
var serializable = &sql.TxOptions{Isolation: sql.LevelSerializable}
