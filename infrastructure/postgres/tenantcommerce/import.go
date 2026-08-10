package tenantcommerce

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/shared/core"
)

// ImportUserTx is the postgres pair-write the import CLI calls: one atomic
// transaction commits the user upsert AND its governance outbox event
// (tenant_commerce_outbox), so a crash or failure can never leave an orphan
// on either side. It lives here, not on *postgres.UserProvider, because this
// package already imports infrastructure/postgres (cycle constraint: the
// provider cannot import back up to tenantcommerce).
//
// Idempotency: the existing insertOutboxEventTx shape — bare ON CONFLICT DO
// NOTHING, then ensureOutboxFactTx fact-equality. A same-fact re-import is a
// no-op (RowsAffected 0 + matching fact); a changed-fact collision (payload
// spec change across CLI versions) surfaces commerce.ErrIdempotencyConflict
// and the deferred rollback undoes the user upsert too.
func ImportUserTx(ctx context.Context, db *sql.DB, u *core.User, event *commerce.OutboxEvent) error {
	if db == nil {
		return fmt.Errorf("tenantcommerce/postgres: database is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: begin import tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := postgresbackend.UpsertUserTx(ctx, tx, u); err != nil {
		return err
	}
	if err := insertOutboxEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("tenantcommerce/postgres: commit import tx: %w", err)
	}
	return nil
}
