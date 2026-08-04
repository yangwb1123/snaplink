package usageledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
)

const sourceBindingColumns = `id, client_id, tenant_id, source_system,
allowed_dimensions, enabled, revision, created_at_ns, updated_at_ns`

func (s *Store) SaveSourceBinding(
	ctx context.Context, binding *ledger.SourceBinding, expectedRevision uint64,
) (*ledger.SourceBinding, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	var stored *ledger.SourceBinding
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		stored, err = saveSourceBindingTx(ctx, tx, binding, expectedRevision)
		return err
	})
	return stored, err
}

func saveSourceBindingTx(
	ctx context.Context, tx *sql.Tx, binding *ledger.SourceBinding, expectedRevision uint64,
) (*ledger.SourceBinding, error) {
	if expectedRevision == 0 {
		if binding.Revision != 1 {
			return nil, ledger.ErrSourceBindingConflict
		}
		return insertSourceBindingTx(ctx, tx, binding)
	}
	if binding.Revision != expectedRevision+1 {
		return nil, ledger.ErrSourceBindingConflict
	}
	return updateSourceBindingTx(ctx, tx, binding, expectedRevision)
}

func insertSourceBindingTx(
	ctx context.Context, tx *sql.Tx, binding *ledger.SourceBinding,
) (*ledger.SourceBinding, error) {
	dimensions, err := encodeJSON(binding.AllowedDimensions)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO usage_source_bindings (`+sourceBindingColumns+`)
VALUES ($1,$2,$3,$4,CAST($5 AS JSONB),$6,$7,$8,$9)`, binding.ID, binding.ClientID,
		binding.TenantID, binding.SourceSystem, dimensions, binding.Enabled, binding.Revision,
		timeNano(binding.CreatedAt), timeNano(binding.UpdatedAt))
	if err != nil {
		return nil, sourceBindingWriteError(err)
	}
	return cloneSourceBinding(binding), nil
}

func updateSourceBindingTx(
	ctx context.Context, tx *sql.Tx, binding *ledger.SourceBinding, expectedRevision uint64,
) (*ledger.SourceBinding, error) {
	dimensions, err := encodeJSON(binding.AllowedDimensions)
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE usage_source_bindings SET
allowed_dimensions=CAST($2 AS JSONB), enabled=$3, revision=$4, updated_at_ns=$5
WHERE id=$1 AND client_id=$6 AND tenant_id=$7 AND source_system=$8
AND revision=$9 AND created_at_ns=$10`, binding.ID, dimensions, binding.Enabled,
		binding.Revision, timeNano(binding.UpdatedAt), binding.ClientID, binding.TenantID,
		binding.SourceSystem, expectedRevision, timeNano(binding.CreatedAt))
	if err != nil {
		return nil, sourceBindingWriteError(err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if updated != 1 {
		return nil, ledger.ErrSourceBindingConflict
	}
	return cloneSourceBinding(binding), nil
}

func sourceBindingWriteError(err error) error {
	if uniqueViolation(err) {
		return ledger.ErrSourceBindingConflict
	}
	return fmt.Errorf("usageledger/postgres: write source binding: %w", err)
}

func (s *Store) ListSourceBindingsByClient(
	ctx context.Context, clientID string,
) ([]*ledger.SourceBinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sourceBindingColumns+`
FROM usage_source_bindings WHERE client_id=$1 ORDER BY id`, clientID)
	if err != nil {
		return nil, fmt.Errorf("usageledger/postgres: list source bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*ledger.SourceBinding, 0)
	for rows.Next() {
		binding, scanErr := scanSourceBinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, binding)
	}
	return result, rows.Err()
}

func scanSourceBinding(scanner rowScanner) (*ledger.SourceBinding, error) {
	binding := &ledger.SourceBinding{}
	var dimensions []byte
	var created, updated int64
	err := scanner.Scan(
		&binding.ID, &binding.ClientID, &binding.TenantID, &binding.SourceSystem,
		&dimensions, &binding.Enabled, &binding.Revision, &created, &updated,
	)
	if err != nil {
		return nil, fmt.Errorf("usageledger/postgres: scan source binding: %w", err)
	}
	if err := decodeJSON(dimensions, &binding.AllowedDimensions); err != nil {
		return nil, err
	}
	binding.CreatedAt, binding.UpdatedAt = nanoTime(created), nanoTime(updated)
	return binding, nil
}

// verifySourceBindingTx pins the active authorization row through commit.
// UPDATE/disable waits for this transaction, while stale evidence observed
// after a completed change fails closed before any usage state is mutated.
func verifySourceBindingTx(
	ctx context.Context, tx *sql.Tx, evidence *ledger.SourceBindingEvidence,
	tenantID, sourceSystem string, dimension ledger.Dimension,
) error {
	if evidence == nil {
		return nil
	}
	if evidence.Validate() != nil {
		return ledger.ErrSourceBindingUnauthorized
	}
	binding, err := scanSourceBinding(tx.QueryRowContext(ctx,
		`SELECT `+sourceBindingColumns+` FROM usage_source_bindings WHERE id=$1 FOR SHARE`,
		evidence.BindingID,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ledger.ErrSourceBindingUnauthorized
		}
		return fmt.Errorf("usageledger/postgres: verify source binding: %w", err)
	}
	if evidence.TenantID != tenantID || evidence.SourceSystem != sourceSystem ||
		!binding.Enabled || binding.ClientID != evidence.ClientID || binding.TenantID != evidence.TenantID ||
		binding.SourceSystem != evidence.SourceSystem || binding.Revision != evidence.Revision ||
		!binding.Allows(dimension) {
		return ledger.ErrSourceBindingUnauthorized
	}
	return nil
}

func cloneSourceBinding(binding *ledger.SourceBinding) *ledger.SourceBinding {
	if binding == nil {
		return nil
	}
	copy := *binding
	copy.AllowedDimensions = append([]ledger.Dimension(nil), binding.AllowedDimensions...)
	return &copy
}

var _ ledger.SourceBindingStore = (*Store)(nil)
