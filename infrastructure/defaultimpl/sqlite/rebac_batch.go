package sqlite

import (
	"context"

	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
)

// ApplyBatch validates every tuple before opening a transaction, then applies
// all writes and deletes under one commit. A rollback leaves the prior graph
// unchanged on any persistence error.
func (s *ReBACStore) ApplyBatch(ctx context.Context, writes, deletes []rebac.Tuple) error {
	for _, t := range append(append([]rebac.Tuple{}, writes...), deletes...) {
		if err := t.Validate(); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range writes {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO rebac_tuples (object, relation, subject) VALUES (?, ?, ?)`,
			t.Object, t.Relation, t.Subject); err != nil {
			return err
		}
	}
	for _, t := range deletes {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM rebac_tuples WHERE object = ? AND relation = ? AND subject = ?`,
			t.Object, t.Relation, t.Subject); err != nil {
			return err
		}
	}
	return tx.Commit()
}
