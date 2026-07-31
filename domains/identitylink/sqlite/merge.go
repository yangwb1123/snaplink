package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/identitylink"
)

// MergeUserLinks implements identitylink.AtomicMerger. The ownership
// predicate is rechecked in the same transaction that reassigns every active
// losing-account link, preventing stale decisions and partial merges.
func (s *Store) MergeUserLinks(ctx context.Context, conflict identitylink.Conflict) error {
	if err := identitylink.ValidateConflict(conflict); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("identitylink/sqlite: begin merge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	owner, err := activeOwner(ctx, tx, conflict.Provider, conflict.Subject)
	if errors.Is(err, sql.ErrNoRows) || owner != conflict.ExistingUserID {
		return identitylink.ErrAccountConflict
	}
	if err != nil {
		return fmt.Errorf("identitylink/sqlite: verify merge: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE identity_links SET user_id = ?
WHERE user_id = ? AND status = ?`,
		conflict.ExistingUserID, conflict.IncomingUserID, identitylink.StatusActive); err != nil {
		return fmt.Errorf("identitylink/sqlite: merge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("identitylink/sqlite: commit merge: %w", err)
	}
	return nil
}

func activeOwner(ctx context.Context, tx *sql.Tx, provider, subject string) (string, error) {
	var owner string
	err := tx.QueryRowContext(ctx, `
SELECT user_id FROM identity_links
WHERE provider = ? AND subject = ? AND status = ?`,
		provider, subject, identitylink.StatusActive).Scan(&owner)
	return owner, err
}
