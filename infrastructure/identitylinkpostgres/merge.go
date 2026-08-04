package identitylinkpostgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/identitylink"
)

// MergeUserLinks implements identitylink.AtomicMerger.
func (s *Store) MergeUserLinks(ctx context.Context, conflict identitylink.Conflict) error {
	if err := identitylink.ValidateConflict(conflict); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("identitylink/postgres: begin merge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	owner, err := activeOwner(ctx, tx, conflict.Provider, conflict.Subject)
	if errors.Is(err, sql.ErrNoRows) || owner != conflict.ExistingUserID {
		return identitylink.ErrAccountConflict
	}
	if err != nil {
		return fmt.Errorf("identitylink/postgres: verify merge: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE identity_links SET user_id = $1
WHERE user_id = $2 AND status = $3`,
		conflict.ExistingUserID, conflict.IncomingUserID, identitylink.StatusActive); err != nil {
		return fmt.Errorf("identitylink/postgres: merge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("identitylink/postgres: commit merge: %w", err)
	}
	return nil
}

func activeOwner(ctx context.Context, tx *sql.Tx, provider, subject string) (string, error) {
	var owner string
	err := tx.QueryRowContext(ctx, `
SELECT user_id FROM identity_links
WHERE provider = $1 AND subject = $2 AND status = $3
FOR UPDATE`, provider, subject, identitylink.StatusActive).Scan(&owner)
	return owner, err
}
