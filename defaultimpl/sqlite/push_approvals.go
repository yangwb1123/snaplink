package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/defaultimpl"
)

// pushApprovalsSchema persists push MFA approvals across the
// Begin → callback → Verify lifecycle. Same single-replica-only
// fallback the in-memory peer suffers from; this peer makes
// cluster deploys workable — Begin on replica A is resolvable by
// the callback hitting replica B.
//
// Status transitions are enforced in SetStatus via UPDATE ...
// WHERE status = 'pending' (only pending entries can change),
// matching the in-memory store's "refuse re-resolution" behavior.
const pushApprovalsSchema = `
CREATE TABLE IF NOT EXISTS push_approvals (
    id          TEXT    PRIMARY KEY,
    subject_id  TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_push_approvals_expires_at
    ON push_approvals(expires_at);
CREATE INDEX IF NOT EXISTS idx_push_approvals_subject
    ON push_approvals(subject_id);
`

// PushApprovalStore is the SQLite-backed
// [defaultimpl.PushApprovalStore]. Suitable for multi-replica
// deployments — every replica reads + writes the same approval
// table so a callback handled on one replica is visible to the
// Verify polling on another.
type PushApprovalStore struct {
	db *sql.DB
}

// NewPushApprovalStore opens dsn, migrates the schema, returns the
// store. Caller owns Close().
func NewPushApprovalStore(dsn string) (*PushApprovalStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), pushApprovalsSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate push_approvals: %w", err)
	}
	return &PushApprovalStore{db: db}, nil
}

// NewPushApprovalStoreWithDB wraps an existing *sql.DB. Caller owns
// the connection lifecycle.
func NewPushApprovalStoreWithDB(db *sql.DB) (*PushApprovalStore, error) {
	if _, err := db.ExecContext(context.Background(), pushApprovalsSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate push_approvals: %w", err)
	}
	return &PushApprovalStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *PushApprovalStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *PushApprovalStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: push approval store closed")
	}
	return s.db.PingContext(ctx)
}

// Put persists a freshly-issued approval. Caller MUST set ID +
// SubjectID; either empty → ErrPushApprovalInvalid. Duplicate ID
// rejected via PRIMARY KEY violation (anti-displacement: an
// attacker who guessed an in-flight id can't overwrite it).
func (s *PushApprovalStore) Put(ctx context.Context, a *defaultimpl.PushApproval) error {
	if a == nil || a.ID == "" || a.SubjectID == "" {
		return defaultimpl.ErrPushApprovalInvalid
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO push_approvals (id, subject_id, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)`,
		a.ID, a.SubjectID, string(a.Status),
		a.CreatedAt.UnixNano(), a.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert push_approval: %w", err)
	}
	return nil
}

// Get returns the approval. Missing / expired entries collapse to
// ErrPushApprovalNotFound (anti-enumeration parity with the
// in-memory peer + with MFAChallengeStore).
func (s *PushApprovalStore) Get(ctx context.Context, id string) (*defaultimpl.PushApproval, error) {
	if id == "" {
		return nil, defaultimpl.ErrPushApprovalNotFound
	}
	row := s.db.QueryRowContext(ctx, `
        SELECT subject_id, status, created_at, expires_at
        FROM push_approvals WHERE id = ?`, id)
	var (
		subjectID string
		statusStr string
		createdNs int64
		expiresNs int64
	)
	if err := row.Scan(&subjectID, &statusStr, &createdNs, &expiresNs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, defaultimpl.ErrPushApprovalNotFound
		}
		return nil, fmt.Errorf("sqlite: get push_approval: %w", err)
	}
	expiresAt := time.Unix(0, expiresNs).UTC()
	if time.Now().After(expiresAt) {
		// Lazy expiry: delete the stale row so Get callers don't
		// repeatedly hit it. Errors here are swallowed — the
		// caller's wire response is unchanged either way.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM push_approvals WHERE id = ?`, id)
		return nil, defaultimpl.ErrPushApprovalNotFound
	}
	return &defaultimpl.PushApproval{
		ID:        id,
		SubjectID: subjectID,
		Status:    defaultimpl.PushApprovalStatus(statusStr),
		CreatedAt: time.Unix(0, createdNs).UTC(),
		ExpiresAt: expiresAt,
	}, nil
}

// SetStatus advances an entry from Pending to a terminal state.
// Uses UPDATE ... WHERE status = 'pending' to atomically guard
// against re-resolution — operators investigating the audit see a
// clean "approve then deny" attempt as ErrPushApprovalResolved
// (vs the silent overwrite a plain UPDATE would produce). Missing
// entries surface as ErrPushApprovalNotFound. Same-status no-op
// short-circuits before the DB hit.
func (s *PushApprovalStore) SetStatus(ctx context.Context, id string, status defaultimpl.PushApprovalStatus) error {
	if id == "" {
		return defaultimpl.ErrPushApprovalNotFound
	}
	// Same-status idempotency without an UPDATE round-trip:
	// callback retries shouldn't burn cycles for a no-op.
	current, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if current.Status == status {
		return nil
	}
	if current.Status != defaultimpl.PushApprovalPending {
		return defaultimpl.ErrPushApprovalResolved
	}
	res, err := s.db.ExecContext(ctx, `
        UPDATE push_approvals SET status = ?
        WHERE id = ? AND status = 'pending'`,
		string(status), id,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update push_approval: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: update push_approval rowsaffected: %w", err)
	}
	if n == 0 {
		// Race: the row was resolved between our Get and our UPDATE.
		// Surface as resolved-already (the safer interpretation —
		// operator sees the legitimate-callback / attacker-callback
		// collision in audit).
		return defaultimpl.ErrPushApprovalResolved
	}
	return nil
}

// Delete drops the entry. Idempotent — missing id → nil so cron
// cleanup loops don't surface error noise on already-pruned ids.
func (s *PushApprovalStore) Delete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM push_approvals WHERE id = ?`, id); err != nil {
		return fmt.Errorf("sqlite: delete push_approval: %w", err)
	}
	return nil
}

// PruneExpired deletes every entry whose expires_at has passed.
// Returns the row count. Operators wire from cron to keep the
// table bounded — Get's lazy expiry only deletes entries on
// access, so an issued-but-never-polled approval sticks around
// until pruned.
func (s *PushApprovalStore) PruneExpired(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("sqlite: push approval store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM push_approvals WHERE expires_at < ?`, time.Now().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sqlite: prune expired push_approvals: %w", err)
	}
	return res.RowsAffected()
}

var _ defaultimpl.PushApprovalStore = (*PushApprovalStore)(nil)
