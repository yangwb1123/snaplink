package userlifecyclepostgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

// Get returns one consistent state-and-history snapshot. Missing users retain
// the domain's implicit-active behavior.
func (s *Store) Get(ctx context.Context, userID string) (userlifecycle.Record, error) {
	rec := userlifecycle.Record{UserID: userID, State: userlifecycle.DefaultState}
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		return loadRecord(ctx, tx, userID, &rec)
	})
	if err != nil {
		return userlifecycle.Record{}, fmt.Errorf("userlifecycle/postgres: get: %w", err)
	}
	return rec, nil
}

// GetState projects only the current state for credential hot paths, avoiding
// the append-only history query used by the admin record view.
func (s *Store) GetState(ctx context.Context, userID string) (userlifecycle.State, error) {
	var state string
	err := s.db.QueryRowContext(ctx, `
SELECT state FROM user_lifecycle_records WHERE user_id = $1`, userID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return userlifecycle.DefaultState, nil
	}
	if err != nil {
		return userlifecycle.StateNone, fmt.Errorf("userlifecycle/postgres: get state: %w", err)
	}
	return userlifecycle.State(state), nil
}

func loadRecord(ctx context.Context, tx *sql.Tx, userID string, rec *userlifecycle.Record) error {
	var state string
	var updatedAt int64
	err := tx.QueryRowContext(ctx, `
SELECT state, updated_at_ns FROM user_lifecycle_records WHERE user_id = $1`, userID).
		Scan(&state, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rec.State = userlifecycle.State(state)
	rec.UpdatedAt = unixNanoTime(updatedAt)
	history, err := loadHistory(ctx, tx, userID)
	if err != nil {
		return err
	}
	rec.History = history
	return nil
}

func loadHistory(ctx context.Context, tx *sql.Tx, userID string) ([]userlifecycle.Transition, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT from_state, to_state, reason, actor, transition_at_ns
FROM user_lifecycle_history WHERE user_id = $1 ORDER BY sequence`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var history []userlifecycle.Transition
	for rows.Next() {
		var from, to string
		var transition userlifecycle.Transition
		var at int64
		if err := rows.Scan(&from, &to, &transition.Reason, &transition.Actor, &at); err != nil {
			return nil, err
		}
		transition.From, transition.To, transition.At = userlifecycle.State(from), userlifecycle.State(to), unixNanoTime(at)
		history = append(history, transition)
	}
	return history, rows.Err()
}

// Append atomically checks the live state, advances it, and appends history.
func (s *Store) Append(ctx context.Context, userID string, transition userlifecycle.Transition) error {
	updatedAt := time.Now().UTC()
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		if err := applyState(ctx, tx, userID, transition, updatedAt); err != nil {
			return err
		}
		return appendHistory(ctx, tx, userID, transition)
	})
	if errors.Is(err, userlifecycle.ErrStateConflict) {
		return userlifecycle.ErrStateConflict
	}
	if err != nil {
		return fmt.Errorf("userlifecycle/postgres: append: %w", err)
	}
	return nil
}

func applyState(ctx context.Context, tx *sql.Tx, userID string, transition userlifecycle.Transition, updatedAt time.Time) error {
	if transition.From == userlifecycle.StateNone {
		return insertInitialState(ctx, tx, userID, transition.To, updatedAt)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE user_lifecycle_records SET state = $1, updated_at_ns = $2
WHERE user_id = $3 AND state = $4`,
		transition.To, updatedAt.UnixNano(), userID, transition.From)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 1 {
		return nil
	}
	if transition.From != userlifecycle.DefaultState {
		return userlifecycle.ErrStateConflict
	}
	return insertInitialState(ctx, tx, userID, transition.To, updatedAt)
}

func insertInitialState(ctx context.Context, tx *sql.Tx, userID string, state userlifecycle.State, updatedAt time.Time) error {
	result, err := tx.ExecContext(ctx, `
INSERT INTO user_lifecycle_records (user_id, state, updated_at_ns)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, userID, state, updatedAt.UnixNano())
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return userlifecycle.ErrStateConflict
	}
	return nil
}

func appendHistory(ctx context.Context, tx *sql.Tx, userID string, transition userlifecycle.Transition) error {
	var sequence int64
	if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX(sequence), 0) + 1 FROM user_lifecycle_history WHERE user_id = $1`, userID).
		Scan(&sequence); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO user_lifecycle_history
    (user_id, sequence, from_state, to_state, reason, actor, transition_at_ns)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, sequence, transition.From, transition.To,
		transition.Reason, transition.Actor, timeUnixNano(transition.At))
	return err
}

// ListByState returns explicit records in stable user-id order.
func (s *Store) ListByState(ctx context.Context, state userlifecycle.State) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT user_id FROM user_lifecycle_records WHERE state = $1 ORDER BY user_id`, state)
	if err != nil {
		return nil, fmt.Errorf("userlifecycle/postgres: list by state: %w", err)
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("userlifecycle/postgres: list by state scan: %w", err)
		}
		users = append(users, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("userlifecycle/postgres: list by state rows: %w", err)
	}
	return users, nil
}

func timeUnixNano(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.UnixNano()
}

func unixNanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}
