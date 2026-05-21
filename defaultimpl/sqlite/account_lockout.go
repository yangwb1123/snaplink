package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
)

// accountLockoutSchema covers the per-key failure counter +
// sliding-window timestamps + lock expiry. Single row per `key`
// (the server composes <client_id>:<identifier>); BEGIN IMMEDIATE
// + read-modify-write keeps the failure increment race-free across
// replicas.
const accountLockoutSchema = `
CREATE TABLE IF NOT EXISTS account_lockouts (
    key              TEXT    PRIMARY KEY,
    failures         INTEGER NOT NULL DEFAULT 0,
    first_failure_at INTEGER NOT NULL DEFAULT 0,
    locked_until     INTEGER NOT NULL DEFAULT 0
);
`

// AccountLockout is the SQLite-backed implementation of
// [sso.AccountLockout]. Replaces the memory backend for multi-replica
// deployments — an attacker rotating targets across replicas can't
// stay under each replica's local threshold because the counter is
// shared.
type AccountLockout struct {
	// MaxFailures / LockoutDuration / FailureWindow mirror
	// sso.MemoryAccountLockout. Fields are exported so cmd can apply
	// the same overrides for both backends.
	MaxFailures     int
	LockoutDuration time.Duration
	FailureWindow   time.Duration

	db *sql.DB
}

// NewAccountLockout opens dsn, migrates the schema, and returns the
// lockout with Default* policy. Operators override the policy
// fields directly after construction.
func NewAccountLockout(dsn string) (*AccountLockout, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), accountLockoutSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate account_lockouts: %w", err)
	}
	return &AccountLockout{
		MaxFailures:     sso.DefaultLockoutMaxFailures,
		LockoutDuration: sso.DefaultLockoutDuration,
		FailureWindow:   sso.DefaultLockoutFailureWindow,
		db:              db,
	}, nil
}

// NewAccountLockoutWithDB wraps an existing *sql.DB (shared-pool
// deployments).
func NewAccountLockoutWithDB(db *sql.DB) (*AccountLockout, error) {
	if _, err := db.ExecContext(context.Background(), accountLockoutSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate account_lockouts: %w", err)
	}
	return &AccountLockout{
		MaxFailures:     sso.DefaultLockoutMaxFailures,
		LockoutDuration: sso.DefaultLockoutDuration,
		FailureWindow:   sso.DefaultLockoutFailureWindow,
		db:              db,
	}, nil
}

// Close releases the SQLite connection. Idempotent.
func (a *AccountLockout) Close() error {
	if a == nil || a.db == nil {
		return nil
	}
	err := a.db.Close()
	a.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (a *AccountLockout) Ping(ctx context.Context) error {
	if a == nil || a.db == nil {
		return errors.New("sqlite: account lockout closed")
	}
	return a.db.PingContext(ctx)
}

// IsLocked reports the lock state. Lazy-expires past locks by
// nulling locked_until — same auto-unlock semantics the memory
// backend gives. Hot-path read for /auth/login so it stays on a
// plain SELECT (no transaction) to avoid lock contention with
// concurrent RegisterFailure transactions.
func (a *AccountLockout) IsLocked(ctx context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	row := a.db.QueryRowContext(ctx, `
        SELECT locked_until FROM account_lockouts WHERE key = ?`, key)
	var lockedUntilNs int64
	if err := row.Scan(&lockedUntilNs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, fmt.Errorf("sqlite: lockout lookup: %w", err)
	}
	if lockedUntilNs == 0 {
		return false, time.Time{}, nil
	}
	until := time.Unix(0, lockedUntilNs).UTC()
	if time.Now().After(until) {
		// Lazy-expire: clear the field so the next IsLocked reads it
		// as 0 without a transaction. RegisterFailure resets the
		// counter on a fresh window.
		if _, err := a.db.ExecContext(ctx, `UPDATE account_lockouts SET locked_until = 0 WHERE key = ?`, key); err != nil {
			// Treat as fail-open — IsLocked is the wrong place to
			// fail-closed (locks every login during a partition).
			return false, time.Time{}, nil
		}
		return false, time.Time{}, nil
	}
	return true, until, nil
}

// RegisterFailure increments the failure counter inside a BEGIN
// IMMEDIATE transaction so two concurrent failures across replicas
// can't both observe count=N-1 and skip the threshold trigger.
//
// On threshold cross, locked_until is set to now + LockoutDuration
// + the function returns (true, until). Subsequent failures against
// an already-locked key return (true, until) without further
// counter mutation — matches memory backend contract.
//
// Sliding-window reset: if firstFailureAt is older than
// FailureWindow, the counter restarts at 1 for THIS failure.
func (a *AccountLockout) RegisterFailure(ctx context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("sqlite: lockout begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		failures           int
		firstFailureAtNs   int64
		lockedUntilNs      int64
	)
	row := tx.QueryRowContext(ctx, `
        SELECT failures, first_failure_at, locked_until
          FROM account_lockouts WHERE key = ?`, key)
	if err := row.Scan(&failures, &firstFailureAtNs, &lockedUntilNs); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return false, time.Time{}, fmt.Errorf("sqlite: lockout scan: %w", err)
		}
		// First-ever failure for this key.
	}

	now := time.Now()
	firstFailureAt := time.Time{}
	if firstFailureAtNs != 0 {
		firstFailureAt = time.Unix(0, firstFailureAtNs).UTC()
	}
	lockedUntil := time.Time{}
	if lockedUntilNs != 0 {
		lockedUntil = time.Unix(0, lockedUntilNs).UTC()
	}

	// Sliding-window reset before any other logic.
	if !firstFailureAt.IsZero() && now.Sub(firstFailureAt) > a.FailureWindow {
		failures = 0
		firstFailureAt = time.Time{}
		lockedUntil = time.Time{}
	}

	// Already-locked path: leave counter untouched, return (true, until).
	if !lockedUntil.IsZero() && now.Before(lockedUntil) {
		// Commit the no-op so any in-flight reset stays observable.
		if err := tx.Commit(); err != nil {
			return true, lockedUntil, nil
		}
		return true, lockedUntil, nil
	}

	failures++
	if firstFailureAt.IsZero() {
		firstFailureAt = now
	}
	threshold := failures >= a.MaxFailures
	if threshold {
		lockedUntil = now.Add(a.LockoutDuration)
	}

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO account_lockouts (key, failures, first_failure_at, locked_until)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (key) DO UPDATE SET
            failures = excluded.failures,
            first_failure_at = excluded.first_failure_at,
            locked_until = excluded.locked_until`,
		key, failures, firstFailureAt.UnixNano(), lockedUntilUnix(lockedUntil),
	); err != nil {
		return false, time.Time{}, fmt.Errorf("sqlite: lockout upsert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, time.Time{}, fmt.Errorf("sqlite: lockout commit: %w", err)
	}
	if threshold {
		return true, lockedUntil, nil
	}
	return false, time.Time{}, nil
}

// RegisterSuccess clears the entry — both the counter and any
// in-progress lock. Idempotent on unknown keys.
func (a *AccountLockout) RegisterSuccess(ctx context.Context, key string) error {
	if key == "" {
		return nil
	}
	_, err := a.db.ExecContext(ctx, `DELETE FROM account_lockouts WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("sqlite: lockout clear: %w", err)
	}
	return nil
}

func lockedUntilUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

var _ sso.AccountLockout = (*AccountLockout)(nil)
