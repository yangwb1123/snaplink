package securitystore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/security"
)

const lockoutSchema = `
CREATE TABLE IF NOT EXISTS account_lockouts (
 key TEXT PRIMARY KEY,
 failures BIGINT NOT NULL DEFAULT 0,
 first_failure_at BIGINT NOT NULL DEFAULT 0,
 locked_until BIGINT NOT NULL DEFAULT 0
);
`

var lockoutMigrations = []migrate.Migration{{Version: 1, Name: "baseline", SQL: lockoutSchema}}

func AccountLockoutMaxVersion() int { return migrate.MaxVersion(lockoutMigrations) }

// AccountLockout retains the opaque key and nanosecond clock of the SQLite peer.
// Policy fields are configured before concurrent use, as with the memory peer.
type AccountLockout struct {
	*store
	MaxFailures     int
	LockoutDuration time.Duration
	FailureWindow   time.Duration
}

func NewAccountLockoutWithDB(db *sql.DB, dialect pg.Dialect) (*AccountLockout, error) {
	s, err := openStore(db, dialect, "account_lockout", lockoutMigrations)
	if err != nil {
		return nil, err
	}
	return &AccountLockout{store: s, MaxFailures: security.DefaultLockoutMaxFailures,
		LockoutDuration: security.DefaultLockoutDuration, FailureWindow: security.DefaultLockoutFailureWindow}, nil
}

func (a *AccountLockout) IsLocked(ctx context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	db, err := a.pool()
	if err != nil {
		return false, time.Time{}, err
	}
	var expiry int64
	err = db.QueryRowContext(ctx, "SELECT locked_until FROM account_lockouts WHERE key=$1", key).Scan(&expiry)
	if errors.Is(err, sql.ErrNoRows) || err == nil && expiry == 0 {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, fmt.Errorf("postgres: lockout lookup: %w", err)
	}
	until := time.Unix(0, expiry).UTC()
	if time.Now().After(until) {
		// Compare-clear cannot erase a fresh lock created after this SELECT.
		// The peer deliberately treats a failed lazy-expiry write as unlocked.
		_, _ = db.ExecContext(ctx, "UPDATE account_lockouts SET locked_until=0 WHERE key=$1 AND locked_until=$2", key, expiry)
		return false, time.Time{}, nil
	}
	return true, until, nil
}

func (a *AccountLockout) RegisterFailure(ctx context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	db, err := a.pool()
	if err != nil {
		return false, time.Time{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("postgres: lockout begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// A no-op conflict UPDATE holds the row lock until commit. DO NOTHING
	// leaves a delete/reset gap before FOR UPDATE, losing concurrent failures.
	if _, err := tx.ExecContext(ctx, "INSERT INTO account_lockouts(key) VALUES($1) ON CONFLICT(key) DO UPDATE SET key=excluded.key", key); err != nil {
		return false, time.Time{}, fmt.Errorf("postgres: lockout insert: %w", err)
	}
	locked, until, err := a.applyFailure(ctx, tx, key)
	if err != nil {
		return false, time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		// Never retry an uncertain commit or publish a provisional lock result.
		return false, time.Time{}, fmt.Errorf("postgres: lockout commit (reconcile before replay): %w", err)
	}
	return locked, until, nil
}

func (a *AccountLockout) applyFailure(ctx context.Context, tx *sql.Tx, key string) (bool, time.Time, error) {
	var failures, first, expiry int64
	err := tx.QueryRowContext(ctx, "SELECT failures,first_failure_at,locked_until FROM account_lockouts WHERE key=$1 FOR UPDATE", key).Scan(&failures, &first, &expiry)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("postgres: lockout scan: %w", err)
	}
	now := time.Now()
	if first != 0 && now.Sub(time.Unix(0, first)) > a.FailureWindow {
		failures, first, expiry = 0, 0, 0
	}
	if expiry != 0 && now.Before(time.Unix(0, expiry)) {
		return true, time.Unix(0, expiry).UTC(), nil
	}
	if failures == math.MaxInt64 {
		return false, time.Time{}, fmt.Errorf("postgres: lockout counter overflow")
	}
	failures++
	if first == 0 {
		first = now.UnixNano()
	}
	locked := failures >= int64(a.MaxFailures)
	if locked {
		expiry = now.Add(a.LockoutDuration).UnixNano()
	}
	_, err = tx.ExecContext(ctx, "UPDATE account_lockouts SET failures=$2,first_failure_at=$3,locked_until=$4 WHERE key=$1", key, failures, first, expiry)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("postgres: lockout update: %w", err)
	}
	if locked {
		return true, time.Unix(0, expiry).UTC(), nil
	}
	return false, time.Time{}, nil
}

func (a *AccountLockout) RegisterSuccess(ctx context.Context, key string) error {
	if key == "" {
		return nil
	}
	db, err := a.pool()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "DELETE FROM account_lockouts WHERE key=$1", key)
	return err
}

var _ security.AccountLockout = (*AccountLockout)(nil)
