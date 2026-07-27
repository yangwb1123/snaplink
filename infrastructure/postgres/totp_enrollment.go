package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

// totpFactorsSchema persists one TOTP factor per user for self-service
// enrollment (Postgres dialect). PRIMARY KEY on user_id makes AddTOTPFactor an
// atomic upsert and matches the memory/SQLite peers' one-secret-per-user model:
// TOTP login verification keys on the user (GetSecret takes a userID), so a
// re-enroll replaces rather than accumulating a secret login could never reach.
// secret is the RAW shared secret stored as BYTEA (MUST-encrypt material — use
// a TLS DSN + encryption-at-rest); added_at is Unix nanoseconds in a BIGINT
// (NOT timestamptz — preserves the exact nanosecond round-trip, matching the
// SQLite peer's INTEGER column).
const totpFactorsSchema = `
CREATE TABLE IF NOT EXISTS totp_factors (
    user_id   TEXT   PRIMARY KEY,
    factor_id TEXT   NOT NULL,
    label     TEXT   NOT NULL DEFAULT '',
    secret    BYTEA  NOT NULL,
    added_at  BIGINT NOT NULL
);
`

var totpMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: totpFactorsSchema},
}

// TOTPEnrollmentStore is the Postgres-backed peer of the SQLite + memory TOTP
// enrollment stores. One instance plays three roles off the same table —
// authenticators.TOTPStore (the login verifier's secret source),
// sso.MFAEnrollmentStore (the /me/mfa list+unbind view), and
// sso.TOTPEnrollmentWriter (the confirm commit) — so a factor enrolled on
// replica A is durable and immediately usable at login on replica B.
type TOTPEnrollmentStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewTOTPEnrollmentStore opens cfg.DSN, migrates the schema, and returns the
// store. Caller owns Close().
func NewTOTPEnrollmentStore(cfg Config) (*TOTPEnrollmentStore, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewTOTPEnrollmentStoreWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewTOTPEnrollmentStoreWithDB wraps an existing shared *sql.DB. The caller owns
// the connection lifecycle (shared-pool deployments).
func NewTOTPEnrollmentStoreWithDB(db *sql.DB, dialect Dialect) (*TOTPEnrollmentStore, error) {
	if err := Run(context.Background(), db, "totp", totpMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate totp: %w", err)
	}
	return &TOTPEnrollmentStore{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool store built via
// NewTOTPEnrollmentStoreWithDB should be closed by whoever owns the pool, not
// here — but Close is safe either way (database/sql Close is idempotent).
func (s *TOTPEnrollmentStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (s *TOTPEnrollmentStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *TOTPEnrollmentStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: totp enrollment store closed")
	}
	return s.db.PingContext(ctx)
}

// AddTOTPFactor commits a verified secret + records the factor. The PRIMARY KEY
// upsert replaces any prior TOTP factor for userID (one per user).
func (s *TOTPEnrollmentStore) AddTOTPFactor(ctx context.Context, userID, factorID, label string, secret []byte) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO totp_factors (user_id, factor_id, label, secret, added_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id) DO UPDATE SET
            factor_id = EXCLUDED.factor_id,
            label     = EXCLUDED.label,
            secret    = EXCLUDED.secret,
            added_at  = EXCLUDED.added_at`,
		userID, factorID, label, secret, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("postgres: upsert totp_factor: %w", err)
	}
	return nil
}

// GetSecret satisfies authenticators.TOTPStore for the login-time verifier.
// Returns authenticators.ErrTOTPNoSecret when the user has no enrolled factor,
// matching the memory/SQLite peers + the TOTPStore contract.
func (s *TOTPEnrollmentStore) GetSecret(ctx context.Context, userID string) ([]byte, error) {
	var secret []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT secret FROM totp_factors WHERE user_id = $1`, userID).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authenticators.ErrTOTPNoSecret
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get totp secret: %w", err)
	}
	return secret, nil
}

// ListFactors returns the user's TOTP factor (0 or 1 element).
func (s *TOTPEnrollmentStore) ListFactors(ctx context.Context, userID string) ([]core.MFAEnrolledFactor, error) {
	var (
		factorID string
		label    string
		addedAt  int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT factor_id, label, added_at FROM totp_factors WHERE user_id = $1`, userID).
		Scan(&factorID, &label, &addedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return []core.MFAEnrolledFactor{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: list totp factors: %w", err)
	}
	return []core.MFAEnrolledFactor{{
		ID:      factorID,
		Method:  authenticators.MethodTOTP,
		Label:   label,
		AddedAt: time.Unix(0, addedAt),
	}}, nil
}

// RemoveFactor unbinds the user's TOTP factor when factorID matches, clearing
// the secret with it. Idempotent; a non-matching factorID affects no rows —
// ownership is enforced by the handler via ListFactors before it calls here.
func (s *TOTPEnrollmentStore) RemoveFactor(ctx context.Context, userID, factorID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM totp_factors WHERE user_id = $1 AND factor_id = $2`, userID, factorID)
	if err != nil {
		return fmt.Errorf("postgres: delete totp_factor: %w", err)
	}
	return nil
}

var (
	_ sso.MFAEnrollmentStore   = (*TOTPEnrollmentStore)(nil)
	_ sso.TOTPEnrollmentWriter = (*TOTPEnrollmentStore)(nil)
	_ authenticators.TOTPStore = (*TOTPEnrollmentStore)(nil)
)
