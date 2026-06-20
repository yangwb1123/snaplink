package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// totpFactorsSchema persists one TOTP factor per user for self-service
// enrollment. PRIMARY KEY on user_id makes AddTOTPFactor an atomic upsert and
// matches the memory peer's one-secret-per-user model: TOTP login verification
// keys on the user (GetSecret takes a userID), so a re-enroll replaces rather
// than accumulating a secret login could never reach. secret is the RAW shared
// secret (MUST-encrypt material — use an encrypted DSN / volume); added_at is
// Unix nanoseconds per the repo timestamp convention.
const totpFactorsSchema = `
CREATE TABLE IF NOT EXISTS totp_factors (
    user_id   TEXT PRIMARY KEY,
    factor_id TEXT NOT NULL,
    label     TEXT NOT NULL DEFAULT '',
    secret    BLOB NOT NULL,
    added_at  INTEGER NOT NULL
);
`

// TOTPEnrollmentStore is the SQLite-backed peer of
// defaultimpl.MemoryTOTPEnrollmentStore. One instance plays three roles off the
// same table — authenticators.TOTPStore (the login verifier's secret source),
// sso.MFAEnrollmentStore (the /me/mfa list+unbind view), and
// sso.TOTPEnrollmentWriter (the confirm commit) — so a factor enrolled on
// replica A is durable and immediately usable at login on replica B (and after
// a restart), unlike the in-memory peer.
type TOTPEnrollmentStore struct {
	db *sql.DB
}

// NewTOTPEnrollmentStore opens dsn, migrates the schema, and returns the store.
// Caller owns Close().
func NewTOTPEnrollmentStore(dsn string) (*TOTPEnrollmentStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "totp_factors", totpFactorsSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate totp_factors: %w", err)
	}
	return &TOTPEnrollmentStore{db: db}, nil
}

// NewTOTPEnrollmentStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments). Caller owns the connection lifecycle.
func NewTOTPEnrollmentStoreWithDB(db *sql.DB) (*TOTPEnrollmentStore, error) {
	if err := ensureSchema(db, "totp_factors", totpFactorsSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate totp_factors: %w", err)
	}
	return &TOTPEnrollmentStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *TOTPEnrollmentStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the operator-facing schema reporter.
// Nil after Close; callers MUST NOT close it.
func (s *TOTPEnrollmentStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck] wiring.
func (s *TOTPEnrollmentStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: totp enrollment store closed")
	}
	return s.db.PingContext(ctx)
}

// AddTOTPFactor commits a verified secret + records the factor. The PRIMARY KEY
// upsert replaces any prior TOTP factor for userID (one per user).
func (s *TOTPEnrollmentStore) AddTOTPFactor(ctx context.Context, userID, factorID, label string, secret []byte) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO totp_factors (user_id, factor_id, label, secret, added_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            factor_id = excluded.factor_id,
            label     = excluded.label,
            secret    = excluded.secret,
            added_at  = excluded.added_at`,
		userID, factorID, label, secret, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: upsert totp_factor: %w", err)
	}
	return nil
}

// GetSecret satisfies authenticators.TOTPStore for the login-time verifier.
// Returns authenticators.ErrTOTPNoSecret when the user has no enrolled factor,
// matching the memory peer + the TOTPStore contract.
func (s *TOTPEnrollmentStore) GetSecret(ctx context.Context, userID string) ([]byte, error) {
	var secret []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT secret FROM totp_factors WHERE user_id = ?`, userID).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authenticators.ErrTOTPNoSecret
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get totp secret: %w", err)
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
		`SELECT factor_id, label, added_at FROM totp_factors WHERE user_id = ?`, userID).
		Scan(&factorID, &label, &addedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return []core.MFAEnrolledFactor{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: list totp factors: %w", err)
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
		`DELETE FROM totp_factors WHERE user_id = ? AND factor_id = ?`, userID, factorID)
	if err != nil {
		return fmt.Errorf("sqlite: delete totp_factor: %w", err)
	}
	return nil
}

var (
	_ sso.MFAEnrollmentStore   = (*TOTPEnrollmentStore)(nil)
	_ sso.TOTPEnrollmentWriter = (*TOTPEnrollmentStore)(nil)
	_ authenticators.TOTPStore = (*TOTPEnrollmentStore)(nil)
)
