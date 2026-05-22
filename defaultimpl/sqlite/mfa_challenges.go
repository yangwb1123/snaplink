package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
)

// mfaChallengesSchema persists in-flight MFA step-up state between
// /auth/login's mfa_required response and the /auth/mfa completion
// call. Same single-use atomic-consume contract AuthCodeStore and
// PARStore enforce — DELETE ... RETURNING makes replay impossible
// even under concurrent /auth/mfa requests targeting one challenge.
//
// RequestState is the SSO server's opaque JSON resume blob (logged
// request + AuthResult); the column is BLOB so future schema additions
// to that blob (binary-safe encoders, compression) don't require a
// migration here.
const mfaChallengesSchema = `
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id             TEXT    PRIMARY KEY,
    subject_id     TEXT    NOT NULL,
    client_id      TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    request_state  BLOB
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at
    ON mfa_challenges(expires_at);
`

// MFAChallengeStore is the SQLite-backed [sso.MFAChallengeStore].
// Suitable for multi-replica deployments — a challenge issued by the
// replica that handled /auth/login is consumable by whichever replica
// the client's /auth/mfa POST lands on (so MFA survives a load
// balancer with no session affinity).
type MFAChallengeStore struct {
	db *sql.DB
}

// NewMFAChallengeStore opens dsn, migrates the schema, returns the
// store. The provider owns the *sql.DB — Close() releases it. See
// sqlite/users.go for DSN cookbook.
func NewMFAChallengeStore(dsn string) (*MFAChallengeStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), mfaChallengesSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate mfa_challenges: %w", err)
	}
	return &MFAChallengeStore{db: db}, nil
}

// NewMFAChallengeStoreWithDB wraps an existing *sql.DB. Caller owns
// the connection lifecycle (matches the AuthCodeStore pattern for
// shared-pool deployments).
func NewMFAChallengeStoreWithDB(db *sql.DB) (*MFAChallengeStore, error) {
	if _, err := db.ExecContext(context.Background(), mfaChallengesSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate mfa_challenges: %w", err)
	}
	return &MFAChallengeStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *MFAChallengeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *MFAChallengeStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: mfa challenge store closed")
	}
	return s.db.PingContext(ctx)
}

// Put persists a freshly-issued challenge. Caller MUST set both ID
// and ExpiresAt; the store performs no defaulting (default-TTL policy
// lives in the SSO server so memory + sqlite peers stay schema-flat).
func (s *MFAChallengeStore) Put(ctx context.Context, c *sso.MFAChallenge) error {
	if c == nil || c.ID == "" {
		return sso.ErrMFAChallengeNotFound
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO mfa_challenges (
            id, subject_id, client_id, created_at, expires_at, request_state
        ) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.SubjectID, c.ClientID,
		c.CreatedAt.UnixNano(), c.ExpiresAt.UnixNano(),
		c.RequestState,
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert mfa_challenge: %w", err)
	}
	return nil
}

// Consume atomically deletes and returns the matching challenge.
// Missing, expired, or already-consumed entries all return
// ErrMFAChallengeNotFound — the SSO server collapses every case to
// the same 400 mfa_invalid wire response (anti-enumeration).
func (s *MFAChallengeStore) Consume(ctx context.Context, id string) (*sso.MFAChallenge, error) {
	if id == "" {
		return nil, sso.ErrMFAChallengeNotFound
	}
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM mfa_challenges WHERE id = ?
        RETURNING subject_id, client_id, created_at, expires_at, request_state`,
		id,
	)
	var (
		out          sso.MFAChallenge
		createdUnix  int64
		expiresUnix  int64
		requestState []byte
	)
	if err := row.Scan(&out.SubjectID, &out.ClientID, &createdUnix, &expiresUnix, &requestState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sso.ErrMFAChallengeNotFound
		}
		return nil, fmt.Errorf("sqlite: consume mfa_challenge: %w", err)
	}
	out.ID = id
	out.CreatedAt = time.Unix(0, createdUnix).UTC()
	out.ExpiresAt = time.Unix(0, expiresUnix).UTC()
	out.RequestState = requestState
	// Row already deleted — even when expired we don't restore it. The
	// caller collapses missing + expired to the same wire response, so
	// the deletion alone is sufficient to enforce both single-use and
	// the expiry boundary.
	if time.Now().After(out.ExpiresAt) {
		return nil, sso.ErrMFAChallengeNotFound
	}
	return &out, nil
}

var _ sso.MFAChallengeStore = (*MFAChallengeStore)(nil)
