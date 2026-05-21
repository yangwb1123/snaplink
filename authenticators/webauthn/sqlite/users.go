// Package sqlite ships SQLite-backed implementations of
// [webauthn.UserStore] and [webauthn.SessionStore] for multi-replica
// deployments. A credential registered against replica A is then
// visible at login time on replica B, and a Begin* ceremony session
// minted on replica A is consumable at the matching Finish* call on
// replica B.
//
// Both stores use the same modernc.org/sqlite driver as the other
// defaultimpl SQLite backends — no CGO. Schema migration is a single
// CREATE TABLE IF NOT EXISTS at construction.
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"

	"github.com/snaplink/sso/authenticators/webauthn"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

// userSchema stores one row per enrolled username; credentials live
// in a JSON array column. Memory backend forks per replica — a
// credential enrolled on replica A is invisible on replica B.
//
// One-row-per-user keeps Add/UpdateCredential as read-modify-write
// inside a transaction (BEGIN IMMEDIATE serializes the increment
// across replicas the same way AccountLockout does for the failure
// counter). The SPI never asks for per-credential queries.
const userSchema = `
CREATE TABLE IF NOT EXISTS webauthn_users (
    name         TEXT    PRIMARY KEY,
    handle       BLOB    NOT NULL,
    display_name TEXT    NOT NULL,
    credentials  TEXT    NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_webauthn_users_handle
    ON webauthn_users(handle);
`

// UserStore is the SQLite-backed [webauthn.UserStore]. Implements
// the optional GetByHandle resolver so [webauthn.Helper.FinishLogin]
// can resolve sessions that encode the raw user handle rather than
// the username.
type UserStore struct {
	db *sql.DB
}

// NewUserStore opens dsn, migrates the schema, and returns the store.
// The provider owns the *sql.DB — [UserStore.Close] releases it.
// DSN cookbook mirrors defaultimpl/sqlite: production wants
// `file:/var/lib/sso/webauthn.db?_journal=WAL&_busy_timeout=5000`.
func NewUserStore(dsn string) (*UserStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), userSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate webauthn_users: %w", err)
	}
	return &UserStore{db: db}, nil
}

// NewUserStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments). Caller owns the connection lifecycle.
func NewUserStoreWithDB(db *sql.DB) (*UserStore, error) {
	if _, err := db.ExecContext(context.Background(), userSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate webauthn_users: %w", err)
	}
	return &UserStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *UserStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *UserStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: webauthn user store closed")
	}
	return s.db.PingContext(ctx)
}

// GetByName implements [webauthn.UserStore].
func (s *UserStore) GetByName(ctx context.Context, name string) (*webauthn.User, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT name, handle, display_name, credentials
          FROM webauthn_users WHERE name = ?`, name)
	return scanUser(row)
}

// GetByHandle returns the user with the given WebAuthn handle.
// [webauthn.Helper] type-asserts this method on UserStore.
func (s *UserStore) GetByHandle(ctx context.Context, handle []byte) (*webauthn.User, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT name, handle, display_name, credentials
          FROM webauthn_users WHERE handle = ?`, handle)
	return scanUser(row)
}

// CreateUser implements [webauthn.UserStore]. Generates a fresh
// 32-byte handle and rejects duplicate names.
func (s *UserStore) CreateUser(ctx context.Context, name, displayName string) (*webauthn.User, error) {
	handle, err := randomHandle()
	if err != nil {
		return nil, fmt.Errorf("sqlite: random handle: %w", err)
	}
	u := &webauthn.User{
		Handle:      handle,
		Name:        name,
		DisplayName: displayName,
	}
	// JSON-encode the zero-length credential slice as "[]" so a
	// subsequent GetByName sees a non-NULL column (matches schema
	// default + avoids special-casing scanUser).
	credsJSON, err := json.Marshal(u.Credentials)
	if err != nil {
		return nil, fmt.Errorf("sqlite: marshal credentials: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO webauthn_users (name, handle, display_name, credentials)
        VALUES (?, ?, ?, ?)`,
		u.Name, u.Handle, u.DisplayName, string(credsJSON),
	)
	if err != nil {
		// modernc.org/sqlite surfaces UNIQUE violations as substring
		// matches on the error message; the SPI just needs a non-nil
		// error so we wrap.
		return nil, fmt.Errorf("sqlite: insert webauthn_user: %w", err)
	}
	return u, nil
}

// AddCredential implements [webauthn.UserStore]. Read-modify-write
// inside BEGIN IMMEDIATE so two concurrent registration ceremonies
// across replicas can't both observe the same credential list and
// drop one of the appends.
func (s *UserStore) AddCredential(ctx context.Context, name string, cred *gw.Credential) error {
	return s.mutateCredentials(ctx, name, func(creds []gw.Credential) ([]gw.Credential, error) {
		return append(creds, *cred), nil
	})
}

// UpdateCredential implements [webauthn.UserStore]. Replaces the
// in-place credential by ID match. Returns an error matching the
// memory backend contract when no credential matches.
func (s *UserStore) UpdateCredential(ctx context.Context, name string, cred *gw.Credential) error {
	return s.mutateCredentials(ctx, name, func(creds []gw.Credential) ([]gw.Credential, error) {
		for i, c := range creds {
			if bytesEqual(c.ID, cred.ID) {
				creds[i] = *cred
				return creds, nil
			}
		}
		return nil, errors.New("webauthn: credential not found for user")
	})
}

func (s *UserStore) mutateCredentials(ctx context.Context, name string, mutate func([]gw.Credential) ([]gw.Credential, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: webauthn_user begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var credsJSON string
	row := tx.QueryRowContext(ctx, `
        SELECT credentials FROM webauthn_users WHERE name = ?`, name)
	if err := row.Scan(&credsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return webauthn.ErrUserUnknown
		}
		return fmt.Errorf("sqlite: webauthn_user scan: %w", err)
	}

	var creds []gw.Credential
	if err := json.Unmarshal([]byte(credsJSON), &creds); err != nil {
		return fmt.Errorf("sqlite: unmarshal credentials: %w", err)
	}
	updated, err := mutate(creds)
	if err != nil {
		return err
	}
	out, err := json.Marshal(updated)
	if err != nil {
		return fmt.Errorf("sqlite: marshal credentials: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE webauthn_users SET credentials = ? WHERE name = ?`,
		string(out), name,
	); err != nil {
		return fmt.Errorf("sqlite: webauthn_user update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: webauthn_user commit: %w", err)
	}
	return nil
}

func scanUser(row *sql.Row) (*webauthn.User, error) {
	var (
		out       webauthn.User
		credsJSON string
	)
	if err := row.Scan(&out.Name, &out.Handle, &out.DisplayName, &credsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, webauthn.ErrUserUnknown
		}
		return nil, fmt.Errorf("sqlite: webauthn_user scan: %w", err)
	}
	if credsJSON != "" && credsJSON != "[]" {
		if err := json.Unmarshal([]byte(credsJSON), &out.Credentials); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal credentials: %w", err)
		}
	}
	return &out, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randomHandle() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

var _ webauthn.UserStore = (*UserStore)(nil)
