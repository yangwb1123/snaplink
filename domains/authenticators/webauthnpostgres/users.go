// Package postgres ships a Postgres/CockroachDB-backed implementation of
// [webauthn.UserStore] so passkey credentials are durable and cluster-shared
// in an HA deployment: a credential registered against replica A is visible at
// login time on replica B, and survives a replica restart. It is the durable
// peer of the memory + SQLite WebAuthn user stores and the direct parallel of
// the Postgres TOTP-enrollment backend (one-secret/credential-set-per-user,
// shared *sql.DB, advisory-locked migration, SERIALIZABLE read-modify-write).
//
// The store receives the SHARED connection pool the cmd builder already opened
// for the rest of the durable backend (the pgx/v5 stdlib driver is registered
// there); it never opens its own connection and never imports pgx, so the
// production build carries no new driver dependency.
package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/snaplink/sso/domains/authenticators/webauthn"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

const (
	// dialectCockroach selects the no-advisory-lock migration path: CockroachDB
	// has no session/advisory locks, so concurrent replica boots rely on
	// CREATE TABLE IF NOT EXISTS + its always-SERIALIZABLE default + the 40001
	// retry instead. Any other value (incl. "" / "postgres") takes the
	// advisory-lock path.
	dialectCockroach = "cockroach"
	// dialectPostgres is the default, taken by "" and any non-cockroach value.
	dialectPostgres = "postgres"

	// sqlStateSerializationFailure is SQLSTATE 40001 (serialization_failure /
	// "restart transaction") emitted by Postgres SSI and CockroachDB under
	// contention. Detected through the driver error's SQLState() method so this
	// package needs no pgx import.
	sqlStateSerializationFailure = "40001"

	// serializableMaxRetries bounds the 40001 retry loop. Postgres holds the
	// advisory lock during migration so it never emits 40001; only CockroachDB
	// contends, and a handful of retries clears any realistic concurrency.
	serializableMaxRetries = 5

	// handleBytes is the WebAuthn user-handle length. 32 random bytes makes the
	// handle effectively unique, which is why the column carries a UNIQUE
	// constraint (it also gives GetByHandle an index without a second DDL stmt).
	handleBytes = 32

	// emptyCredentials is the JSON encoding of a zero-length credential array;
	// the load path treats it (and the "null" a nil slice marshals to) as no
	// credentials without a json.Unmarshal round-trip.
	emptyCredentials = "[]"

	// migrationLockNamespace seeds the per-table advisory-lock key so two
	// replicas migrating THIS table serialize while never blocking a different
	// table's migration.
	migrationLockNamespace = "sso:webauthn_users:migrate"
)

// webauthnUsersSchema stores one row per enrolled username with the user's
// credentials in an opaque JSON array column. The SPI never queries inside the
// array (login resolves by name or handle, then filters in Go), so a plain TEXT
// column mirrors the SQLite peer exactly and sidesteps jsonb parameter-encoding
// edge cases under a pgbouncer transaction-mode (simple-protocol) pooler. The
// handle is BYTEA + UNIQUE so GetByHandle is index-backed in a single CREATE
// TABLE statement (CockroachDB rejects multiple DDL in one explicit txn).
const webauthnUsersSchema = `
CREATE TABLE IF NOT EXISTS webauthn_users (
    name         TEXT  PRIMARY KEY,
    handle       BYTEA NOT NULL UNIQUE,
    display_name TEXT  NOT NULL,
    credentials  TEXT  NOT NULL DEFAULT '[]'
)`

const (
	sqlAdvisoryLock   = `SELECT pg_advisory_xact_lock($1)`
	sqlInsertUser     = `INSERT INTO webauthn_users (name, handle, display_name, credentials) VALUES ($1, $2, $3, $4)`
	sqlSelectByName   = `SELECT name, handle, display_name, credentials FROM webauthn_users WHERE name = $1`
	sqlSelectByHandle = `SELECT name, handle, display_name, credentials FROM webauthn_users WHERE handle = $1`
	sqlSelectCreds    = `SELECT credentials FROM webauthn_users WHERE name = $1`
	sqlUpdateCreds    = `UPDATE webauthn_users SET credentials = $1 WHERE name = $2`
)

// errCredentialNotFound matches the memory/SQLite backends' contract: an
// UpdateCredential whose ID is not enrolled for the user is an error, not a
// silent no-op.
var errCredentialNotFound = errors.New("webauthn: credential not found for user")

// UserStore is the Postgres-backed [webauthn.UserStore]. It also implements the
// optional GetByHandle resolver that [webauthn.Helper.FinishLogin] type-asserts
// to resolve a login session that encodes the raw user handle.
type UserStore struct {
	db      *sql.DB
	dialect string // normalized: "cockroach" or "postgres"
}

// NewUserStore wraps the shared *sql.DB and migrates the schema. dialect is
// "postgres" (default, also the empty string) or "cockroach"; it only selects
// the migration locking strategy — the SQL targets both. The caller owns the
// pool's lifecycle (it is shared with the other durable stores), so this type
// has no Close.
func NewUserStore(db *sql.DB, dialect string) (*UserStore, error) {
	if db == nil {
		return nil, errors.New("webauthnpostgres: nil *sql.DB")
	}
	d := normalizeDialect(dialect)
	if err := migrate(context.Background(), db, d); err != nil {
		return nil, fmt.Errorf("webauthnpostgres: migrate webauthn_users: %w", err)
	}
	return &UserStore{db: db, dialect: d}, nil
}

// DB exposes the shared pool for operator-facing schema/health reporting.
// Callers MUST NOT close it — the pool owner does.
func (s *UserStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *UserStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("webauthnpostgres: webauthn user store closed")
	}
	return s.db.PingContext(ctx)
}

// GetByName implements [webauthn.UserStore]. Unknown name -> ErrUserUnknown.
func (s *UserStore) GetByName(ctx context.Context, name string) (*webauthn.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, sqlSelectByName, name))
}

// GetByHandle resolves the user with the given WebAuthn handle (index-backed by
// the UNIQUE constraint). Unknown handle -> ErrUserUnknown.
func (s *UserStore) GetByHandle(ctx context.Context, handle []byte) (*webauthn.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, sqlSelectByHandle, handle))
}

// CreateUser implements [webauthn.UserStore]. Mints a fresh 32-byte handle and
// rejects a duplicate name (PRIMARY KEY violation -> non-nil error, NOT an
// upsert: the SPI contract is create-or-fail).
func (s *UserStore) CreateUser(ctx context.Context, name, displayName string) (*webauthn.User, error) {
	handle, err := randomHandle()
	if err != nil {
		return nil, fmt.Errorf("webauthnpostgres: random handle: %w", err)
	}
	u := &webauthn.User{Handle: handle, Name: name, DisplayName: displayName}
	credsJSON, err := json.Marshal(u.Credentials)
	if err != nil {
		return nil, fmt.Errorf("webauthnpostgres: marshal credentials: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, sqlInsertUser,
		u.Name, u.Handle, u.DisplayName, string(credsJSON)); err != nil {
		return nil, fmt.Errorf("webauthnpostgres: insert webauthn_user: %w", err)
	}
	return u, nil
}

// AddCredential implements [webauthn.UserStore]. Read-modify-write at
// SERIALIZABLE so two concurrent registration ceremonies across replicas cannot
// both read the same list and drop one of the appends.
func (s *UserStore) AddCredential(ctx context.Context, name string, cred *gw.Credential) error {
	return s.mutateCredentials(ctx, name, func(creds []gw.Credential) ([]gw.Credential, error) {
		return append(creds, *cred), nil
	})
}

// UpdateCredential implements [webauthn.UserStore]. Replaces the credential
// in place by ID. No match -> errCredentialNotFound (memory-backend contract).
func (s *UserStore) UpdateCredential(ctx context.Context, name string, cred *gw.Credential) error {
	return s.mutateCredentials(ctx, name, func(creds []gw.Credential) ([]gw.Credential, error) {
		for i := range creds {
			if bytes.Equal(creds[i].ID, cred.ID) {
				creds[i] = *cred
				return creds, nil
			}
		}
		return nil, errCredentialNotFound
	})
}

// RemoveCredential implements [webauthn.UserStore]. Idempotent: a credentialID
// absent for the user leaves the set unchanged. Unknown user -> ErrUserUnknown
// (from mutateCredentials).
func (s *UserStore) RemoveCredential(ctx context.Context, name string, credentialID []byte) error {
	return s.mutateCredentials(ctx, name, func(creds []gw.Credential) ([]gw.Credential, error) {
		out := creds[:0:0]
		for _, c := range creds {
			if !bytes.Equal(c.ID, credentialID) {
				out = append(out, c)
			}
		}
		return out, nil
	})
}

// mutateCredentials loads the user's credential array, applies mutate, and
// stores it back inside one SERIALIZABLE transaction (retried on 40001). The
// plain SELECT is safe under SSI: a concurrent writer's read/write dependency
// aborts one side with 40001 and the retry re-runs against the committed state.
// Under plain READ COMMITTED the same SELECT-then-UPDATE would lose an append.
func (s *UserStore) mutateCredentials(ctx context.Context, name string, mutate func([]gw.Credential) ([]gw.Credential, error)) error {
	return s.runSerializable(ctx, func(tx *sql.Tx) error {
		var credsJSON string
		if err := tx.QueryRowContext(ctx, sqlSelectCreds, name).Scan(&credsJSON); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return webauthn.ErrUserUnknown
			}
			return fmt.Errorf("webauthnpostgres: scan credentials: %w", err)
		}
		creds, err := decodeCredentials(credsJSON)
		if err != nil {
			return err
		}
		updated, err := mutate(creds)
		if err != nil {
			return err
		}
		out, err := json.Marshal(updated)
		if err != nil {
			return fmt.Errorf("webauthnpostgres: marshal credentials: %w", err)
		}
		if _, err := tx.ExecContext(ctx, sqlUpdateCreds, string(out), name); err != nil {
			return fmt.Errorf("webauthnpostgres: update credentials: %w", err)
		}
		return nil
	})
}

// rowScanner abstracts *sql.Row / *sql.Rows so scanUser serves GetByName and
// GetByHandle from the same code.
type rowScanner interface{ Scan(dest ...any) error }

func scanUser(row rowScanner) (*webauthn.User, error) {
	var (
		out       webauthn.User
		credsJSON string
	)
	if err := row.Scan(&out.Name, &out.Handle, &out.DisplayName, &credsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, webauthn.ErrUserUnknown
		}
		return nil, fmt.Errorf("webauthnpostgres: scan user: %w", err)
	}
	creds, err := decodeCredentials(credsJSON)
	if err != nil {
		return nil, err
	}
	out.Credentials = creds
	return &out, nil
}

// decodeCredentials unmarshals the stored JSON array, treating the empty array
// and a nil-slice "null" as no credentials (no allocation, no error).
func decodeCredentials(credsJSON string) ([]gw.Credential, error) {
	if credsJSON == "" || credsJSON == emptyCredentials {
		return nil, nil
	}
	var creds []gw.Credential
	if err := json.Unmarshal([]byte(credsJSON), &creds); err != nil {
		return nil, fmt.Errorf("webauthnpostgres: unmarshal credentials: %w", err)
	}
	return creds, nil
}

// runSerializable runs fn in a fresh SERIALIZABLE transaction, retrying the
// WHOLE unit of work on a 40001. Each attempt re-reads inside the supplied tx,
// so fn must be a pure function of that re-read state. The 40001 may surface
// from a statement or be deferred to Commit (common on PG SSI); both are caught
// because the closure returns the Commit error.
func (s *UserStore) runSerializable(ctx context.Context, fn func(*sql.Tx) error) error {
	return withRetry(func() error {
		tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return fmt.Errorf("webauthnpostgres: begin tx: %w", err)
		}
		defer func() { _ = tx.Rollback() }() // no-op after a successful Commit
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	})
}

// migrate creates the table at construction. Postgres serializes concurrent
// replica boots on a per-table advisory lock held until COMMIT; CockroachDB has
// no advisory locks, so it relies on IF NOT EXISTS + its SERIALIZABLE default +
// the 40001 retry. A *sql.Tx pins one backend connection, so the advisory lock
// and the COMMIT that releases it run on the same session.
func migrate(ctx context.Context, db *sql.DB, dialect string) error {
	return withRetry(func() error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("webauthnpostgres: begin migration: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		if dialect != dialectCockroach {
			if _, err := tx.ExecContext(ctx, sqlAdvisoryLock, advisoryKey(migrationLockNamespace)); err != nil {
				return fmt.Errorf("webauthnpostgres: advisory lock: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, webauthnUsersSchema); err != nil {
			return fmt.Errorf("webauthnpostgres: create table: %w", err)
		}
		return tx.Commit()
	})
}

// withRetry retries fn on a 40001 serialization failure (bounded). Non-40001
// errors and success return immediately.
func withRetry(fn func() error) error {
	var err error
	for range serializableMaxRetries {
		if err = fn(); err == nil || !isSerializationFailure(err) {
			return err
		}
	}
	return err
}

// isSerializationFailure reports whether err carries SQLSTATE 40001. It matches
// any error in the chain exposing SQLState() string (the pgx PgError does),
// keeping this package free of a direct pgx dependency.
func isSerializationFailure(err error) bool {
	var sqlErr interface{ SQLState() string }
	return errors.As(err, &sqlErr) && sqlErr.SQLState() == sqlStateSerializationFailure
}

// advisoryKey derives a stable bigint from namespace for pg_advisory_xact_lock.
// Only identity matters, so wrapping the unsigned hash to a signed bigint is
// intentional.
func advisoryKey(namespace string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(namespace))
	return int64(h.Sum64()) //nolint:gosec // wrap to bigint is intentional; only identity matters
}

// normalizeDialect maps "" and any non-cockroach value to "postgres".
func normalizeDialect(dialect string) string {
	if dialect == dialectCockroach {
		return dialectCockroach
	}
	return dialectPostgres
}

func randomHandle() ([]byte, error) {
	b := make([]byte, handleBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

var _ webauthn.UserStore = (*UserStore)(nil)
