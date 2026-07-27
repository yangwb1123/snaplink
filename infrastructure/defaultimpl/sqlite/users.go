// Package sqlite provides SQLite-backed implementations of the SDK's
// storage SPIs. modernc.org/sqlite is pure Go (no CGO), so the
// resulting binaries stay compatible with the distroless/static
// runtime image and cross-compile without a C toolchain.
//
// Today only UserProvider is implemented — establishes the schema +
// migration + scan pattern that ClientStore, SessionManager, and
// audit Sink implementations will follow. Operators wanting full
// SQLite persistence can swap in user storage today and keep memory
// for the rest until the matching backends land.
//
// Connection lifecycle: callers own the *sql.DB. Pass any DSN
// modernc.org/sqlite accepts — file:/var/lib/sso/sso.db, :memory:
// for tests, file::memory:?cache=shared for cross-goroutine tests
// sharing one in-memory database.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"

	_ "modernc.org/sqlite" // register the "sqlite" driver name.
)

// userSchema is applied at NewUserProvider time via CREATE-IF-NOT-EXISTS.
// Migration framework deferred — for v1 the single table is stable;
// future schema changes can layer on a real migration runner without
// rewriting the existing data layout.
//
// Timestamps stored as INTEGER (Unix NANOSECONDS) — SQLite has no
// native timestamp type and integer-vs-text is faster for the
// index-friendly queries we expect. Nanos rather than seconds so
// roundtrip preserves precision (Go's time.Time has nanosecond
// resolution; truncating loses CreatedAt vs UpdatedAt distinction
// in fast-write test scenarios).
const userSchema = `
CREATE TABLE IF NOT EXISTS users (
    id          TEXT    PRIMARY KEY,
    external_id TEXT,
    provider    TEXT,
    email       TEXT,
    name        TEXT,
    attributes  TEXT    NOT NULL DEFAULT '{}',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_provider_external
    ON users(provider, external_id)
    WHERE provider IS NOT NULL AND external_id IS NOT NULL;
`

// UserProvider is the SQLite-backed implementation of [sso.UserProvider].
type UserProvider struct {
	db *sql.DB
}

// NewUserProvider opens the SQLite DB at dsn, runs the schema migration,
// and returns a ready-to-use UserProvider. The DB is owned by the
// provider — call Close to release it.
//
// dsn examples:
//
//	file:/var/lib/sso/sso.db?_journal=WAL&_pragma=busy_timeout(5000)   # production
//	:memory:                                                    # tests (per-conn)
//	file::memory:?cache=shared                                  # tests sharing one db
func NewUserProvider(dsn string) (*UserProvider, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "users", userSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate: %w", err)
	}
	return &UserProvider{db: db}, nil
}

// NewUserProviderWithDB wraps an existing *sql.DB. Use when the
// operator manages connection lifecycle (shared pool across multiple
// SQLite-backed providers, custom dial options, test injection).
// Caller is responsible for the schema migration AND for closing the
// DB — the provider's Close becomes a no-op.
func NewUserProviderWithDB(db *sql.DB) *UserProvider {
	return &UserProvider{db: db}
}

// Close releases the SQLite connection. Idempotent — safe to call
// multiple times.
func (p *UserProvider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	err := p.db.Close()
	p.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring. cmd registers this so /readyz flips to 503 on connection
// loss (mount went read-only, file deleted underneath us, etc.).
//
// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (p *UserProvider) DB() *sql.DB { return p.db }

func (p *UserProvider) Ping(ctx context.Context) error {
	if p == nil || p.db == nil {
		return errors.New("sqlite: user provider closed")
	}
	return p.db.PingContext(ctx)
}

// GetByID implements [sso.UserProvider].
func (p *UserProvider) GetByID(ctx context.Context, id string) (*sso.User, error) {
	row := p.db.QueryRowContext(ctx, `
        SELECT id, external_id, provider, email, name, attributes, created_at, updated_at
        FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrNoSuchUser
	}
	return u, err
}

// GetByExternalID implements [sso.UserProvider].
func (p *UserProvider) GetByExternalID(ctx context.Context, provider, externalID string) (*sso.User, error) {
	row := p.db.QueryRowContext(ctx, `
        SELECT id, external_id, provider, email, name, attributes, created_at, updated_at
        FROM users WHERE provider = ? AND external_id = ?`, provider, externalID)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrNoSuchUser
	}
	return u, err
}

// CreateOrUpdate implements [sso.UserProvider]. ON CONFLICT(id) updates
// every column except CreatedAt (preserved from the original insert,
// matching the documented contract that CreateOrUpdate is upsert
// semantics).
func (p *UserProvider) CreateOrUpdate(ctx context.Context, u *sso.User) error {
	if u == nil || u.ID == "" {
		return errors.New("sqlite: user.ID required")
	}
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal attributes: %w", err)
	}
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now

	_, err = p.db.ExecContext(ctx, `
        INSERT INTO users (id, external_id, provider, email, name, attributes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            external_id = excluded.external_id,
            provider    = excluded.provider,
            email       = excluded.email,
            name        = excluded.name,
            attributes  = excluded.attributes,
            updated_at  = excluded.updated_at`,
		u.ID, nullable(u.ExternalID), nullable(u.Provider),
		nullable(u.Email), nullable(u.Name),
		string(attrs), u.CreatedAt.UnixNano(), u.UpdatedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: upsert: %w", err)
	}
	return nil
}

// List implements [sso.UserProvider]. No pagination — caller's job per
// the interface contract. Order: ascending id (stable, cheap via the
// PRIMARY KEY index).
func (p *UserProvider) List(ctx context.Context) ([]*sso.User, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT id, external_id, provider, email, name, attributes, created_at, updated_at
        FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*sso.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: list rows: %w", err)
	}
	return out, nil
}

// Delete implements [sso.UserProvider]. Idempotent — missing ids
// return nil (matches the interface contract documented in user.go).
func (p *UserProvider) Delete(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete: %w", err)
	}
	return nil
}

// scanner is the subset of *sql.Row and *sql.Rows we need. Lets one
// scanUser handle both single-row and multi-row paths.
type scanner interface {
	Scan(dest ...any) error
}

func scanUser(s scanner) (*sso.User, error) {
	var (
		u                                sso.User
		externalID, provider             sql.NullString
		email, name                      sql.NullString
		attrs                            string
		createdAtUnixNs, updatedAtUnixNs int64
	)
	if err := s.Scan(
		&u.ID, &externalID, &provider, &email, &name,
		&attrs, &createdAtUnixNs, &updatedAtUnixNs,
	); err != nil {
		return nil, err
	}
	u.ExternalID = externalID.String
	u.Provider = provider.String
	u.Email = email.String
	u.Name = name.String
	u.CreatedAt = time.Unix(0, createdAtUnixNs).UTC()
	u.UpdatedAt = time.Unix(0, updatedAtUnixNs).UTC()
	if attrs != "" && attrs != "{}" {
		if err := json.Unmarshal([]byte(attrs), &u.Attributes); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal attributes: %w", err)
		}
	}
	return &u, nil
}

// nullable converts an empty string to sql.NullString{Valid:false}
// so NULL is what hits the database (cleaner indexes than empty
// strings — the partial index on (provider, external_id) skips rows
// where either is NULL).
func nullable(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// Compile-time interface assertion.
var _ sso.UserProvider = (*UserProvider)(nil)
