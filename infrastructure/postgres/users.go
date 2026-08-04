package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

// userSchema is the baseline users table (Postgres dialect). One row per id.
// CreateOrUpdate upserts via ON CONFLICT(id), preserving created_at while
// refreshing every other column. attributes is a JSON object stored as TEXT;
// created_at / updated_at are Unix nanoseconds in BIGINT columns (NOT
// timestamptz — preserves the exact nanosecond round-trip the SQLite peer
// relies on). external_id / provider / email / name are NULL when empty so the
// partial index skips rows lacking a (provider, external_id) pair.
const userSchema = `
CREATE TABLE IF NOT EXISTS users (
    id          TEXT   PRIMARY KEY,
    external_id TEXT,
    provider    TEXT,
    email       TEXT,
    name        TEXT,
    attributes  TEXT   NOT NULL DEFAULT '{}',
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_provider_external
    ON users(provider, external_id)
    WHERE provider IS NOT NULL AND external_id IS NOT NULL;
`

var userMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: userSchema},
	{Version: 2, Name: "scim_username_unique", SQL: `
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_username
    ON users(lower((attributes::jsonb ->> 'scim:userName')))
    WHERE (attributes::jsonb ->> 'scim:userName') IS NOT NULL;
`},
}

// UserProvider is the Postgres-backed implementation of [core.UserProvider].
type UserProvider struct {
	db      *sql.DB
	dialect Dialect
}

// NewUserProvider opens cfg.DSN, migrates the schema, and returns the store.
func NewUserProvider(cfg Config) (*UserProvider, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewUserProviderWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewUserProviderWithDB wraps an existing shared *sql.DB. The caller owns the
// connection lifecycle (shared-pool deployments).
func NewUserProviderWithDB(db *sql.DB, dialect Dialect) (*UserProvider, error) {
	if err := Run(context.Background(), db, "users", userMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate users: %w", err)
	}
	return &UserProvider{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool store built via
// NewUserProviderWithDB should be closed by whoever owns the pool, not here —
// but Close is safe either way (database/sql Close is idempotent).
func (p *UserProvider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	err := p.db.Close()
	p.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (p *UserProvider) DB() *sql.DB { return p.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (p *UserProvider) Ping(ctx context.Context) error {
	if p == nil || p.db == nil {
		return errors.New("postgres: user provider closed")
	}
	return p.db.PingContext(ctx)
}

// GetByID implements [core.UserProvider].
func (p *UserProvider) GetByID(ctx context.Context, id string) (*core.User, error) {
	row := p.db.QueryRowContext(ctx, `
        SELECT id, external_id, provider, email, name, attributes, created_at, updated_at
          FROM users WHERE id = $1`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrNoSuchUser
	}
	return u, err
}

// GetByExternalID implements [core.UserProvider].
func (p *UserProvider) GetByExternalID(ctx context.Context, provider, externalID string) (*core.User, error) {
	row := p.db.QueryRowContext(ctx, `
        SELECT id, external_id, provider, email, name, attributes, created_at, updated_at
          FROM users WHERE provider = $1 AND external_id = $2`, provider, externalID)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrNoSuchUser
	}
	return u, err
}

// CreateOrUpdate implements [core.UserProvider]. ON CONFLICT(id) updates every
// column except created_at (preserved from the original insert, matching the
// documented upsert contract).
func (p *UserProvider) CreateOrUpdate(ctx context.Context, u *core.User) error {
	if u == nil || u.ID == "" {
		return errors.New("postgres: user.ID required")
	}
	attrs, err := json.Marshal(u.Attributes)
	if err != nil {
		return fmt.Errorf("postgres: marshal attributes: %w", err)
	}
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now

	_, err = p.db.ExecContext(ctx, `
        INSERT INTO users (id, external_id, provider, email, name, attributes, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO UPDATE SET
            external_id = EXCLUDED.external_id,
            provider    = EXCLUDED.provider,
            email       = EXCLUDED.email,
            name        = EXCLUDED.name,
            attributes  = EXCLUDED.attributes,
            updated_at  = EXCLUDED.updated_at`,
		u.ID, nullable(u.ExternalID), nullable(u.Provider),
		nullable(u.Email), nullable(u.Name),
		string(attrs), u.CreatedAt.UnixNano(), u.UpdatedAt.UnixNano())
	if err != nil {
		if isUniqueViolation(err) {
			return core.ErrUserExists
		}
		return fmt.Errorf("postgres: upsert user: %w", err)
	}
	return nil
}

// List implements [core.UserProvider]. No pagination — caller's job per the
// interface contract. Order: ascending id (stable, cheap via the PRIMARY KEY).
func (p *UserProvider) List(ctx context.Context) ([]*core.User, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT id, external_id, provider, email, name, attributes, created_at, updated_at
          FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*core.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows iter: %w", err)
	}
	return out, nil
}

// ListPaginated implements [core.UserPaginationProvider] with database-native
// COUNT/LIMIT/OFFSET so admin pages do not materialize the whole directory.
func (p *UserProvider) ListPaginated(ctx context.Context, offset, limit int) ([]*core.User, int, error) {
	var total int
	if err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("postgres: count users: %w", err)
	}
	offset, limit = normalizeUserPage(offset, limit)
	rows, err := p.db.QueryContext(ctx, `
        SELECT id, external_id, provider, email, name, attributes, created_at, updated_at
          FROM users ORDER BY id ASC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("postgres: list paginated: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*core.User, 0, limit)
	for rows.Next() {
		u, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("postgres: scan paginated user: %w", scanErr)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("postgres: paginated rows: %w", err)
	}
	return out, total, nil
}

func normalizeUserPage(offset, limit int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	return offset, limit
}

// Delete implements [core.UserProvider]. Idempotent — missing ids return nil.
func (p *UserProvider) Delete(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete user: %w", err)
	}
	return nil
}

func scanUser(s scanner) (*core.User, error) {
	var (
		u                                core.User
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
			return nil, fmt.Errorf("postgres: unmarshal attributes: %w", err)
		}
	}
	return &u, nil
}

// nullable converts an empty string to sql.NullString{Valid:false} so NULL
// hits the database (cleaner indexes than empty strings — the partial index on
// (provider, external_id) skips rows where either is NULL).
func nullable(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// Compile-time interface assertion.
var _ core.UserProvider = (*UserProvider)(nil)
var _ core.UserPaginationProvider = (*UserProvider)(nil)
