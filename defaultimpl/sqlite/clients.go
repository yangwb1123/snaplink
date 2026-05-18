package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/snaplink/sso"

	_ "modernc.org/sqlite"
)

// clientSchema mirrors the in-memory shape — slices + maps are
// JSON blobs since the SDK only ever reads whole rows, never WHERE
// clauses over their internals. The tenant_id index is for
// ListByTenant; otherwise lookups are by id only.
const clientSchema = `
CREATE TABLE IF NOT EXISTS clients (
    id                      TEXT    PRIMARY KEY,
    secret                  TEXT    NOT NULL,
    name                    TEXT    NOT NULL DEFAULT '',
    redirect_uris           TEXT    NOT NULL DEFAULT '[]',
    allowed_scopes          TEXT    NOT NULL DEFAULT '[]',
    allowed_authenticators  TEXT    NOT NULL DEFAULT '[]',
    token_strategy          TEXT    NOT NULL DEFAULT '',
    active                  INTEGER NOT NULL DEFAULT 1,
    tenant_id               TEXT    NOT NULL DEFAULT '',
    require_pkce            INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_clients_tenant
    ON clients(tenant_id)
    WHERE tenant_id <> '';
`

// ClientStore is the SQLite-backed [sso.ClientStore], including the
// optional [sso.TenantScopedClientStore] extension via the
// idx_clients_tenant partial index.
type ClientStore struct {
	db *sql.DB
}

func NewClientStore(dsn string) (*ClientStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), clientSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate clients: %w", err)
	}
	return &ClientStore{db: db}, nil
}

func NewClientStoreWithDB(db *sql.DB) *ClientStore {
	return &ClientStore{db: db}
}

func (s *ClientStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *ClientStore) Get(ctx context.Context, clientID string) (*sso.Client, error) {
	row := s.db.QueryRowContext(ctx, clientSelectByCol("id"), clientID)
	c, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrNoSuchClient
	}
	return c, err
}

func (s *ClientStore) ValidateSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.Get(ctx, clientID)
	if err != nil {
		return err
	}
	if c.Secret != clientSecret {
		return errors.New("invalid client secret")
	}
	return nil
}

// List returns every registered client. Order: ascending id (stable,
// cheap via the PRIMARY KEY index).
func (s *ClientStore) List(ctx context.Context) ([]*sso.Client, error) {
	rows, err := s.db.QueryContext(ctx, clientSelectAll()+" ORDER BY id ASC")
	if err != nil {
		return nil, fmt.Errorf("sqlite: list clients: %w", err)
	}
	defer rows.Close()
	var out []*sso.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListByTenant implements [sso.TenantScopedClientStore] using the
// partial index — empty tenant_id rows aren't indexed (they belong
// to no tenant) so a tenant-scoped read never touches them.
func (s *ClientStore) ListByTenant(ctx context.Context, tenantID string) ([]*sso.Client, error) {
	rows, err := s.db.QueryContext(ctx, clientSelectByCol("tenant_id")+" ORDER BY id ASC", tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list by tenant: %w", err)
	}
	defer rows.Close()
	var out []*sso.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *ClientStore) Add(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO clients (id, secret, name, redirect_uris, allowed_scopes,
            allowed_authenticators, token_strategy, active, tenant_id, require_pkce)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
	)
	if err != nil {
		// modernc.org/sqlite returns the constraint code in the error
		// message; UNIQUE on PRIMARY KEY → ErrClientExists per contract.
		if isUniqueViolation(err) {
			return sso.ErrClientExists
		}
		return fmt.Errorf("sqlite: insert client: %w", err)
	}
	return nil
}

func (s *ClientStore) Update(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("sqlite: client.ID required")
	}
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	res, err := s.db.ExecContext(ctx, `
        UPDATE clients SET secret = ?, name = ?, redirect_uris = ?,
            allowed_scopes = ?, allowed_authenticators = ?,
            token_strategy = ?, active = ?, tenant_id = ?, require_pkce = ?
        WHERE id = ?`,
		c.Secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
		c.ID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sso.ErrNoSuchClient
	}
	return nil
}

// Delete is idempotent — missing ids return nil (matches the
// interface contract).
func (s *ClientStore) Delete(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("sqlite: delete client: %w", err)
	}
	return nil
}

func (s *ClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	secret, err := generateClientSecret()
	if err != nil {
		return "", err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE clients SET secret = ? WHERE id = ?`, secret, clientID)
	if err != nil {
		return "", fmt.Errorf("sqlite: rotate secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sso.ErrNoSuchClient
	}
	return secret, nil
}

// clientSelectAll keeps the column list in one place so Add / Update /
// scan can't drift.
func clientSelectAll() string {
	return `SELECT id, secret, name, redirect_uris, allowed_scopes,
        allowed_authenticators, token_strategy, active, tenant_id, require_pkce
        FROM clients`
}

func clientSelectByCol(col string) string {
	return clientSelectAll() + ` WHERE ` + col + ` = ?`
}

func scanClient(s scanner) (*sso.Client, error) {
	var (
		c                                     sso.Client
		redirects, scopes, auths              string
		activeInt, requirePKCEInt             int64
		secret, name, tokenStrategy, tenantID string
	)
	if err := s.Scan(
		&c.ID, &secret, &name,
		&redirects, &scopes, &auths,
		&tokenStrategy, &activeInt, &tenantID, &requirePKCEInt,
	); err != nil {
		return nil, err
	}
	c.Secret = secret
	c.Name = name
	c.TokenStrategy = tokenStrategy
	c.TenantID = tenantID
	c.Active = activeInt != 0
	c.RequirePKCE = requirePKCEInt != 0
	if redirects != "" && redirects != "[]" {
		if err := json.Unmarshal([]byte(redirects), &c.RedirectURIs); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal redirect_uris: %w", err)
		}
	}
	if scopes != "" && scopes != "[]" {
		if err := json.Unmarshal([]byte(scopes), &c.AllowedScopes); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal allowed_scopes: %w", err)
		}
	}
	if auths != "" && auths != "[]" {
		if err := json.Unmarshal([]byte(auths), &c.AllowedAuthenticators); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal allowed_authenticators: %w", err)
		}
	}
	return &c, nil
}

// generateClientSecret matches defaultimpl.MemoryClientStore — 32-byte
// base64url ≈ 256 bits of entropy.
func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sqlite: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// isUniqueViolation reports whether err is a SQLite UNIQUE-constraint
// violation. modernc.org/sqlite returns SQLITE_CONSTRAINT_PRIMARYKEY
// or SQLITE_CONSTRAINT_UNIQUE — both rendered as part of the message
// in the absence of a typed code we can switch on without CGO.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE constraint") ||
		strings.Contains(s, "PRIMARY KEY") ||
		strings.Contains(s, "constraint failed")
}

var (
	_ sso.ClientStore             = (*ClientStore)(nil)
	_ sso.TenantScopedClientStore = (*ClientStore)(nil)
)
