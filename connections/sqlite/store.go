// Package sqlite is the SQLite-backed connections.Store — the multi-replica
// durable peer of connections.MemoryStore. Suitable for a B2B deployment where
// every replica resolves home-realm discovery against the same database.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite" // register the "sqlite" driver name (pure-Go, no CGO).
)

const connectionSchema = `
CREATE TABLE IF NOT EXISTS connections (
    id           TEXT    PRIMARY KEY,
    tenant_id    TEXT    NOT NULL DEFAULT '',
    type         TEXT    NOT NULL DEFAULT '',
    display_name TEXT    NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 0,
    domains      TEXT    NOT NULL DEFAULT '[]',
    config       TEXT    NOT NULL DEFAULT '{}'
);

-- Domain routing index for home-realm discovery: one row per (lowercase)
-- domain -> connection. PRIMARY KEY enforces "a domain routes to one
-- connection" (last-write-wins via upsert).
CREATE TABLE IF NOT EXISTS connection_domains (
    domain        TEXT NOT NULL PRIMARY KEY,
    connection_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_connections_tenant ON connections(tenant_id);
`

var connectionMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: connectionSchema},
}

// Store is the SQLite connections.Store.
type Store struct {
	db *sql.DB
}

var _ connections.Store = (*Store)(nil)

// New opens dsn, migrates, and returns the store.
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "connections", connectionMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate connections: %w", err)
	}
	return &Store{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewWithDB(db *sql.DB) *Store {
	_ = migrate.Run(context.Background(), db, "connections", connectionMigrations)
	return &Store{db: db}
}

// Close releases the connection. Idempotent.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the *sql.DB for the storage-health schema reporter.
func (s *Store) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: connection store closed")
	}
	return s.db.PingContext(ctx)
}

func (s *Store) Get(ctx context.Context, id string) (*connections.Connection, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, type, display_name, enabled, domains, config FROM connections WHERE id = ?`, id)
	c, err := scanConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connections.ErrNoConnection
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get connection: %w", err)
	}
	return c, nil
}

func (s *Store) ByTenant(ctx context.Context, tenantID string) ([]*connections.Connection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, type, display_name, enabled, domains, config FROM connections WHERE tenant_id = ? ORDER BY id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*connections.Connection
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan connection: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ByDomain(ctx context.Context, emailDomain string) (*connections.Connection, error) {
	d := strings.ToLower(strings.TrimSpace(emailDomain))
	if d == "" {
		return nil, connections.ErrNoConnection
	}
	row := s.db.QueryRowContext(ctx, `
        SELECT c.id, c.tenant_id, c.type, c.display_name, c.enabled, c.domains, c.config
        FROM connections c
        JOIN connection_domains cd ON cd.connection_id = c.id
        WHERE cd.domain = ? AND c.enabled = 1`, d)
	c, err := scanConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connections.ErrNoConnection
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: by domain: %w", err)
	}
	return c, nil
}

func (s *Store) Upsert(ctx context.Context, c *connections.Connection) error {
	if c == nil || c.ID == "" {
		return errors.New("connections: id required")
	}
	domainsJSON, err := json.Marshal(c.Domains)
	if err != nil {
		return fmt.Errorf("sqlite: marshal domains: %w", err)
	}
	configJSON, err := json.Marshal(c.Config)
	if err != nil {
		return fmt.Errorf("sqlite: marshal config: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO connections (id, tenant_id, type, display_name, enabled, domains, config)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            tenant_id=excluded.tenant_id, type=excluded.type,
            display_name=excluded.display_name, enabled=excluded.enabled,
            domains=excluded.domains, config=excluded.config`,
		c.ID, c.TenantID, string(c.Type), c.DisplayName, boolToInt(c.Enabled),
		string(domainsJSON), string(configJSON)); err != nil {
		return fmt.Errorf("sqlite: upsert connection: %w", err)
	}
	// Rebuild this connection's domain routing: drop its old rows, then insert
	// the current set (re-claiming a domain reassigns it via the PK conflict).
	if _, err := tx.ExecContext(ctx, `DELETE FROM connection_domains WHERE connection_id = ?`, c.ID); err != nil {
		return fmt.Errorf("sqlite: clear domains: %w", err)
	}
	for _, dm := range c.Domains {
		nd := strings.ToLower(strings.TrimSpace(dm))
		if nd == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO connection_domains (domain, connection_id) VALUES (?, ?)
             ON CONFLICT(domain) DO UPDATE SET connection_id=excluded.connection_id`,
			nd, c.ID); err != nil {
			return fmt.Errorf("sqlite: index domain: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) Delete(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM connection_domains WHERE connection_id = ?`, id); err != nil {
		return fmt.Errorf("sqlite: delete domains: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM connections WHERE id = ?`, id); err != nil {
		return fmt.Errorf("sqlite: delete connection: %w", err)
	}
	return tx.Commit()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanConnection(sc scanner) (*connections.Connection, error) {
	var (
		c                            connections.Connection
		typ, domainsJSON, configJSON string
		enabled                      int
	)
	if err := sc.Scan(&c.ID, &c.TenantID, &typ, &c.DisplayName, &enabled, &domainsJSON, &configJSON); err != nil {
		return nil, err
	}
	c.Type = connections.ConnectionType(typ)
	c.Enabled = enabled != 0
	if domainsJSON != "" && domainsJSON != "[]" {
		if err := json.Unmarshal([]byte(domainsJSON), &c.Domains); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal domains: %w", err)
		}
	}
	if configJSON != "" && configJSON != "{}" {
		if err := json.Unmarshal([]byte(configJSON), &c.Config); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal config: %w", err)
		}
	}
	return &c, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
