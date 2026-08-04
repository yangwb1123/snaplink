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

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/platform/migrate"

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
	// v2 adds the per-(connection,domain) ownership-claim table backing DNS-TXT
	// domain verification. connection_domains stays the verified-only routing
	// index; connection_domain_claims tracks pending + verified claims.
	{Version: 2, Name: "domain_claims", SQL: connectionDomainClaimsSchema},
	// v3 adds the per-connection health table backing the admin-triggered
	// reachability probe (POST .../connections/:id/probe).
	{Version: 3, Name: "connection_health", SQL: connectionHealthSchema},
}

// Store is the SQLite connections.Store.
type Store struct {
	db  *sql.DB
	cfg connections.StoreConfig
}

var _ connections.Store = (*Store)(nil)

// New opens dsn, migrates, and returns the store. Options are variadic so the
// historical single-arg call sites keep compiling unchanged; with no options
// the store behaves byte-identically to the pre-verification build.
func New(dsn string, opts ...connections.StoreOption) (*Store, error) {
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
	return &Store{db: db, cfg: connections.ApplyStoreOptions(opts...)}, nil
}

// NewWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewWithDB(db *sql.DB, opts ...connections.StoreOption) *Store {
	_ = migrate.Run(context.Background(), db, "connections", connectionMigrations)
	return &Store{db: db, cfg: connections.ApplyStoreOptions(opts...)}
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
	return scanConnections(rows)
}

func (s *Store) List(ctx context.Context) ([]*connections.Connection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, type, display_name, enabled, domains, config FROM connections ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list connections: %w", err)
	}
	return scanConnections(rows)
}

func scanConnections(rows *sql.Rows) ([]*connections.Connection, error) {
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
	if err := s.reconcileDomainsTx(ctx, tx, c.ID, c.Domains); err != nil {
		return err
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
	// Without this, a deleted connection's domain-ownership claims (including
	// any VERIFIED one) survive in connection_domain_claims. Recreating a
	// connection with the SAME id later (a plausible admin "reset connection"
	// action) then hits ensureClaimTx's idempotent no-op branch — which finds
	// the stale row and leaves it untouched — so the new connection silently
	// inherits the old VERIFIED status without ever re-proving DNS control.
	// That defeats DomainVerificationRequired's anti-hijack guarantee for the
	// delete-then-recreate case. MemoryStore.Delete already purges the
	// equivalent claims map on delete; this brings the sqlite backend to the
	// same by-value, no-stale-state contract.
	if _, err := tx.ExecContext(ctx, `DELETE FROM connection_domain_claims WHERE connection_id = ?`, id); err != nil {
		return fmt.Errorf("sqlite: delete domain claims: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM connection_health WHERE connection_id = ?`, id); err != nil {
		return fmt.Errorf("sqlite: delete health: %w", err)
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
