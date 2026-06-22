package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// Dialect selects the small set of behaviors that differ between plain
// PostgreSQL and CockroachDB (advisory locks, serialization retry). The same
// SQL targets both; only the migrate runner branches.
type Dialect string

const (
	DialectPostgres  Dialect = "postgres"
	DialectCockroach Dialect = "cockroach"
)

// normalized maps "" (and any unknown value) to DialectPostgres, the default.
func (d Dialect) normalized() Dialect {
	if strings.EqualFold(string(d), string(DialectCockroach)) {
		return DialectCockroach
	}
	return DialectPostgres
}

// Config is the connection + pool configuration for the durable backend. One
// pool is shared across every store on a given DSN (built once, passed to each
// NewXxxStoreWithDB), mirroring the SQLite shared-pool pattern.
type Config struct {
	DSN     string
	Dialect Dialect // "" => postgres

	// Pool sizing. Behind a transaction-mode pooler (pgbouncer) keep MaxOpen
	// SMALL — the pooler multiplexes onto a tiny DB-side pool, and N replicas x
	// MaxOpen must stay under the DB max_connections. Set
	// default_query_exec_mode=simple_protocol in the DSN for pgbouncer tx mode
	// (server-side prepared statements are unavailable there).
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// Open dials the DSN with the pgx/v5 stdlib driver, applies the pool sizing,
// and verifies connectivity. The returned *sql.DB is the shared handle every
// store on this DSN uses; the caller owns Close.
func Open(cfg Config) (*sql.DB, error) {
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, errors.New("postgres: dsn required")
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return db, nil
}
