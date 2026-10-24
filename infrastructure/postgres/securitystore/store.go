// Package securitystore implements durable security SPIs on an owned shared PostgreSQL pool.
package securitystore

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"time"

	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

type store struct {
	db     *sql.DB
	closed atomic.Bool
}

func openStore(db *sql.DB, dialect pg.Dialect, namespace string, migrations []migrate.Migration) (*store, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres security: shared pool required")
	}
	if dialect != "" && dialect != pg.DialectPostgres {
		return nil, fmt.Errorf("postgres security: dialect %q unsupported", dialect)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pg.CheckSchema(ctx, db, namespace, migrate.MaxVersion(migrations)); err != nil {
		return nil, err
	}
	if err := pg.Run(ctx, db, namespace, migrations, dialect); err != nil {
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) pool() (*sql.DB, error) {
	if s == nil || s.closed.Load() {
		return nil, fmt.Errorf("postgres security: store closed")
	}
	return s.db, nil
}

// Close retires this adapter, not the caller-owned shared connection pool.
func (s *store) Close() error {
	if s != nil {
		s.closed.Store(true)
	}
	return nil
}

func (s *store) DB() *sql.DB {
	db, _ := s.pool()
	return db
}

func (s *store) Ping(ctx context.Context) error {
	db, err := s.pool()
	if err != nil {
		return err
	}
	return db.PingContext(ctx)
}
