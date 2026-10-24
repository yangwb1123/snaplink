package securitystore

import (
	"database/sql"
	"os"
	"testing"

	pg "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/internal/pgtest"
)

func fixture(t *testing.T) (*sql.DB, string) {
	t.Helper()
	if os.Getenv("SSO_TEST_POSTGRES_DSN") == "" {
		t.Fatal("owned PostgreSQL fixture required; security coverage may not skip")
	}
	dsn := pgtest.Schema(t)
	return openPool(t, dsn), dsn
}

func openPool(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := pg.Open(pg.Config{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func scalar(t *testing.T, db *sql.DB, query string, args ...any) int64 {
	t.Helper()
	var value int64
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func exec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}
