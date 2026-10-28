package serverbuildsign

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/internal/pgtest"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type healthDBStub struct {
	db *sql.DB
}

func (s healthDBStub) Ping(context.Context) error { return nil }
func (s healthDBStub) DB() *sql.DB                { return s.db }

func TestAppendStorageHealthSourceIsDialectSafe(t *testing.T) {
	sqliteDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqliteDB.Close() })
	sqliteSources := AppendStorageHealthSource(nil, "sqlite", healthDBStub{db: sqliteDB})
	if len(sqliteSources) != 1 || sqliteSources[0].SchemaVersions == nil {
		t.Fatalf("sqlite source = %+v; want schema reporter", sqliteSources)
	}

	postgresDB, err := sql.Open("pgx", "postgres://invalid")
	if err != nil {
		t.Fatalf("open pgx: %v", err)
	}
	t.Cleanup(func() { _ = postgresDB.Close() })
	postgresSources := AppendStorageHealthSource(nil, "postgres", healthDBStub{db: postgresDB})
	if len(postgresSources) != 1 || postgresSources[0].SchemaVersions != nil {
		t.Fatalf("postgres source = %+v; want Ping-only", postgresSources)
	}
}

func TestCheckSQLiteSchemaSkipsPostgresDialect(t *testing.T) {
	db, err := postgres.Open(postgres.Config{DSN: pgtest.Schema(t), MaxOpenConns: 2})
	if err != nil {
		t.Fatal("open isolated PostgreSQL")
	}
	t.Cleanup(func() { _ = db.Close() })
	sessions, err := postgres.NewSessionManagerWithDB(db, postgres.DialectPostgres, time.Hour)
	if err != nil {
		t.Fatal("construct PostgreSQL sessions")
	}
	tenants, err := postgres.NewTenantStoreWithDB(db, postgres.DialectPostgres)
	if err != nil {
		t.Fatal("construct PostgreSQL tenants")
	}
	for _, test := range []struct {
		name  string
		store any
	}{{"sessions", sessions}, {"tenant", tenants}} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckSQLiteSchema(t.Context(), test.store, test.name, 1); err != nil {
				t.Fatalf("SQLite-only helper queried real PostgreSQL: %v", err)
			}
		})
	}
}
