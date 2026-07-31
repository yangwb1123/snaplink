package serverbuildsign

import (
	"context"
	"database/sql"
	"testing"

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
