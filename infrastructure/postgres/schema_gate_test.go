package postgres

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
)

func TestPostgresMigrationRejectsInvalidOrder(t *testing.T) {
	for name, migrations := range map[string][]migrate.Migration{
		"descending": {{Version: 2}, {Version: 1}},
		"duplicate":  {{Version: 1}, {Version: 1}},
		"zero":       {{Version: 0}},
		"negative":   {{Version: -1}},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("invalid migration ordering reached SQL instead of input validation")
				}
			}()
			err := Run(t.Context(), nil, "invalid_order_fixture", migrations, DialectPostgres)
			if err == nil || errors.Is(err, migrate.ErrSchemaTooNew) || !strings.Contains(err.Error(), "strictly increasing") {
				t.Fatalf("malformed migration inventory error=%v, want input-order rejection", err)
			}
		})
	}
}

func TestPostgresMigrationAllowsOrderedGaps(t *testing.T) {
	cfg := testConfig(t)
	db, err := Open(cfg)
	if err != nil {
		t.Fatal("open ordered migration fixture")
	}
	t.Cleanup(func() { _ = db.Close() })
	migrations := []migrate.Migration{
		{Version: 1, Name: "initial", SQL: "CREATE TABLE ordered_gap_fixture (id TEXT PRIMARY KEY)"},
		{Version: 3, Name: "next", SQL: "ALTER TABLE ordered_gap_fixture ADD COLUMN label TEXT"},
	}
	for range 2 {
		if err := Run(t.Context(), db, "ordered_gap_fixture", migrations, cfg.Dialect); err != nil {
			t.Fatal("valid positive ordered migrations with a version gap were rejected")
		}
	}
	if version, err := CurrentVersion(t.Context(), db, "ordered_gap_fixture"); err != nil || version != 3 {
		t.Fatal("ordered gap inventory did not migrate idempotently to its native maximum")
	}
}

func TestPostgresStoreConstructorsRejectAheadSchema(t *testing.T) {
	cfg := testConfig(t)
	db, err := Open(cfg)
	if err != nil {
		t.Fatal("open isolated PostgreSQL schema gate fixture")
	}
	t.Cleanup(func() { _ = db.Close() })
	constructors := []struct {
		namespace string
		open      func() error
	}{
		{"sessions", func() error { _, err := NewSessionManagerWithDB(db, cfg.Dialect, time.Hour); return err }},
		{"users", func() error { _, err := NewUserProviderWithDB(db, cfg.Dialect); return err }},
		{"clients", func() error { _, err := NewClientStoreWithDB(db, cfg.Dialect); return err }},
		{"tenant", func() error { _, err := NewTenantStoreWithDB(db, cfg.Dialect); return err }},
		{"password_credentials", func() error { _, err := NewPasswordCredentialStoreWithDB(db, cfg.Dialect); return err }},
	}
	for _, factory := range constructors {
		t.Run(factory.namespace, func(t *testing.T) {
			if err := factory.open(); err != nil {
				t.Fatal("initial native store migration failed")
			}
			current, err := CurrentVersion(t.Context(), db, factory.namespace)
			if err != nil || current <= 0 {
				t.Fatal("native store migration not recorded")
			}
			query := fmt.Sprintf("INSERT INTO schema_migrations_%s(version, name, applied_at) VALUES($1, $2, $3)", factory.namespace)
			if _, err := db.ExecContext(t.Context(), query, current+1, "future-binary-fixture", time.Now().UnixNano()); err != nil {
				t.Fatal("inject isolated ahead-schema fixture")
			}
			if err := factory.open(); !errors.Is(err, migrate.ErrSchemaTooNew) {
				t.Fatalf("forward-migrated constructor error=%v, want ErrSchemaTooNew", err)
			}
			live, err := CurrentVersion(t.Context(), db, factory.namespace)
			if err != nil || live != current+1 {
				t.Fatal("refused constructor changed forward schema version")
			}
		})
	}
}
