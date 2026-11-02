package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/internal/pgtest"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestBuildAppSessionSchemaBackends(t *testing.T) {
	cases := []struct {
		name, identity, sessions string
	}{
		{"inherited-postgres", "postgres", ""},
		{"memory-with-postgres-sessions", "memory", "postgres"},
		{"sqlite-with-postgres-sessions", "sqlite", "postgres"},
		{"normalized-postgres-override", "memory", " POSTGRES "},
		{"postgres-with-sqlite-sessions", "postgres", "sqlite"},
		{"memory-with-sqlite-sessions", "memory", "sqlite"},
		{"default-memory-sessions", "memory", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sessionSchemaConfig(t, tc.identity, tc.sessions)
			a := openSessionSchemaApp(t, cfg)
			session, err := a.sessionMgr.Create(t.Context(), "schema-test-user")
			if err != nil {
				t.Fatal(err)
			}
			got, err := a.sessionMgr.Get(t.Context(), session.ID)
			if err != nil || got.UserID != session.UserID {
				t.Fatalf("session round trip = (%+v, %v)", got, err)
			}
			handler, err := buildHTTPHandler(cfg, a, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("readiness = %d: %s", response.Code, response.Body.String())
			}
		})
	}
}

func sessionSchemaConfig(t *testing.T, identity, sessions string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Identity.Backend = identity
	cfg.Identity.SessionBackend = sessions
	cfg.Identity.SQLite.DSN = "file:" + filepath.Join(t.TempDir(), "identity.db")
	cfg.Server.SessionTTL = time.Hour
	if identity == "postgres" || strings.EqualFold(strings.TrimSpace(sessions), "postgres") {
		cfg.Postgres.DSN = pgtest.Schema(t)
		cfg.Postgres.MaxOpenConns = 2
	}
	return cfg
}

func openSessionSchemaApp(t *testing.T, cfg *config.Config) *app {
	t.Helper()
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	t.Cleanup(func() { closeSessionSchemaApp(t, a) })
	return a
}

func closeSessionSchemaApp(t *testing.T, a *app) {
	t.Helper()
	shutdownApp(t, a)
	for _, store := range []any{a.sessionMgr, a.userProvider, a.clientStore} {
		if closer, ok := store.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	if a.pgDB != nil {
		_ = a.pgDB.Close()
	}
}

func TestBuildAppSessionSchemaRejectsAheadPostgres(t *testing.T) {
	cfg := sessionSchemaConfig(t, "memory", "postgres")
	db, err := postgresbackend.Open(postgresbackend.Config{DSN: cfg.Postgres.DSN})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := postgresbackend.NewSessionManagerWithDB(db, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(t.Context(), "preserved-user")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	version, err := postgresbackend.CurrentVersion(t.Context(), db, "sessions")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(t.Context(), `INSERT INTO schema_migrations_sessions
		(version, name, applied_at) VALUES ($1, 'future', 0)`, version+1)
	if err != nil {
		t.Fatal(err)
	}
	assertSessionSchemaBootRejected(t, cfg)
	after, err := store.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected boot changed session: (%+v, %v)", after, err)
	}
	live, err := postgresbackend.CurrentVersion(t.Context(), db, "sessions")
	if err != nil || live != version+1 {
		t.Fatalf("rejected boot changed schema version: (%d, %v)", live, err)
	}
}

func TestBuildAppSessionSchemaRejectsAheadSQLite(t *testing.T) {
	cfg := sessionSchemaConfig(t, "memory", "sqlite")
	store, err := sqlitestores.NewSessionManager(cfg.Identity.SQLite.DSN, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	created, err := store.Create(t.Context(), "preserved-user")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	version := sqlitestores.SessionsMaxVersion() + 1
	stampSchemaVersion(t, store, "schema_migrations_sessions", version)
	assertSessionSchemaBootRejected(t, cfg)
	after, err := store.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected boot changed session: (%+v, %v)", after, err)
	}
	live, err := migrate.CurrentVersion(t.Context(), store.DB(), "sessions")
	if err != nil || live != version {
		t.Fatalf("rejected boot changed schema version: (%d, %v)", live, err)
	}
}

func assertSessionSchemaBootRejected(t *testing.T, cfg *config.Config) {
	t.Helper()
	a, err := buildApp(cfg, quietLogger())
	if a != nil {
		closeSessionSchemaApp(t, a)
		t.Fatal("app returned against an unsupported session schema")
	}
	if !errors.Is(err, migrate.ErrSchemaTooNew) {
		t.Fatalf("boot error = %v; want ErrSchemaTooNew", err)
	}
	if !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("boot error does not identify the session namespace: %v", err)
	}
}

func TestStoreSchemaUnsupportedBackendFailsClosed(t *testing.T) {
	b := &appBuilder{schemaCtx: t.Context()}
	err := b.checkStoreSchema("unimplemented", "sessions", struct{}{}, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("unsupported backend error = %v; want a namespaced error", err)
	}
}

func TestStoreSchemaNonSQLBackends(t *testing.T) {
	for _, backend := range []string{"", "memory", "redis"} {
		t.Run(backend, func(t *testing.T) {
			b := &appBuilder{schemaCtx: t.Context()}
			if err := b.checkStoreSchema(backend, "sessions", struct{}{}, 0, 0); err != nil {
				t.Fatalf("non-SQL schema check: %v", err)
			}
		})
	}
}

func TestBuildAppPostgresSessionSurvivesRebuild(t *testing.T) {
	cfg := sessionSchemaConfig(t, "memory", "postgres")
	first := openSessionSchemaApp(t, cfg)
	creator, ok := first.sessionMgr.(core.SessionMetaCreator)
	if !ok {
		t.Fatal("session manager does not support security metadata")
	}
	before, err := creator.CreateWithMeta(context.Background(), "persistent-user", core.SessionMeta{
		TenantID: "tenant-a", ClientID: "client-a", DeviceID: "device-a",
		AuthorizedScopes: []string{"openid", "offline_access"},
		AuthTime:         time.Now().UTC().Add(-time.Minute).Truncate(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err = first.sessionMgr.Get(t.Context(), before.ID)
	if err != nil {
		t.Fatal(err)
	}
	closeSessionSchemaApp(t, first)
	second := openSessionSchemaApp(t, cfg)
	after, err := second.sessionMgr.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("session changed after rebuild: before=%+v after=%+v err=%v", before, after, err)
	}
}
