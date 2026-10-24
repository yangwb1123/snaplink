package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestClientStoreWithoutMigrations_DoesNotInitialize(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewClientStoreWithoutMigrations(db)
	var tables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("wrapper performed schema work: count=%d err=%v", tables, err)
	}
	if _, err := store.List(context.Background()); err == nil {
		t.Fatal("absent schema was accepted")
	}
	if _, err := NewClientStoreWithoutMigrations(nil).Get(context.Background(), "missing"); err == nil {
		t.Fatal("nil database was accepted")
	}
}

func legacyClientFixture(t *testing.T) (string, *core.Client) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewClientStoreWithDB(db)
	client := &core.Client{ID: "fixture-client", Secret: "fixture-only-secret", Name: "source é ", Active: true,
		RedirectURIs: []string{"https://fixture.invalid/callback"}, AllowedScopes: []string{"openid", "offline_access"},
		GrantTypes: []string{core.GrantAuthorizationCode, core.GrantRefreshToken},
		Attributes: map[string]string{"_snaplink_client_skip_consent": "true", "locale": "zh-CN"}}
	if err := store.Add(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	expected, err := store.Get(context.Background(), client.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"skip_consent", "consent_refresh_interval", "allow_passwordless_only"} {
		if _, err := db.Exec("ALTER TABLE clients DROP COLUMN " + column); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("DELETE FROM schema_migrations_clients WHERE version=9"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path, expected
}

func TestClientStoreWithoutMigrations_ReadOnlyProjectedLegacy(t *testing.T) {
	path, expected := legacyClientFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := NewClientStoreWithoutMigrations(db)
	if _, err := store.Get(context.Background(), expected.ID); err == nil {
		t.Fatal("missing policies were synthesized implicitly")
	}
	if _, err := db.Exec(`PRAGMA temp_store=MEMORY; CREATE TEMP VIEW clients AS SELECT clients.*,0 AS skip_consent,0 AS consent_refresh_interval,0 AS allow_passwordless_only FROM main.clients; PRAGMA query_only=ON;`); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), expected.ID)
	if err != nil || !reflect.DeepEqual(got, expected) {
		t.Fatal("full Get projection differs; values withheld")
	}
	all, err := store.List(context.Background())
	if err != nil || len(all) != 1 || !reflect.DeepEqual(all[0], expected) {
		t.Fatal("full List projection differs; values withheld")
	}
	if _, err := db.Exec("UPDATE main.clients SET name='forbidden'"); err == nil {
		t.Fatal("source write admitted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("immutable source changed")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Fatal("source sidecar created")
		}
	}
}

func TestClientStoreWithoutMigrations_CurrentSchemaKeepsOrdinaryValues(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	initialized := NewClientStoreWithDB(db)
	client := &core.Client{ID: "current", SkipConsent: true, AllowPasswordlessOnly: true, ConsentRefreshInterval: 17}
	if err := initialized.Add(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	want, err := initialized.Get(context.Background(), client.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewClientStoreWithoutMigrations(db).Get(context.Background(), client.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Fatal("existing policy values changed")
	}
}
