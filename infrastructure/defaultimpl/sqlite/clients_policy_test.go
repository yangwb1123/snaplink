package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

func assertClientLoginPolicy(t *testing.T, got, want *sso.Client) {
	t.Helper()
	if got.SkipConsent != want.SkipConsent || got.ConsentRefreshInterval != want.ConsentRefreshInterval ||
		got.AllowPasswordlessOnly != want.AllowPasswordlessOnly {
		t.Fatal("client login policy did not round-trip")
	}
}

func TestSQLiteClients_LoginPoliciesPersistAllWritePaths(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "clients.db")
	store, err := NewClientStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	client := &sso.Client{ID: "policy", TenantID: "tenant", Active: true, SkipConsent: true,
		ConsentRefreshInterval: 37 * time.Minute, AllowPasswordlessOnly: true,
		Attributes: map[string]string{"operator": "retained"}}
	for _, write := range []func(context.Context, *sso.Client) error{store.Add, store.Update, store.Put} {
		if err := write(ctx, client); err != nil {
			t.Fatal(err)
		}
		reader, err := NewClientStore(dsn)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reader.Get(ctx, client.ID)
		if err != nil {
			t.Fatal(err)
		}
		assertClientLoginPolicy(t, got, client)
		for _, list := range []func(context.Context) ([]*sso.Client, error){reader.List,
			func(ctx context.Context) ([]*sso.Client, error) { return reader.ListByTenant(ctx, "tenant") }} {
			rows, err := list(ctx)
			if err != nil || len(rows) != 1 {
				t.Fatal("client listing failed")
			}
			assertClientLoginPolicy(t, rows[0], client)
		}
		if got.Attributes["operator"] != "retained" {
			t.Fatal("operator attributes were lost")
		}
		_ = reader.Close()
		client.SkipConsent = !client.SkipConsent
		client.AllowPasswordlessOnly = !client.AllowPasswordlessOnly
		client.ConsentRefreshInterval /= 2
	}
}

func TestSQLiteClients_LoginPolicyMigrationKeepsLegacyDefaults(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := migrate.Run(ctx, db, "clients", clientMigrations[:8]); err != nil {
		t.Fatal(err)
	}
	// Legacy editable metadata cannot be promoted to an authorization policy.
	_, err = db.ExecContext(ctx, `INSERT INTO clients (id, secret, attributes) VALUES ('legacy', '',
		'{"_snaplink_client_skip_consent":"true","_snaplink_client_allow_passwordless_only":"true","skip_consent":"true"}')`)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewClientStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	got, err := store.Get(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	assertClientLoginPolicy(t, got, &sso.Client{})
}
