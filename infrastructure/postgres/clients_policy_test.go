package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func assertClientLoginPolicy(t *testing.T, got, want *sso.Client) {
	t.Helper()
	if got.SkipConsent != want.SkipConsent || got.ConsentRefreshInterval != want.ConsentRefreshInterval ||
		got.AllowPasswordlessOnly != want.AllowPasswordlessOnly {
		t.Fatal("client login policy did not round-trip")
	}
}

func TestClient_LoginPoliciesPersistAllWritePaths(t *testing.T) {
	cfg := testConfig(t)
	store, err := NewClientStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	client := &sso.Client{ID: "policy", TenantID: "tenant", Active: true, SkipConsent: true,
		ConsentRefreshInterval: 37 * time.Minute, AllowPasswordlessOnly: true,
		Attributes: map[string]string{"operator": "retained"}}
	ctx := context.Background()
	for _, write := range []func(context.Context, *sso.Client) error{store.Add, store.Update, store.Put} {
		if err := write(ctx, client); err != nil {
			t.Fatal(err)
		}
		reader, err := NewClientStore(cfg)
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

func TestClient_LoginPolicyMigrationKeepsLegacyDefaults(t *testing.T) {
	cfg := testConfig(t)
	db, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := Run(ctx, db, "clients", clientMigrations[:6], cfg.Dialect); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO clients (id, secret, attributes) VALUES ('legacy', '',
		'{"_snaplink_client_skip_consent":"true","_snaplink_client_allow_passwordless_only":"true","skip_consent":"true"}')`)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewClientStoreWithDB(db, cfg.Dialect)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	assertClientLoginPolicy(t, got, &sso.Client{})
}
