package sqlite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/connections"
	csqlite "github.com/snaplink/sso/connections/sqlite"
)

func newStore(t *testing.T) *csqlite.Store {
	t.Helper()
	s, err := csqlite.New("file:" + t.TempDir() + "/conn.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLite_HomeRealmDiscoveryAndCRUD(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Upsert(ctx, &connections.Connection{
		ID: "acme", TenantID: "t-acme", Type: connections.TypeOIDC, DisplayName: "Acme",
		Domains: []string{"acme.com", "Acme.io"}, Enabled: true,
		Config: map[string]string{"oidc_issuer": "https://acme.okta.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(ctx, &connections.Connection{
		ID: "paused", TenantID: "t-acme", Domains: []string{"paused.com"}, Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}

	// Home-realm discovery, case-insensitive, with Config + Type round-trip.
	c, err := connections.Resolve(ctx, s, "Alice@ACME.com")
	if err != nil || c.ID != "acme" || c.Type != connections.TypeOIDC ||
		c.Config["oidc_issuer"] != "https://acme.okta.com" {
		t.Fatalf("resolve = %+v / %v", c, err)
	}
	if _, err := connections.Resolve(ctx, s, "x@acme.io"); err != nil {
		t.Errorf("the second domain should route: %v", err)
	}
	// A disabled connection's domain must not resolve.
	if _, err := connections.Resolve(ctx, s, "x@paused.com"); !errors.Is(err, connections.ErrNoConnection) {
		t.Errorf("disabled connection resolved: %v", err)
	}
	if _, err := connections.Resolve(ctx, s, "x@unknown.com"); !errors.Is(err, connections.ErrNoConnection) {
		t.Errorf("unknown domain: %v", err)
	}

	if got, _ := s.ByTenant(ctx, "t-acme"); len(got) != 2 {
		t.Errorf("ByTenant = %d, want 2", len(got))
	}

	// Re-upsert dropping a domain stops it routing.
	if err := s.Upsert(ctx, &connections.Connection{
		ID: "acme", TenantID: "t-acme", Type: connections.TypeOIDC,
		Domains: []string{"acme.com"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := connections.Resolve(ctx, s, "x@acme.io"); !errors.Is(err, connections.ErrNoConnection) {
		t.Error("a domain dropped on re-upsert still routes")
	}
	if c, err := connections.Resolve(ctx, s, "x@acme.com"); err != nil || c.ID != "acme" {
		t.Errorf("kept domain should still route: %+v / %v", c, err)
	}

	// Delete clears the connection AND its domain routing.
	if err := s.Delete(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := connections.Resolve(ctx, s, "x@acme.com"); !errors.Is(err, connections.ErrNoConnection) {
		t.Error("delete didn't clear domain routing")
	}
	if _, err := s.Get(ctx, "acme"); !errors.Is(err, connections.ErrNoConnection) {
		t.Error("deleted connection still gettable")
	}
}
