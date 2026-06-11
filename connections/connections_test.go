package connections_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/connections"
)

func TestDomainFromIdentifier(t *testing.T) {
	cases := map[string]string{
		"alice@acme.com":   "acme.com",
		"Alice@ACME.com":   "acme.com",
		"  bob@Big.Co  ":   "big.co",
		"acme.com":         "acme.com",
		"ACME.com":         "acme.com",
		"weird@a@b.com":    "b.com", // last @ wins
		"":                 "",
		"   ":              "",
		"user@":            "",
		"plainusernomatch": "plainusernomatch",
	}
	for in, want := range cases {
		if got := connections.DomainFromIdentifier(in); got != want {
			t.Errorf("DomainFromIdentifier(%q) = %q, want %q", in, got, want)
		}
	}
}

func seedStore(t *testing.T) *connections.MemoryStore {
	t.Helper()
	s := connections.NewMemoryStore()
	ctx := context.Background()
	if err := s.Upsert(ctx, &connections.Connection{
		ID: "acme-okta", TenantID: "acme", Type: connections.TypeOIDC,
		DisplayName: "Acme Okta", Domains: []string{"acme.com", "Acme.io"},
		Enabled: true, Config: map[string]string{"oidc_issuer": "https://acme.okta.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(ctx, &connections.Connection{
		ID: "bigco-adfs", TenantID: "bigco", Type: connections.TypeSAML,
		DisplayName: "BigCo ADFS", Domains: []string{"big.co"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(ctx, &connections.Connection{
		ID: "paused", TenantID: "acme", Type: connections.TypeOIDC,
		Domains: []string{"paused.com"}, Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMemoryStore_ByDomainAndResolve(t *testing.T) {
	s := seedStore(t)
	ctx := context.Background()

	// Home-realm discovery via Resolve (email -> domain -> connection),
	// case-insensitive on both the seeded domain and the query.
	for _, id := range []string{"alice@acme.com", "alice@ACME.COM", "bob@acme.io"} {
		c, err := connections.Resolve(ctx, s, id)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", id, err)
		}
		if c.ID != "acme-okta" || c.TenantID != "acme" {
			t.Errorf("Resolve(%q) = %s/%s, want acme-okta/acme", id, c.ID, c.TenantID)
		}
	}
	if c, err := connections.Resolve(ctx, s, "x@big.co"); err != nil || c.ID != "bigco-adfs" {
		t.Errorf("Resolve big.co = %v / %v, want bigco-adfs", c, err)
	}

	// A disabled connection's domain does NOT resolve.
	if _, err := connections.Resolve(ctx, s, "x@paused.com"); !errors.Is(err, connections.ErrNoConnection) {
		t.Errorf("disabled connection should not resolve, got %v", err)
	}
	// Unknown domain + empty identifier + nil store -> ErrNoConnection.
	for _, id := range []string{"x@unknown.com", "", "   "} {
		if _, err := connections.Resolve(ctx, s, id); !errors.Is(err, connections.ErrNoConnection) {
			t.Errorf("Resolve(%q) err = %v, want ErrNoConnection", id, err)
		}
	}
	if _, err := connections.Resolve(ctx, nil, "x@acme.com"); !errors.Is(err, connections.ErrNoConnection) {
		t.Errorf("nil store should be ErrNoConnection, got %v", err)
	}
}

func TestMemoryStore_GetByTenantUpsertDelete(t *testing.T) {
	s := seedStore(t)
	ctx := context.Background()

	if c, err := s.Get(ctx, "acme-okta"); err != nil || c.Type != connections.TypeOIDC {
		t.Errorf("Get acme-okta = %v / %v", c, err)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, connections.ErrNoConnection) {
		t.Errorf("Get unknown = %v, want ErrNoConnection", err)
	}
	acme, _ := s.ByTenant(ctx, "acme")
	if len(acme) != 2 { // acme-okta + paused
		t.Errorf("ByTenant(acme) = %d, want 2", len(acme))
	}

	// Re-upsert with a changed domain set: the old domain stops routing.
	if err := s.Upsert(ctx, &connections.Connection{
		ID: "acme-okta", TenantID: "acme", Type: connections.TypeOIDC,
		Domains: []string{"acme.com"}, Enabled: true, // dropped "acme.io"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := connections.Resolve(ctx, s, "x@acme.io"); !errors.Is(err, connections.ErrNoConnection) {
		t.Error("a domain removed on re-upsert must stop routing")
	}
	if c, err := connections.Resolve(ctx, s, "x@acme.com"); err != nil || c.ID != "acme-okta" {
		t.Errorf("kept domain should still route: %v / %v", c, err)
	}

	// Returned values are copies — mutating one can't corrupt the store.
	got, _ := s.Get(ctx, "acme-okta")
	got.Domains[0] = "evil.com"
	if again, _ := s.Get(ctx, "acme-okta"); again.Domains[0] != "acme.com" {
		t.Error("Get returned an aliased Connection (store corrupted)")
	}

	// Delete clears the domain index too.
	if err := s.Delete(ctx, "acme-okta"); err != nil {
		t.Fatal(err)
	}
	if _, err := connections.Resolve(ctx, s, "x@acme.com"); !errors.Is(err, connections.ErrNoConnection) {
		t.Error("Delete must drop the connection's domain routing")
	}
}

func TestMemoryStore_DomainLastWriteWins(t *testing.T) {
	s := connections.NewMemoryStore()
	ctx := context.Background()
	_ = s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"shared.com"}, Enabled: true})
	_ = s.Upsert(ctx, &connections.Connection{ID: "b", Domains: []string{"shared.com"}, Enabled: true})
	c, err := connections.Resolve(ctx, s, "x@shared.com")
	if err != nil || c.ID != "b" {
		t.Errorf("a domain claimed by two connections should route to the latest: %v / %v", c, err)
	}
}
