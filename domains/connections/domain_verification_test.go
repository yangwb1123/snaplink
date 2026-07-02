package connections_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/snaplink/sso/domains/connections"
)

// fakeDNSResolver is a deterministic in-memory connections.DNSResolver — the
// hermetic (no real network) test double the design mandates, mirroring the
// federation fetcher test-fake precedent (a plain struct, not a mock).
type fakeDNSResolver struct {
	mu      sync.Mutex
	records map[string][]string // record name -> TXT values
	err     error               // when set, every lookup returns it (NXDOMAIN/transient)
	calls   int
}

func (f *fakeDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.records[name], nil
}

func (f *fakeDNSResolver) set(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		f.records = map[string][]string{}
	}
	f.records[name] = values
}

func mustClaim(t *testing.T, s connections.Store, connID, domain string) *connections.DomainVerification {
	t.Helper()
	c, err := s.DomainClaim(context.Background(), connID, domain)
	if err != nil {
		t.Fatalf("DomainClaim(%s,%s): %v", connID, domain, err)
	}
	return c
}

// TestVerifyDomainOwnership_FakeResolver exercises the DNS-TXT challenge check
// end-to-end against a real MemoryStore and the injected fake resolver.
func TestVerifyDomainOwnership_FakeResolver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	claim := mustClaim(t, s, "a", "acme.com")
	if claim.Status != connections.DomainPending || claim.Token == "" {
		t.Fatalf("new claim should be pending with a token, got %+v", claim)
	}
	if want := connections.DomainVerificationRecordName("", "acme.com"); claim.Record != want {
		t.Errorf("record = %q, want %q", claim.Record, want)
	}

	// NXDOMAIN / transient DNS failure is the expected "not yet published" state,
	// not a hard error: (false, nil), claim stays pending.
	res := &fakeDNSResolver{err: errors.New("no such host")}
	if ok, err := connections.VerifyDomainOwnership(ctx, s, res, "a", "acme.com", 0); ok || err != nil {
		t.Errorf("NXDOMAIN = (%v,%v), want (false,nil)", ok, err)
	}
	if mustClaim(t, s, "a", "acme.com").Status != connections.DomainPending {
		t.Error("claim should still be pending after NXDOMAIN")
	}

	// TXT present but wrong value -> still pending.
	res2 := &fakeDNSResolver{}
	res2.set(claim.Record, "not-the-token")
	if ok, err := connections.VerifyDomainOwnership(ctx, s, res2, "a", "acme.com", 0); ok || err != nil {
		t.Errorf("wrong TXT = (%v,%v), want (false,nil)", ok, err)
	}
	if mustClaim(t, s, "a", "acme.com").Status != connections.DomainPending {
		t.Error("wrong TXT must leave the claim pending")
	}

	// Correct token published -> verified, and the domain now routes.
	res2.set(claim.Record, "other", claim.Token)
	if ok, err := connections.VerifyDomainOwnership(ctx, s, res2, "a", "acme.com", 0); !ok || err != nil {
		t.Errorf("matching TXT = (%v,%v), want (true,nil)", ok, err)
	}
	if mustClaim(t, s, "a", "acme.com").Status != connections.DomainVerified {
		t.Error("claim should be verified after a matching TXT")
	}
	if c, err := connections.Resolve(ctx, s, "x@acme.com"); err != nil || c.ID != "a" {
		t.Errorf("verified domain must route: %v / %v", c, err)
	}

	// Already-verified is idempotent and must NOT hit the resolver again.
	panicRes := &fakeDNSResolver{}
	if ok, err := connections.VerifyDomainOwnership(ctx, s, panicRes, "a", "acme.com", 0); !ok || err != nil {
		t.Errorf("re-verify = (%v,%v), want (true,nil)", ok, err)
	}
	if panicRes.calls != 0 {
		t.Errorf("verified claim must short-circuit the resolver, calls=%d", panicRes.calls)
	}

	// A domain this connection never claimed is a distinct sentinel (-> 404 at HTTP).
	if _, err := connections.VerifyDomainOwnership(ctx, s, res2, "a", "never.com", 0); !errors.Is(err, connections.ErrNoDomainClaim) {
		t.Errorf("unclaimed domain err = %v, want ErrNoDomainClaim", err)
	}
}

// TestMemoryStore_DomainVerificationRequired_BlocksHijack is the core security
// test: with verification required, an Upsert claiming a domain another
// connection has already VERIFIED must NOT steal routing; only a successful DNS
// re-proof (legitimate change of DNS control) supersedes it.
func TestMemoryStore_DomainVerificationRequired_BlocksHijack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))

	// connA owns shared.com (verified via the operator/boot-seed direct path).
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyDomain(ctx, "a", "shared.com"); err != nil {
		t.Fatal(err)
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c == nil || c.ID != "a" {
		t.Fatalf("connA should own shared.com, got %v", c)
	}

	// connB claims the same domain: last-write-wins is REFUSED — routing stays A.
	if err := s.Upsert(ctx, &connections.Connection{ID: "b", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c == nil || c.ID != "a" {
		t.Fatalf("hijack: an unproven Upsert must not steal routing, got %v", c)
	}
	if mustClaim(t, s, "b", "shared.com").Status != connections.DomainPending {
		t.Error("connB's competing claim must be pending")
	}

	// connB proving the WRONG token does not take over.
	claimB := mustClaim(t, s, "b", "shared.com")
	res := &fakeDNSResolver{}
	res.set(claimB.Record, "wrong")
	if ok, _ := connections.VerifyDomainOwnership(ctx, s, res, "b", "shared.com", 0); ok {
		t.Error("wrong TXT must not verify connB")
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c.ID != "a" {
		t.Error("routing must still be connA after a failed proof")
	}

	// connB proving the CORRECT token (real DNS control) legitimately supersedes.
	res.set(claimB.Record, claimB.Token)
	if ok, err := connections.VerifyDomainOwnership(ctx, s, res, "b", "shared.com", 0); !ok || err != nil {
		t.Fatalf("valid proof should verify connB: %v/%v", ok, err)
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c == nil || c.ID != "b" {
		t.Fatalf("DNS control changing hands must supersede: got %v", c)
	}
	// The prior owner is demoted (no longer routes, claim back to pending).
	if mustClaim(t, s, "a", "shared.com").Status != connections.DomainPending {
		t.Error("the superseded owner's claim must be demoted to pending")
	}
}

// TestMemoryStore_SameConnectionReVerify confirms the legitimate same-owner path
// is not collateral damage of the anti-hijack rule.
func TestMemoryStore_SameConnectionReVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	tok := mustClaim(t, s, "a", "acme.com").Token
	if err := s.VerifyDomain(ctx, "a", "acme.com"); err != nil {
		t.Fatal(err)
	}
	// Re-upsert with the same domain must be idempotent: keep the token + verified.
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	again := mustClaim(t, s, "a", "acme.com")
	if again.Status != connections.DomainVerified || again.Token != tok {
		t.Errorf("re-upsert must preserve verified status + token, got %+v", again)
	}
	if c, _ := connections.Resolve(ctx, s, "x@acme.com"); c == nil || c.ID != "a" {
		t.Error("same-connection re-verify must keep routing")
	}
}

// TestMemoryStore_DomainVerificationNotRequired_Unaffected proves the default
// (opt-out) mode is byte-identical last-write-wins, with claims auto-verified.
func TestMemoryStore_DomainVerificationNotRequired_Unaffected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := connections.NewMemoryStore() // no options == today's behavior
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if mustClaim(t, s, "a", "shared.com").Status != connections.DomainVerified {
		t.Error("default mode must auto-verify a claimed domain")
	}
	// Last-write-wins still holds (matches the pre-feature contract).
	if err := s.Upsert(ctx, &connections.Connection{ID: "b", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if c, err := connections.Resolve(ctx, s, "x@shared.com"); err != nil || c.ID != "b" {
		t.Errorf("default mode last-write-wins: %v / %v", c, err)
	}
}
