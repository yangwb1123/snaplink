package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
	csqlite "github.com/yangwb1123/snaplink/domains/connections/sqlite"

	_ "modernc.org/sqlite" // register the pure-Go "sqlite" driver for the manual sql.Open.
)

// fakeResolver is the hermetic DNS double (no real network).
type fakeResolver struct {
	records map[string][]string
	err     error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records[name], nil
}

type pausedResolver struct {
	started     chan struct{}
	released    chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
	token       string
}

func (f *pausedResolver) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	f.startOnce.Do(func() { close(f.started) })
	select {
	case <-f.released:
		return []string{f.token}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *pausedResolver) release() {
	f.releaseOnce.Do(func() { close(f.released) })
}

func newVerifiedStore(t *testing.T) *csqlite.Store {
	t.Helper()
	s, err := csqlite.New("file:"+t.TempDir()+"/conn.db", connections.WithDomainVerificationRequired(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestSQLite_MigrationV2 confirms the domain-claim migration lifts the reported
// max version so the boot schema-guard reflects it.
func TestSQLite_MigrationV2(t *testing.T) {
	t.Parallel()
	if got := csqlite.ConnectionsMaxVersion(); got < 2 {
		t.Errorf("ConnectionsMaxVersion() = %d, want >= 2 (domain_claims migration)", got)
	}
	// New() runs migrations; a clean open proves v2 applies on top of v1.
	_ = newVerifiedStore(t)
}

// TestSQLite_DomainVerificationRequired_BlocksHijack mirrors the memory-store
// security test against the durable backend.
func TestSQLite_DomainVerificationRequired_BlocksHijack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newVerifiedStore(t)

	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyDomain(ctx, "a", "shared.com"); err != nil {
		t.Fatal(err)
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c == nil || c.ID != "a" {
		t.Fatalf("connA should own shared.com, got %v", c)
	}

	// connB's unproven claim must not steal routing.
	if err := s.Upsert(ctx, &connections.Connection{ID: "b", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c == nil || c.ID != "a" {
		t.Fatalf("hijack blocked: routing must stay connA, got %v", c)
	}
	claimB, err := s.DomainClaim(ctx, "b", "shared.com")
	if err != nil || claimB.Status != connections.DomainPending {
		t.Fatalf("connB claim = %+v / %v, want pending", claimB, err)
	}

	// Wrong proof: no takeover.
	wrong := fakeResolver{records: map[string][]string{claimB.Record: {"nope"}}}
	if ok, _ := connections.VerifyDomainOwnership(ctx, s, wrong, "b", "shared.com", 0); ok {
		t.Error("wrong TXT must not verify")
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c.ID != "a" {
		t.Error("routing must still be connA")
	}

	// Correct proof: DNS control supersedes.
	right := fakeResolver{records: map[string][]string{claimB.Record: {claimB.Token}}}
	if ok, err := connections.VerifyDomainOwnership(ctx, s, right, "b", "shared.com", 0); !ok || err != nil {
		t.Fatalf("valid proof should verify connB: %v/%v", ok, err)
	}
	if c, _ := connections.Resolve(ctx, s, "x@shared.com"); c == nil || c.ID != "b" {
		t.Fatalf("verified connB should now route, got %v", c)
	}
	if a, _ := s.DomainClaim(ctx, "a", "shared.com"); a == nil || a.Status != connections.DomainPending {
		t.Errorf("prior owner must be demoted to pending, got %+v", a)
	}
}

func TestSQLite_VerifyDomainOwnership_RejectsReplacedClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newVerifiedStore(t)
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	oldClaim, err := s.DomainClaim(ctx, "a", "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pausedResolver{
		started:  make(chan struct{}),
		released: make(chan struct{}),
		token:    oldClaim.Token,
	}
	resultCh := make(chan struct {
		verified bool
		err      error
	}, 1)
	go func() {
		verified, err := connections.VerifyDomainOwnership(ctx, s, resolver, "a", "acme.com", 0)
		resultCh <- struct {
			verified bool
			err      error
		}{verified, err}
	}()
	defer resolver.release()
	select {
	case <-resolver.started:
	case <-time.After(time.Second):
		t.Fatal("DNS resolver was not reached after loading the old claim")
	}

	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	freshClaim, err := s.DomainClaim(ctx, "a", "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if freshClaim.Token == oldClaim.Token {
		t.Fatal("recreated claim unexpectedly reused the old token")
	}
	if freshClaim.Status != connections.DomainPending {
		t.Fatalf("recreated claim = %q, want pending", freshClaim.Status)
	}

	resolver.release()
	result := <-resultCh
	if result.verified || result.err != nil {
		t.Fatalf("old DNS proof = (%v, %v), want (false, nil)", result.verified, result.err)
	}
	claim, err := s.DomainClaim(ctx, "a", "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if claim.Status != connections.DomainPending {
		t.Fatalf("recreated claim after old proof = %q, want pending", claim.Status)
	}
	if c, err := connections.Resolve(ctx, s, "x@acme.com"); c != nil || !errors.Is(err, connections.ErrNoConnection) {
		t.Fatalf("recreated claim must not route: %v / %v", c, err)
	}
}

// TestSQLite_VerifyDomainOwnership_FailClosedOnStoreError proves a store read
// failure fails CLOSED: VerifyDomainOwnership returns the error and cannot
// silently authorize a takeover. A closed real store induces the error (no mock).
func TestSQLite_VerifyDomainOwnership_FailClosedOnStoreError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/conn.db")
	if err != nil {
		t.Fatal(err)
	}
	s := csqlite.NewWithDB(db, connections.WithDomainVerificationRequired(true))
	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Close the underlying pool so a genuine DB error (not a nil deref) surfaces.
	_ = db.Close()

	res := fakeResolver{records: map[string][]string{
		connections.DomainVerificationRecordName("", "acme.com"): {"anything"},
	}}
	ok, err := connections.VerifyDomainOwnership(ctx, s, res, "a", "acme.com", 0)
	if ok {
		t.Fatal("a store error must NOT report verified")
	}
	if err == nil {
		t.Fatal("a store read error must be surfaced (fail-closed), got nil")
	}
	if errors.Is(err, connections.ErrNoDomainClaim) {
		t.Fatal("a DB failure must not masquerade as ErrNoDomainClaim")
	}
}

// TestSQLite_Delete_PurgesDomainClaims proves Delete removes a connection's
// domain-ownership claims (not just its routing + health rows), matching
// MemoryStore.Delete's map cleanup. Without this, a stale VERIFIED claim
// survives the delete and is silently inherited — without re-proving DNS
// control — by a later connection reusing the same id, defeating
// DomainVerificationRequired's anti-hijack guarantee for that case.
func TestSQLite_Delete_PurgesDomainClaims(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newVerifiedStore(t)

	if err := s.Upsert(ctx, &connections.Connection{ID: "acme", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyDomain(ctx, "acme", "acme.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DomainClaim(ctx, "acme", "acme.com"); !errors.Is(err, connections.ErrNoDomainClaim) {
		t.Fatalf("DomainClaim after delete = %v, want ErrNoDomainClaim (claim must not survive delete)", err)
	}

	// Recreate a connection under the SAME id + domain: the hardened mode must
	// require FRESH DNS proof, not inherit the deleted connection's verified
	// status via a leftover claims row.
	if err := s.Upsert(ctx, &connections.Connection{ID: "acme", Domains: []string{"acme.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	claim, err := s.DomainClaim(ctx, "acme", "acme.com")
	if err != nil {
		t.Fatalf("recreated connection should have a fresh claim: %v", err)
	}
	if claim.Status != connections.DomainPending {
		t.Fatalf("recreated connection's claim = %q, want pending (must re-prove DNS control, not inherit stale verified state)", claim.Status)
	}
	if c, _ := connections.Resolve(ctx, s, "x@acme.com"); c != nil {
		t.Fatalf("recreated connection must not auto-route on an unproven claim, got %+v", c)
	}
}

// TestSQLite_DomainVerificationNotRequired_Unaffected confirms the default store
// is byte-identical last-write-wins with auto-verified claims.
func TestSQLite_DomainVerificationNotRequired_Unaffected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := csqlite.New("file:" + t.TempDir() + "/conn.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Upsert(ctx, &connections.Connection{ID: "a", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if claim, err := s.DomainClaim(ctx, "a", "shared.com"); err != nil || claim.Status != connections.DomainVerified {
		t.Fatalf("default mode must auto-verify: %+v / %v", claim, err)
	}
	if err := s.Upsert(ctx, &connections.Connection{ID: "b", Domains: []string{"shared.com"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if c, err := connections.Resolve(ctx, s, "x@shared.com"); err != nil || c.ID != "b" {
		t.Errorf("default mode last-write-wins: %v / %v", c, err)
	}
}
