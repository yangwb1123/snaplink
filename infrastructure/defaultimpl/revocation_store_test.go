package defaultimpl_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
)

func TestMemoryRevocationStore_RoundTripAndPrune(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryRevocationStore()
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()
	if err := s.Revoke(ctx, "live", future); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "dead", past); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got["live"] != future {
		t.Errorf("live revocation = %d, want %d", got["live"], future)
	}
	if _, ok := got["dead"]; ok {
		t.Error("an already-expired revocation must be pruned out of Load")
	}
}

// runRevocationRestart drives the restart-survival contract against a shared
// durable store: replica A revokes a token (persisting to the store), then a
// FRESH replica B (same signing key, same store, EMPTY in-process deny-set —
// the restart / late-join condition) must honor the revocation after
// SeedRevocations, where without it the token would resurrect.
func runRevocationRestart(t *testing.T, store defaultimpl.RevocationStore) {
	t.Helper()
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *defaultimpl.Ed25519JWTIssuer {
		return defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer("iss"),
			defaultimpl.WithEd25519Key(priv),
			defaultimpl.WithEd25519KeyID("k1"),
			defaultimpl.WithEd25519RevocationStore(store),
		)
	}

	a := mk()
	tok, err := a.Issue(ctx, &sso.Subject{ID: "u", ClientID: "c"}, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Validate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("token should validate before revoke: %v", err)
	}
	if err := a.Revoke(ctx, tok.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Validate(ctx, tok.AccessToken); err == nil {
		t.Fatal("revoked token must not validate on A")
	}

	// Fresh replica B: same key + same shared store, empty in-process map.
	b := mk()
	// Pre-seed: B doesn't yet know about the revocation — this is exactly the
	// resurrection bug the durable store + SeedRevocations closes.
	if _, err := b.Validate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("pre-seed B should accept (proving the seed is what fixes it): %v", err)
	}
	if err := b.SeedRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Validate(ctx, tok.AccessToken); err == nil {
		t.Fatal("after SeedRevocations the revoked token must be rejected on B (restart survival)")
	}
}

func TestEd25519Issuer_RevocationSurvivesRestart_Memory(t *testing.T) {
	runRevocationRestart(t, defaultimpl.NewMemoryRevocationStore())
}

func TestEd25519Issuer_RevocationSurvivesRestart_SQLite(t *testing.T) {
	store, err := sqlite.NewRevocationStore("file:" + t.TempDir() + "/rev.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runRevocationRestart(t, store)
}

func TestEd25519Issuer_NilStore_SeedNoOp(t *testing.T) {
	// nil store: SeedRevocations is a byte-identical no-op (no regression for
	// the in-process-only default).
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("iss"))
	if err := iss.SeedRevocations(context.Background()); err != nil {
		t.Errorf("SeedRevocations with no store should be a no-op, got %v", err)
	}
}
