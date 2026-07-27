package defaultimpl_test

// Runtime key rotation (RotateKey / RetireKey) — distinct from the
// construction-time WithEd25519VerifyKey rotation covered in
// ed25519_rotation_test.go.

import (
	"context"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func jwksKIDs(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer) map[string]bool {
	t.Helper()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	out := make(map[string]bool, len(jwks))
	for _, k := range jwks {
		out[k.Kid] = true
	}
	return out
}

// TestRotateKey_OverlapWindow proves the rotation contract: a token
// minted before rotation still validates after it (old key demoted to
// verify-only), new tokens carry the new kid, and JWKS serves both.
func TestRotateKey_OverlapWindow(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	oldKID := iss.KeyID()

	oldTok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("issue old: %v", err)
	}

	newKID, err := iss.RotateKey(nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newKID == oldKID {
		t.Fatal("rotation produced the same kid")
	}
	if iss.KeyID() != newKID {
		t.Errorf("active kid = %q, want %q", iss.KeyID(), newKID)
	}

	// Old token still verifies (demoted key kept for its TTL).
	if _, err := iss.Validate(context.Background(), oldTok.AccessToken); err != nil {
		t.Errorf("old token should still validate after rotation: %v", err)
	}
	// New token verifies under the new key.
	newTok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("issue new: %v", err)
	}
	if _, err := iss.Validate(context.Background(), newTok.AccessToken); err != nil {
		t.Errorf("new token should validate: %v", err)
	}

	// JWKS serves both kids during the overlap.
	kids := jwksKIDs(t, iss)
	if !kids[oldKID] || !kids[newKID] {
		t.Errorf("JWKS missing a kid during overlap: have %v, want both %q and %q", kids, oldKID, newKID)
	}
}

// TestRetireKey_DropsOldAndProtectsActive proves retirement removes a
// demoted key from JWKS and refuses to retire the active signer.
func TestRetireKey_DropsOldAndProtectsActive(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	oldKID := iss.KeyID()
	newKID, _ := iss.RotateKey(nil)

	if err := iss.RetireKey(newKID); err == nil {
		t.Error("RetireKey(active) should error")
	}
	if err := iss.RetireKey(oldKID); err != nil {
		t.Errorf("RetireKey(old): %v", err)
	}
	if kids := jwksKIDs(t, iss); kids[oldKID] {
		t.Errorf("retired kid %q still in JWKS: %v", oldKID, kids)
	}
}

// TestRotateKey_ConcurrentWithIssue is a race-detector guard: rotation
// must not data-race concurrent issuance/JWKS reads.
func TestRotateKey_ConcurrentWithIssue(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(3)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = iss.JWKS(context.Background())
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = iss.RotateKey(nil)
			}
		}
	}()

	for range 20 {
		_, _ = iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	}
	close(stop)
	wg.Wait()
}
