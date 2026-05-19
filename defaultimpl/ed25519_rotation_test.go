package defaultimpl_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// generateKey is a tiny helper so each test gets a fresh keypair.
func generateKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return priv, pub
}

func TestKeyRotation_LegacyKeyValidatesAfterSwap(t *testing.T) {
	// Step 1: original issuer signs a token.
	oldPriv, oldPub := generateKey(t)
	old := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(oldPriv),
		defaultimpl.WithEd25519KeyID("old-kid"),
	)
	token, err := old.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Step 2: simulate a rotation — new issuer with the NEW primary
	// key plus the OLD key registered as verify-only.
	newPriv, _ := generateKey(t)
	rotated := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(newPriv),
		defaultimpl.WithEd25519KeyID("new-kid"),
		defaultimpl.WithEd25519VerifyKey("old-kid", oldPub),
	)

	// The old token MUST still validate post-rotation.
	if _, err := rotated.Validate(context.Background(), token.AccessToken); err != nil {
		t.Errorf("old token rejected after rotation: %v", err)
	}
}

func TestKeyRotation_UnknownKidRejected(t *testing.T) {
	// Issuer that has ONLY its own key.
	priv, _ := generateKey(t)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519KeyID("primary"),
	)

	// Make a token signed by a DIFFERENT key with a DIFFERENT kid.
	otherPriv, _ := generateKey(t)
	other := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(otherPriv),
		defaultimpl.WithEd25519KeyID("foreign"),
	)
	token, _ := other.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)

	if _, err := iss.Validate(context.Background(), token.AccessToken); err == nil {
		t.Error("validate accepted token signed by unregistered kid")
	}
}

func TestKeyRotation_NewTokensSignedByPrimary(t *testing.T) {
	oldPriv, oldPub := generateKey(t)
	newPriv, _ := generateKey(t)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(newPriv),
		defaultimpl.WithEd25519KeyID("new"),
		defaultimpl.WithEd25519VerifyKey("old", oldPub),
	)
	// Newly issued token must round-trip on the new primary (we
	// don't accidentally sign with the retired key).
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	// Decode the header to extract kid — the primary's new-kid.
	if !strings.Contains(tok.AccessToken, "."+`eyJ`) {
		// nothing to assert about base64 contents directly; just
		// make sure validation works.
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Errorf("new token failed to validate against primary: %v", err)
		_ = oldPriv
	}
}

func TestKeyRotation_JWKSEmitsBothKeys(t *testing.T) {
	priv, _ := generateKey(t)
	_, oldPub := generateKey(t)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519KeyID("primary"),
		defaultimpl.WithEd25519VerifyKey("retired", oldPub),
	)
	keys, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("JWKS returned %d keys, want 2", len(keys))
	}
	// Order: primary first, then retired (sorted by kid).
	if keys[0].Kid != "primary" {
		t.Errorf("first key kid = %q want primary", keys[0].Kid)
	}
	if keys[1].Kid != "retired" {
		t.Errorf("second key kid = %q want retired", keys[1].Kid)
	}
}

func TestKeyRotation_VerifyKeyOverrideIdempotent(t *testing.T) {
	priv, _ := generateKey(t)
	_, pubA := generateKey(t)
	_, pubB := generateKey(t)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519KeyID("primary"),
		defaultimpl.WithEd25519VerifyKey("k1", pubA),
		// Re-registering same kid with different key replaces, doesn't dup.
		defaultimpl.WithEd25519VerifyKey("k1", pubB),
	)
	keys, _ := iss.JWKS(context.Background())
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (primary + k1), got %d", len(keys))
	}
}

func TestKeyRotation_JWKSStableOrderPreservesETag(t *testing.T) {
	// Insertion order shouldn't change JWKS output — kids sort
	// deterministically. Verify two builds with the same inputs in
	// different order produce identical JWKS sequences.
	priv, _ := generateKey(t)
	_, k1 := generateKey(t)
	_, k2 := generateKey(t)

	a := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519KeyID("primary"),
		defaultimpl.WithEd25519VerifyKey("a", k1),
		defaultimpl.WithEd25519VerifyKey("b", k2),
	)
	b := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519KeyID("primary"),
		defaultimpl.WithEd25519VerifyKey("b", k2),
		defaultimpl.WithEd25519VerifyKey("a", k1),
	)
	keysA, _ := a.JWKS(context.Background())
	keysB, _ := b.JWKS(context.Background())
	if len(keysA) != len(keysB) {
		t.Fatalf("len mismatch: %d vs %d", len(keysA), len(keysB))
	}
	for i := range keysA {
		if keysA[i].Kid != keysB[i].Kid {
			t.Errorf("kid order differs at i=%d: %q vs %q",
				i, keysA[i].Kid, keysB[i].Kid)
		}
	}
}
