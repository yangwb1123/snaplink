package defaultjwe

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

// encryptTo wraps msg for the recipient key with the given kid, selected from
// jwks — so a test can address a SPECIFIC key version (e.g. the one about to be
// retired) rather than whichever the encrypter would pick by default.
func encryptTo(t *testing.T, jwks []core.JWK, kid string, msg []byte) string {
	t.Helper()
	var target []core.JWK
	for _, k := range jwks {
		if k.Kid == kid {
			target = append(target, k)
		}
	}
	if len(target) == 0 {
		t.Fatalf("no JWK with kid %q in %d-key set", kid, len(jwks))
	}
	enc := NewRSAJWEResponseEncrypter()
	ct, err := enc.Encrypt(context.Background(), msg, target, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("encrypt to %q: %v", kid, err)
	}
	return ct
}

func jwksOf(t *testing.T, d *RotatingJWEDecrypter) []core.JWK {
	t.Helper()
	ks, err := d.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	return ks
}

// TestRotatingJWE_RoundTripAndOverlap proves the routine-rotation contract: the
// current key decrypts; after a rotation the demoted key STILL decrypts within
// its overlap window (so in-flight request objects encrypted to it survive) and
// BOTH keys are published in JWKS for migrating RPs.
func TestRotatingJWE_RoundTripAndOverlap(t *testing.T) {
	t.Parallel()
	dec, err := NewRotatingJWEDecrypter(nil, "jwe-enc", 2048, time.Hour)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	msg := []byte("signed-jar-request-object")

	v1kid := dec.CurrentMeta().ID // jwe-enc/v1
	ctV1 := encryptTo(t, jwksOf(t, dec), v1kid, msg)
	if got, err := dec.Decrypt(context.Background(), ctV1); err != nil || string(got) != string(msg) {
		t.Fatalf("decrypt with current key: got=%q err=%v", got, err)
	}

	if _, err := dec.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// The demoted v1 key still decrypts inside the overlap window.
	if got, err := dec.Decrypt(context.Background(), ctV1); err != nil || string(got) != string(msg) {
		t.Fatalf("decrypt with demoted key inside overlap: got=%q err=%v", got, err)
	}
	if ks := jwksOf(t, dec); len(ks) != 2 {
		t.Fatalf("JWKS during overlap = %d keys, want 2 (current + demoted)", len(ks))
	}
}

// TestRotatingJWE_CompromiseDropsLeakedKeyImmediately is the Phase-3 property at
// the key level: RotateCompromised installs a fresh key and DROPS the leaked one
// with no overlap — a request object encrypted to the leaked key no longer
// decrypts, and the leaked key is gone from JWKS.
func TestRotatingJWE_CompromiseDropsLeakedKeyImmediately(t *testing.T) {
	t.Parallel()
	// A long overlap is configured; compromise must ignore it entirely.
	dec, err := NewRotatingJWEDecrypter(nil, "jwe-enc", 2048, time.Hour)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	msg := []byte("secret-request-object")

	leakedKid := dec.CurrentMeta().ID // jwe-enc/v1 — the key we will declare leaked
	ctLeaked := encryptTo(t, jwksOf(t, dec), leakedKid, msg)

	meta, err := dec.RotateCompromised(context.Background())
	if err != nil {
		t.Fatalf("RotateCompromised: %v", err)
	}
	if meta.Version != 2 || meta.Type != corecredential.CredentialTypeJWEDecryption {
		t.Fatalf("compromise meta = v%d/%q, want v2/jwe_decryption", meta.Version, meta.Type)
	}

	// The leaked key must NOT decrypt anymore — no overlap acceptance.
	if _, err := dec.Decrypt(context.Background(), ctLeaked); err == nil {
		t.Fatal("leaked key still decrypts after compromise — overlap must be zero")
	}
	// And it must be gone from JWKS (only the fresh key remains).
	ks := jwksOf(t, dec)
	if len(ks) != 1 {
		t.Fatalf("JWKS after compromise = %d keys, want 1 (only the fresh key)", len(ks))
	}
	if ks[0].Kid == leakedKid {
		t.Fatalf("JWKS still advertises the leaked kid %q", leakedKid)
	}

	// The fresh key round-trips.
	freshCT := encryptTo(t, ks, meta.ID, msg)
	if got, err := dec.Decrypt(context.Background(), freshCT); err != nil || string(got) != string(msg) {
		t.Fatalf("decrypt with fresh key: got=%q err=%v", got, err)
	}
}

// TestRotatingJWE_ImplementsRotationSPIs guards the interface contract the
// framework wiring relies on.
func TestRotatingJWE_ImplementsRotationSPIs(t *testing.T) {
	t.Parallel()
	dec, err := NewRotatingJWEDecrypter(nil, "", 2048, time.Minute)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var _ corecredential.CompromiseRotator = dec
	if dec.Type() != corecredential.CredentialTypeJWEDecryption {
		t.Errorf("Type = %q", dec.Type())
	}
	if dec.OverlapWindow() != time.Minute {
		t.Errorf("OverlapWindow = %v, want 1m", dec.OverlapWindow())
	}
	deps := dec.Dependents()
	if len(deps) != 1 || deps[0] != corecredential.DependencyJWKS {
		t.Errorf("Dependents = %v, want [jwks]", deps)
	}
}
