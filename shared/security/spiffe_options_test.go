package security_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// Coverage for the SPIFFEValidator option functions + the Validate
// branches the happy/security suite in spiffe_svid_test.go doesn't
// reach (option wiring, empty audience, nbf-in-future, empty bundle).

func TestSPIFFEValidator_TrustDomainAccessor(t *testing.T) {
	t.Parallel()
	// NewSPIFFEValidator lowercases the trust domain.
	src := security.NewStaticJWKS([]core.JWK{newES256Key(t, "k1").jwk})
	v, err := security.NewSPIFFEValidator("Example.ORG", src)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	if v.TrustDomain() != "example.org" {
		t.Errorf("TrustDomain() = %q, want example.org (lowercased)", v.TrustDomain())
	}
}

func TestSPIFFEValidator_WithMaxClockSkew(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "spire-1")
	src := security.NewStaticJWKS([]core.JWK{k.jwk})
	// A generous skew lets a token whose exp is slightly in the past
	// (within skew) still validate.
	v, err := security.NewSPIFFEValidator(testTrustDomain, src, security.WithSPIFFEMaxClockSkew(10*time.Minute))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	c := baseClaims(testSub, testAudience)
	c["iat"] = time.Now().Add(-12 * time.Minute).Unix()
	c["exp"] = time.Now().Add(-2 * time.Minute).Unix() // expired 2m ago, inside 10m skew
	svid := mintSVID(t, k, "", c)
	if _, err := v.Validate(context.Background(), svid, testAudience); err != nil {
		t.Fatalf("validate within skew: %v", err)
	}
}

func TestSPIFFEValidator_WithMaxClockSkew_NegativeIgnored(t *testing.T) {
	t.Parallel()
	// A negative skew is ignored (guarded by skew>=0), so the default
	// 60s tolerance remains; a clearly-expired token still fails.
	k := newES256Key(t, "spire-1")
	src := security.NewStaticJWKS([]core.JWK{k.jwk})
	v, err := security.NewSPIFFEValidator(testTrustDomain, src, security.WithSPIFFEMaxClockSkew(-time.Hour))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	c := baseClaims(testSub, testAudience)
	c["exp"] = time.Now().Add(-30 * time.Minute).Unix()
	svid := mintSVID(t, k, "", c)
	if _, err := v.Validate(context.Background(), svid, testAudience); err != security.ErrSPIFFESVIDInvalid {
		t.Errorf("negative skew not ignored: err = %v", err)
	}
}

func TestSPIFFEValidator_WithAllowedAlgs(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "spire-1")
	src := security.NewStaticJWKS([]core.JWK{k.jwk})
	// Restrict to ES256 only — the matching SVID still validates.
	v, err := security.NewSPIFFEValidator(testTrustDomain, src, security.WithSPIFFEAllowedAlgs("ES256"))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))
	if _, err := v.Validate(context.Background(), svid, testAudience); err != nil {
		t.Fatalf("validate ES256-restricted: %v", err)
	}

	// An EdDSA SVID is rejected when the allowlist is ES256-only.
	ek := newEdDSAKey(t, "spire-ed")
	v2, err := security.NewSPIFFEValidator(testTrustDomain, security.NewStaticJWKS([]core.JWK{ek.jwk}),
		security.WithSPIFFEAllowedAlgs("ES256"))
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	esvid := mintSVID(t, ek, "", baseClaims(testSub, testAudience))
	if _, err := v2.Validate(context.Background(), esvid, testAudience); err != security.ErrSPIFFESVIDInvalid {
		t.Errorf("EdDSA accepted under ES256-only allowlist: %v", err)
	}
}

func TestSPIFFEValidator_WithAllowedAlgs_EmptyIgnored(t *testing.T) {
	t.Parallel()
	// Empty algs leaves the default set in place; EdDSA still works.
	k := newEdDSAKey(t, "spire-ed")
	src := security.NewStaticJWKS([]core.JWK{k.jwk})
	v, err := security.NewSPIFFEValidator(testTrustDomain, src, security.WithSPIFFEAllowedAlgs())
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))
	if _, err := v.Validate(context.Background(), svid, testAudience); err != nil {
		t.Fatalf("validate with default algs: %v", err)
	}
}

func TestSPIFFEValidator_EmptyAudienceRejected(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "spire-1")
	v := newValidator(t, k.jwk)
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))
	// An empty expectedAudience is a server misconfiguration — collapses
	// to the opaque error, never reveals server state.
	if _, err := v.Validate(context.Background(), svid, ""); err != security.ErrSPIFFESVIDInvalid {
		t.Errorf("empty audience err = %v, want ErrSPIFFESVIDInvalid", err)
	}
}

func TestSPIFFEValidator_EmptyBundleRejected(t *testing.T) {
	t.Parallel()
	// A validator whose trust bundle is empty rejects everything
	// (no keys to verify against) — still opaque.
	v := newValidator(t) // no keys
	k := newES256Key(t, "spire-1")
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))
	if _, err := v.Validate(context.Background(), svid, testAudience); err != security.ErrSPIFFESVIDInvalid {
		t.Errorf("empty-bundle err = %v, want ErrSPIFFESVIDInvalid", err)
	}
}

func TestSPIFFEValidator_NbfInFutureRejected(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "spire-1")
	v := newValidator(t, k.jwk)
	c := baseClaims(testSub, testAudience)
	// nbf well beyond the default skew → not yet valid.
	c["nbf"] = time.Now().Add(10 * time.Minute).Unix()
	svid := mintSVID(t, k, "", c)
	if _, err := v.Validate(context.Background(), svid, testAudience); err != security.ErrSPIFFESVIDInvalid {
		t.Errorf("future-nbf err = %v, want ErrSPIFFESVIDInvalid", err)
	}
}

func TestSPIFFEValidator_MissingExpRejected(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "spire-1")
	v := newValidator(t, k.jwk)
	// A JWT-SVID MUST carry exp; omit it.
	c := map[string]any{"sub": testSub, "aud": testAudience, "iat": time.Now().Unix()}
	svid := mintSVID(t, k, "", c)
	if _, err := v.Validate(context.Background(), svid, testAudience); err != security.ErrSPIFFESVIDInvalid {
		t.Errorf("missing-exp err = %v, want ErrSPIFFESVIDInvalid", err)
	}
}
