package cryptosigner_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/cryptosigner"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// Software keys implement crypto.Signer, so they stand in for a
// KMS/HSM-backed signer in these tests — the bridge can't tell the
// difference, which is the whole point. The end-to-end assertions issue
// a token through the real issuer and validate it, proving the bridged
// signature is byte-compatible with what the issuer's own verifier
// expects (this is the only assertion that catches the ECDSA DER->R||S
// conversion being wrong).

func TestEd25519_EndToEnd(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sgn, gotPub, err := cryptosigner.Ed25519(priv)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if !gotPub.Equal(pub) {
		t.Fatal("returned public key does not match")
	}
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519ExternalSigner(sgn, gotPub, "kms-ed25519"),
	)
	assertIssueValidate(t, iss, iss)
}

func TestECDSA_EndToEnd(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	// ecdsa.PrivateKey.Sign returns ASN.1 DER — exercises the conversion.
	sgn, gotPub, err := cryptosigner.ECDSA(priv)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if !gotPub.Equal(&priv.PublicKey) {
		t.Fatal("returned public key does not match")
	}
	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAExternalSigner(sgn, gotPub, "kms-es256"),
	)
	assertIssueValidate(t, iss, iss)
}

func TestRSA_EndToEnd(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{cryptosigner.AlgRS256, cryptosigner.AlgPS256} {
		t.Run(alg, func(t *testing.T) {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("genkey: %v", err)
			}
			sgn, gotPub, err := cryptosigner.RSA(priv, alg)
			if err != nil {
				t.Fatalf("bridge: %v", err)
			}
			if !gotPub.Equal(&priv.PublicKey) {
				t.Fatal("returned public key does not match")
			}
			iss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAAlg(alg),
				defaultimpl.WithRSAExternalSigner(sgn, gotPub, "kms-"+alg),
			)
			assertIssueValidate(t, iss, iss)
		})
	}
}

// tokenIssuer + validator are the minimal surface assertIssueValidate
// needs; every issuer satisfies both.
type tokenIssuer interface {
	Issue(context.Context, *sso.Subject, []string) (*sso.Token, error)
}
type tokenValidator interface {
	Validate(context.Context, string) (*sso.TokenClaims, error)
}

func assertIssueValidate(t *testing.T, iss tokenIssuer, val tokenValidator) {
	t.Helper()
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u1", ClientID: "c1"}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := val.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v (bridged signature rejected by the issuer's own verifier)", err)
	}
	if claims.Subject != "u1" {
		t.Errorf("subject = %q, want u1", claims.Subject)
	}
}

// cryptoSignerAccessor is the SAML/PKIX signing seam an issuer exposes: the
// active key as a stdlib crypto.Signer (+ its public key + kid). Asserting it
// here (in the cryptosigner package's external test) proves the bridge's
// CryptoSigner() correctly surfaces the UNDERLYING out-of-process signer all
// the way through the issuer accessor — the bridge-side half of the seam.
type cryptoSignerAccessor interface {
	CryptoSigner() (crypto.Signer, crypto.PublicKey, string)
}

// TestCryptoSigner_BridgeUnwrapsUnderlyingKey proves that for each algorithm,
// an issuer wired with a cryptosigner BRIDGE exposes — via CryptoSigner() —
// the UNDERLYING crypto.Signer (the stand-in KMS/HSM key), not the bridge.
// The check is Public()-equality with the key the bridge wraps: SAML/XML-DSig
// thus signs with the exact key published in JWKS, even for an external key.
func TestCryptoSigner_BridgeUnwrapsUnderlyingKey(t *testing.T) {
	t.Parallel()
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	edSgn, edBridgePub, _ := cryptosigner.Ed25519(edPriv)
	ecSgn, ecBridgePub, _ := cryptosigner.ECDSA(ecPriv)
	rsaSgn, rsaBridgePub, _ := cryptosigner.RSA(rsaPriv, cryptosigner.AlgRS256)

	cases := []struct {
		name    string
		iss     cryptoSignerAccessor
		wantPub crypto.PublicKey
		kid     string
		// equal compares the accessor-returned signer's Public() to the
		// underlying KMS key, per-alg (each public key type has its own Equal).
		equal func(got crypto.PublicKey) bool
	}{
		{
			name:    "ed25519",
			iss:     defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519ExternalSigner(edSgn, edBridgePub, "kms-ed25519")),
			wantPub: edPub,
			kid:     "kms-ed25519",
			equal:   func(got crypto.PublicKey) bool { p, ok := got.(ed25519.PublicKey); return ok && p.Equal(edPub) },
		},
		{
			name:    "es256",
			iss:     defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAExternalSigner(ecSgn, ecBridgePub, "kms-es256")),
			wantPub: &ecPriv.PublicKey,
			kid:     "kms-es256",
			equal: func(got crypto.PublicKey) bool {
				p, ok := got.(*ecdsa.PublicKey)
				return ok && p.Equal(&ecPriv.PublicKey)
			},
		},
		{
			name:    "rs256",
			iss:     defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAExternalSigner(rsaSgn, rsaBridgePub, "kms-rs256")),
			wantPub: &rsaPriv.PublicKey,
			kid:     "kms-rs256",
			equal: func(got crypto.PublicKey) bool {
				p, ok := got.(*rsa.PublicKey)
				return ok && p.Equal(&rsaPriv.PublicKey)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, pub, kid := tc.iss.CryptoSigner()
			if signer == nil {
				t.Fatal("issuer wired with a cryptosigner bridge returned a nil crypto.Signer")
			}
			if kid != tc.kid {
				t.Errorf("kid = %q, want %q", kid, tc.kid)
			}
			if !tc.equal(signer.Public()) {
				t.Error("CryptoSigner() did not unwrap to the underlying (KMS) key — SAML would sign with the wrong key")
			}
			if !tc.equal(pub) {
				t.Error("accessor public key != underlying key (would mismatch JWKS)")
			}
		})
	}
}

func TestWrongKeyType(t *testing.T) {
	t.Parallel()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = edPub

	if _, _, err := cryptosigner.Ed25519(rsaKey); err == nil {
		t.Error("Ed25519 accepted an RSA signer")
	}
	if _, _, err := cryptosigner.ECDSA(edPriv); err == nil {
		t.Error("ECDSA accepted an Ed25519 signer")
	}
	if _, _, err := cryptosigner.RSA(ecKey, cryptosigner.AlgRS256); err == nil {
		t.Error("RSA accepted an ECDSA signer")
	}
}

func TestECDSA_RejectsNonP256(t *testing.T) {
	t.Parallel()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if _, _, err := cryptosigner.ECDSA(p384); err == nil {
		t.Error("ECDSA accepted a P-384 key; want P-256 only")
	}
}

func TestRSA_RejectsSmallKeyAndBadAlg(t *testing.T) {
	t.Parallel()
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if _, _, err := cryptosigner.RSA(small, cryptosigner.AlgRS256); err == nil {
		t.Error("RSA accepted a 1024-bit key; want >= 2048")
	}
	ok, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if _, _, err := cryptosigner.RSA(ok, "HS256"); err == nil {
		t.Error("RSA accepted alg HS256; want RS256/PS256 only")
	}
}

func TestNilSigner(t *testing.T) {
	t.Parallel()
	if _, _, err := cryptosigner.Ed25519(nil); err == nil {
		t.Error("Ed25519(nil) did not error")
	}
	if _, _, err := cryptosigner.ECDSA(nil); err == nil {
		t.Error("ECDSA(nil) did not error")
	}
	if _, _, err := cryptosigner.RSA(nil, cryptosigner.AlgRS256); err == nil {
		t.Error("RSA(nil) did not error")
	}
}

func TestContextCancellationFailsClosed(t *testing.T) {
	t.Parallel()
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	sgn, _, err := cryptosigner.Ed25519(edPriv)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sgn.Sign(ctx, []byte("header.payload")); err == nil {
		t.Error("Sign with a cancelled context did not fail closed")
	}
}
