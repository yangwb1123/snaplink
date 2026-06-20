package defaultimpl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// TestCryptoSigner_Ed25519 proves the Ed25519 issuer's CryptoSigner()
// returns a stdlib crypto.Signer that (1) reports the SAME public key + kid
// the issuer publishes in JWKS, and (2) signs the RAW message under the
// Ed25519 crypto.Signer contract (HashFunc()==0) — a signature ed25519.Verify
// accepts. Ed25519 signs the message directly, so there is no pre-hash to
// double; this case locks the "raw message in" half of the seam.
func TestCryptoSigner_Ed25519(t *testing.T) {
	iss := NewEd25519JWTIssuer(WithEd25519Issuer("https://sso.test"))

	signer, pub, kid := iss.CryptoSigner()
	if signer == nil {
		t.Fatal("CryptoSigner() returned nil signer for an in-process Ed25519 issuer")
	}
	if kid != iss.KeyID() {
		t.Errorf("kid = %q, want issuer KeyID() %q", kid, iss.KeyID())
	}

	// The returned crypto.Signer's Public() must equal both the accessor's
	// returned public key AND the issuer's JWKS-published key.
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("accessor public key is %T, want ed25519.PublicKey", pub)
	}
	signerPub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("signer.Public() is %T, want ed25519.PublicKey", signer.Public())
	}
	if !edPub.Equal(signerPub) {
		t.Error("signer.Public() != accessor public key")
	}
	if !edPub.Equal(iss.PublicKey()) {
		t.Error("accessor public key != issuer PublicKey() (would mismatch JWKS)")
	}

	// Ed25519 crypto.Signer signs the raw message with HashFunc()==0.
	msg := []byte("saml-assertion-signing-input")
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(edPub, msg, sig) {
		t.Error("ed25519.Verify rejected a signature from the borrowed crypto.Signer")
	}
}

// TestCryptoSigner_ECDSA proves the ES256 issuer's CryptoSigner() returns a
// crypto.Signer that signs a PRE-HASHED SHA-256 digest and emits ASN.1 DER
// (the XML-DSig / PKIX contract), verifiable with ecdsa.VerifyASN1 over that
// SAME digest. This is the load-bearing NO-DOUBLE-HASH proof: we hash once,
// hand the digest to Sign, and verify against the identical digest. If the
// seam re-hashed internally (like the JWS ECDSASigner does), VerifyASN1 over
// the single digest would FAIL.
func TestCryptoSigner_ECDSA_NoDoubleHash(t *testing.T) {
	iss := NewECDSAJWTIssuer(WithECDSAIssuer("https://sso.test"))

	signer, pub, kid := iss.CryptoSigner()
	if signer == nil {
		t.Fatal("CryptoSigner() returned nil signer for an in-process ECDSA issuer")
	}
	if kid != iss.KeyID() {
		t.Errorf("kid = %q, want issuer KeyID() %q", kid, iss.KeyID())
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("accessor public key is %T, want *ecdsa.PublicKey", pub)
	}
	signerPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("signer.Public() is %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !ecPub.Equal(signerPub) {
		t.Error("signer.Public() != accessor public key")
	}
	if !ecPub.Equal(iss.PublicKey()) {
		t.Error("accessor public key != issuer PublicKey() (would mismatch JWKS)")
	}

	// Hash ONCE; sign the digest; verify the DER signature over the SAME
	// digest. crypto/ecdsa.PrivateKey.Sign returns ASN.1 DER (the DSig form).
	msg := []byte("xml-dsig-canonicalized-bytes")
	digest := sha256.Sum256(msg)
	der, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(ecPub, digest[:], der) {
		t.Error("ecdsa.VerifyASN1 rejected the DER signature over the pre-hashed digest (double-hash or wrong encoding)")
	}
	// Negative control: verifying over a re-hash of the digest must FAIL,
	// confirming the signature is over the digest itself (not a second hash).
	rehash := sha256.Sum256(digest[:])
	if ecdsa.VerifyASN1(ecPub, rehash[:], der) {
		t.Error("signature verified over a DOUBLE-hashed digest — the pre-hashed-digest contract is broken")
	}
}

// TestCryptoSigner_RSA proves the RSA issuer's CryptoSigner() returns a
// crypto.Signer that signs a PRE-HASHED SHA-256 digest (PKCS1v15), verifiable
// with rsa.VerifyPKCS1v15 over that SAME digest — the no-double-hash proof
// for the RSA family.
func TestCryptoSigner_RSA_NoDoubleHash(t *testing.T) {
	iss := NewRSAJWTIssuer(WithRSAIssuer("https://sso.test"))

	signer, pub, kid := iss.CryptoSigner()
	if signer == nil {
		t.Fatal("CryptoSigner() returned nil signer for an in-process RSA issuer")
	}
	if kid != iss.KeyID() {
		t.Errorf("kid = %q, want issuer KeyID() %q", kid, iss.KeyID())
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("accessor public key is %T, want *rsa.PublicKey", pub)
	}
	signerPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("signer.Public() is %T, want *rsa.PublicKey", signer.Public())
	}
	if !rsaPub.Equal(signerPub) {
		t.Error("signer.Public() != accessor public key")
	}
	if !rsaPub.Equal(iss.PublicKey()) {
		t.Error("accessor public key != issuer PublicKey() (would mismatch JWKS)")
	}

	msg := []byte("xml-dsig-canonicalized-bytes")
	digest := sha256.Sum256(msg)
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("rsa.VerifyPKCS1v15 rejected the signature over the pre-hashed digest: %v", err)
	}
	rehash := sha256.Sum256(digest[:])
	if rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, rehash[:], sig) == nil {
		t.Error("signature verified over a DOUBLE-hashed digest — the pre-hashed-digest contract is broken")
	}
}

// TestCryptoSigner_NilSigner proves an issuer with no wired signer degrades
// to (nil, nil, "") rather than panicking — the "a signer that can't expose
// a crypto.Signer means no SAML signing" contract. A zero-value issuer has a
// nil signer field, exercising the first guard in the accessor.
func TestCryptoSigner_NilSigner(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signer func() (crypto.Signer, crypto.PublicKey, string)
	}{
		{"ed25519", (&Ed25519JWTIssuer{}).CryptoSigner},
		{"ecdsa", (&ECDSAJWTIssuer{}).CryptoSigner},
		{"rsa", (&RSAJWTIssuer{}).CryptoSigner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, pub, kid := tc.signer()
			if s != nil || pub != nil || kid != "" {
				t.Errorf("nil-signer issuer = (%v, %v, %q), want (nil, nil, \"\")", s, pub, kid)
			}
		})
	}
}

// TestCryptoSigner_ExternalKeyMatchesJWKS proves the seam works for an
// EXTERNAL (KMS/HSM) key: when the issuer is wired with an external signer,
// CryptoSigner() returns the UNDERLYING out-of-process crypto.Signer (so SAML
// signs with the exact key in JWKS) and the kid + public key match what the
// issuer publishes. We stand in for a KMS signer with an in-memory
// crypto.Signer; the point is that the seam returns the wrapped signer the
// cryptosigner bridge holds, not the bridge.
//
// NOTE: the cryptosigner bridge lives in a sub-package, so this test
// constructs the external-signer wiring with a hand-rolled CryptoSigner-
// exposing signer to prove the issuer accessor type-asserts and unwraps it.
// The bridge's own CryptoSigner() is covered in the cryptosigner package
// test.
func TestCryptoSigner_ExternalKeyMatchesJWKS(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		// GenerateKey(nil) uses crypto/rand by default; nil reader is valid.
		t.Fatalf("generate key: %v", err)
	}
	edPub := edPriv.Public().(ed25519.PublicKey)

	ext := externalEd25519{priv: edPriv}
	iss := NewEd25519JWTIssuer(WithEd25519ExternalSigner(ext, edPub, "kms-kid"))

	signer, pub, kid := iss.CryptoSigner()
	if signer == nil {
		t.Fatal("CryptoSigner() returned nil for an external-signer issuer that exposes CryptoSigner")
	}
	if kid != "kms-kid" {
		t.Errorf("kid = %q, want kms-kid", kid)
	}
	// The accessor must hand back the UNDERLYING signer (edPriv), not the
	// wrapper — proven by Public() equality with the JWKS key.
	gotPub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !gotPub.Equal(edPub) {
		t.Error("external CryptoSigner() did not unwrap to the underlying KMS key")
	}
	if ap, ok := pub.(ed25519.PublicKey); !ok || !ap.Equal(edPub) {
		t.Error("accessor public key != external key (would mismatch JWKS)")
	}
}

// externalEd25519 is a stand-in external Ed25519Signer that ALSO exposes its
// underlying key via CryptoSigner — mirroring what the cryptosigner bridge
// does for a real KMS signer. It lets this package-local test prove the
// issuer accessor unwraps an external signer without importing the
// cryptosigner sub-package (a backwards edge). The Sign method satisfies the
// Ed25519Signer interface (used by the issuer's JWT path); CryptoSigner
// satisfies the unexported cryptoSignerProvider seam (used by the SAML path).
type externalEd25519 struct{ priv ed25519.PrivateKey }

func (e externalEd25519) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(e.priv, message), nil
}

func (e externalEd25519) CryptoSigner() crypto.Signer { return e.priv }

var _ Ed25519Signer = externalEd25519{}
