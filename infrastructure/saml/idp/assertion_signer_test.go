package idp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// TestAssertionSigner_RSA_SignatureMethodAndCert proves the RSA adapter selects
// RSA-SHA256 and wraps the RSA public key in a self-signed cert.
func TestAssertionSigner_RSA(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, err := NewAssertionSigner(key, &key.PublicKey, "kid-rsa", "issuer")
	if err != nil {
		t.Fatalf("NewAssertionSigner(RSA): %v", err)
	}
	if s.SignatureMethod() != dsig.RSASHA256SignatureMethod {
		t.Errorf("RSA method = %q, want RSA-SHA256", s.SignatureMethod())
	}
	cert, err := s.Certificate()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("cert public key type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
}

// TestAssertionSigner_ECDSA proves the ECDSA adapter selects ECDSA-SHA256 and
// wraps the EC public key.
func TestAssertionSigner_ECDSA(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewAssertionSigner(key, &key.PublicKey, "kid-ec", "issuer")
	if err != nil {
		t.Fatalf("NewAssertionSigner(ECDSA): %v", err)
	}
	if s.SignatureMethod() != dsig.ECDSASHA256SignatureMethod {
		t.Errorf("ECDSA method = %q, want ECDSA-SHA256", s.SignatureMethod())
	}
	cert, err := s.Certificate()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("cert public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
}

// TestAssertionSigner_Ed25519_Rejected proves an Ed25519 key (no XML-DSig
// method in goxmldsig) is rejected with ErrUnsupportedSigningKey.
func TestAssertionSigner_Ed25519_Rejected(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewAssertionSigner(priv, pub, "kid-ed", "issuer"); err != ErrUnsupportedSigningKey {
		t.Errorf("Ed25519 err = %v, want ErrUnsupportedSigningKey", err)
	}
}

// TestAssertionSigner_NilSigner_Rejected proves a nil signer (issuer can't
// expose a crypto.Signer) is rejected — the fail-closed precondition.
func TestAssertionSigner_NilSigner_Rejected(t *testing.T) {
	t.Parallel()
	if _, err := NewAssertionSigner(nil, nil, "", "issuer"); err != ErrUnsupportedSigningKey {
		t.Errorf("nil-signer err = %v, want ErrUnsupportedSigningKey", err)
	}
}

// TestAssertionSigner_NonP256ECDSA_Rejected proves a non-P-256 EC key is
// rejected (the ES256 issuer is P-256 only).
func TestAssertionSigner_NonP256ECDSA_Rejected(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewAssertionSigner(key, &key.PublicKey, "kid", "issuer"); err != ErrUnsupportedSigningKey {
		t.Errorf("P-384 err = %v, want ErrUnsupportedSigningKey", err)
	}
}

// TestAssertionSigner_CertCachedStable proves Certificate() returns the SAME
// cert on repeated calls (generated once, cached) — so metadata and every
// assertion embed an identical cert.
func TestAssertionSigner_CertCachedStable(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := NewAssertionSigner(key, &key.PublicKey, "kid", "issuer")
	c1, err := s.Certificate()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	c2, _ := s.Certificate()
	if c1 != c2 {
		t.Error("Certificate() returned different pointers — not cached")
	}
}

// TestAssertionSigner_EnvelopedSignatureValidates is the end-to-end DSig proof
// for BOTH RSA and ECDSA: sign an element with the AssertionSigner via
// goxmldsig, then validate it with goxmldsig against the signer's own cert —
// proving the produced signature (PKCS#1 v1.5 for RSA, ASN.1 DER for ECDSA) is
// exactly what the validation engine (and crewjam, and the SP side) expects.
// This is the test that would FAIL if we wrongly converted ECDSA DER->R‖S.
func TestAssertionSigner_EnvelopedSignatureValidates(t *testing.T) {
	t.Parallel()
	t.Run("RSA", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		s, _ := NewAssertionSigner(key, &key.PublicKey, "kid", "issuer")
		signAndValidate(t, s)
	})
	t.Run("ECDSA", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		s, _ := NewAssertionSigner(key, &key.PublicKey, "kid", "issuer")
		signAndValidate(t, s)
	})
}

func signAndValidate(t *testing.T, s *AssertionSigner) {
	t.Helper()
	// Build a minimal element with an ID (goxmldsig signs by reference URI).
	el := etree.NewElement("Thing")
	el.CreateAttr("ID", "_abc123")
	el.CreateElement("Child").SetText("hello")

	ctx, err := s.SigningContext()
	if err != nil {
		t.Fatalf("signing context: %v", err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatalf("sign enveloped: %v", err)
	}

	// Serialize + reparse before validating — this is what a real SP (and
	// crewjam's ParseXMLResponse) does: it validates freshly-parsed bytes, not
	// the in-memory post-sign tree. goxmldsig's Validate on the un-serialized
	// element mis-handles namespace context; round-tripping through bytes (the
	// shape the response ALWAYS takes on the wire) is the correct validation.
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	reparsed := etree.NewDocument()
	if err := reparsed.ReadFromBytes(raw); err != nil {
		t.Fatalf("reparse: %v", err)
	}

	cert, _ := s.Certificate()
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	vctx := dsig.NewDefaultValidationContext(store)
	if _, err := vctx.Validate(reparsed.Root()); err != nil {
		t.Fatalf("signature did NOT validate: %v", err)
	}
}
