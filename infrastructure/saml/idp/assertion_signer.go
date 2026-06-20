// Package idp implements the SAML 2.0 Identity Provider (IdP) side of the SSO
// server as part of the SEPARATE nested saml/ module: this server ISSUES a
// SIGNED SAML assertion that a downstream Service Provider (SP) trusts. It is
// the mirror image of saml/sp (which CONSUMES an upstream IdP's assertion).
//
// SECURITY POSTURE. The assertion is what an SP authenticates a user on, so
// the signing path is the trust root:
//
//   - The assertion (not merely the enclosing Response) is XML-DSig signed,
//     enveloped, exclusive-C14N, SHA-256 — an SP that only checks the
//     assertion signature (the common, safer posture, and exactly what
//     saml/sp does) still validates.
//   - The signing key is resolved PER-TENANT through the same
//     deps.IssuerForClient path the rest of the server signs tokens with, and
//     the published metadata cert wraps that SAME key — so the SP validates
//     against the metadata it already fetched, with NO second trust anchor.
//     Metadata + assertion MUST use the identical IssuerForClient resolution
//     (blueprint Risk 3) or an SP would reject assertions it can't match to
//     the advertised cert.
//   - The assertion is ONLY POSTed to a registered ACS URL (the SP's
//     pre-registered allowlist), never a response-supplied one
//     (assertion-exfiltration defense).
//   - Pending-AuthnRequest lookup is single-use + oracle-safe: unknown,
//     expired, consumed, or invalid-session all collapse to ONE
//     saml_request_invalid.
package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// ErrUnsupportedSigningKey is returned when the per-tenant issuer's active
// signing key cannot drive XML-DSig. The ONLY unsupported stdlib key is
// Ed25519: goxmldsig v1.4.0 has NO Ed25519/EdDSA XML signature-method
// identifier (its signatureMethodIdentifiers map covers only x509.RSA +
// x509.ECDSA), so an Ed25519 issuer cannot sign a SAML assertion — the same
// "no EdDSA" wall AWS KMS hits. An operator running SAML IdP MUST configure an
// RSA (RS256/PS256) or ECDSA (ES256) signing key. Mirrors awskms'
// ErrUnsupportedKey: fail loud, never silently downgrade.
var ErrUnsupportedSigningKey = errors.New("saml/idp: unsupported signing key for XML-DSig (need RSA or ECDSA; Ed25519/EdDSA is not an XML-DSig signature method)")

// AssertionSigner adapts a per-tenant JWT issuer's stdlib [crypto.Signer]
// (borrowed via the Phase A CryptoSigner() seam) into the goxmldsig signing
// surface, plus the self-signed X.509 certificate that wraps the issuer's
// JWKS public key for the DSig KeyInfo and the published metadata.
//
// # Why no DER->R‖S conversion (the crewjam/goxmldsig interop fact)
//
// The blueprint flagged that XML-DSig's wire format for ECDSA is raw R‖S
// (W3C XML-DSig / RFC 4051), whereas a stdlib *ecdsa.PrivateKey.Sign returns
// ASN.1 DER — so a naive crypto.Signer would emit DER where the spec wants
// R‖S. We INVESTIGATED goxmldsig v1.4.0 directly (the version pinned in
// saml/go.mod, and the SAME library this module's SP side validates with):
//
//   - SIGN (sign.go signDigest): takes ctx.signer.Sign(rand, digest, Hash)
//     and writes the RETURNED BYTES VERBATIM as the SignatureValue — no
//     re-encoding. For a stdlib ECDSA key that is ASN.1 DER.
//   - VALIDATE (validate.go verifySignedInfo): calls
//     cert.CheckSignature(algo, canonical, decodedSignature). stdlib
//     x509.CheckSignature for an ECDSA algorithm parses the signature as
//     ASN.1 DER (ecdsa.VerifyASN1).
//
// So goxmldsig's sign and validate halves are INTERNALLY CONSISTENT on DER
// for ECDSA — and crewjam's ServiceProvider validation goes through that SAME
// goxmldsig ValidationContext. If we forced R‖S here, crewjam's own
// validation (and this repo's saml/sp ParseXMLResponse) would REJECT the
// assertion. Therefore the correct adapter is a PASS-THROUGH: hand goxmldsig
// the issuer's crypto.Signer unmodified and let stdlib produce DER (ECDSA) /
// PKCS#1 v1.5 (RSA). The DER->R‖S concern from the blueprint does NOT apply to
// goxmldsig v1.4.0. (A future SP that validates with a strict W3C-R‖S library
// would need a conversion shim; goxmldsig is not such a library.)
//
// For RSA: goxmldsig passes opts == crypto.SHA256 (a crypto.Hash, NOT
// *rsa.PSSOptions), so an *rsa.PrivateKey signs PKCS#1 v1.5 — which is exactly
// what the RSA-SHA256 XML signature method denotes, regardless of whether the
// issuer signs JWTs as RS256 or PS256. A KMS-backed RSA signer's Sign must
// likewise honor the crypto.SHA256 opts as PKCS#1 v1.5.
type AssertionSigner struct {
	// signer is the issuer's active signing key as a stdlib crypto.Signer
	// (in-process software key, or an out-of-process KMS/HSM signer behind the
	// cryptosigner bridge — either way the private material never leaves where
	// it lives). goxmldsig drives it under the pre-hashed-digest contract.
	signer crypto.Signer

	// pub is the issuer's public key (== the JWKS public key). Public() returns
	// it so goxmldsig's getPublicKeyAlgorithm classifies the key (RSA vs ECDSA)
	// and selects the matching x509 algorithm at validate time.
	pub crypto.PublicKey

	// kid is the issuer's key id (== the JWKS kid). Carried for diagnostics /
	// audit correlation; the SP trusts the cert in KeyInfo, not the kid.
	kid string

	// sigMethod is the goxmldsig XML signature-method identifier chosen by key
	// type at construction (RSA-SHA256 or ECDSA-SHA256). Fixed once so every
	// assertion this signer produces is alg-stable.
	sigMethod string

	// certOnce + cert lazily build the self-signed X.509 cert wrapping pub
	// EXACTLY ONCE, then cache it. Metadata and every assertion's KeyInfo embed
	// the same cert, so the SP sees one consistent signing certificate. WHY
	// lazy+cached: cert generation is a small CPU cost we pay once per
	// (issuer-key) lifetime, not per metadata/assertion request, and a single
	// cached cert keeps the published-vs-signing identity trivially equal.
	certOnce sync.Once
	cert     *x509.Certificate
	certErr  error

	// issuerName + notAfter parameterize the synthetic cert (CommonName +
	// validity). They are cosmetic to the trust decision (the SP pins the cert
	// bytes, not its subject/validity — goxmldsig validates the signature, and
	// crewjam's getIDPSigningCerts reads the cert without a chain/expiry check),
	// but a sane validity window keeps the cert presentable to operators
	// inspecting metadata.
	issuerName string
	notAfter   time.Time
}

// NewAssertionSigner adapts the (signer, publicKey, kid) triple borrowed from a
// per-tenant issuer's CryptoSigner() into an AssertionSigner, selecting the XML
// signature method by key type. A nil signer (issuer has no signing key, or
// the wired signer can't expose a stdlib crypto.Signer) or an Ed25519 key
// yields ErrUnsupportedSigningKey — the caller MUST fail closed (HTTP 500
// saml_assertion_failed), never fall back to a different tenant's key.
//
// issuerName seeds the synthetic cert CommonName (typically the SP-resolved AS
// issuer URL). It does not affect the trust decision.
func NewAssertionSigner(signer crypto.Signer, pub crypto.PublicKey, kid, issuerName string) (*AssertionSigner, error) {
	if signer == nil {
		return nil, ErrUnsupportedSigningKey
	}
	// Classify by the PUBLIC key (the authority on key type) and reject Ed25519
	// up front so the failure is a clear typed error, not a deep goxmldsig
	// "unsupported hash mechanism" further down.
	var method string
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		method = dsig.RSASHA256SignatureMethod
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() {
			// goxmldsig has SHA-384/512 ECDSA methods, but the SSO ECDSA issuer
			// is P-256 (ES256) only; refuse anything else rather than emit a
			// digest/curve-mismatched signature.
			return nil, ErrUnsupportedSigningKey
		}
		method = dsig.ECDSASHA256SignatureMethod
	default:
		// Ed25519 (ed25519.PublicKey) and anything else: not an XML-DSig key.
		return nil, ErrUnsupportedSigningKey
	}

	return &AssertionSigner{
		signer:     signer,
		pub:        pub,
		kid:        kid,
		sigMethod:  method,
		issuerName: issuerName,
		notAfter:   time.Now().Add(10 * 365 * 24 * time.Hour), // 10y synthetic cert window
	}, nil
}

// newCertOnlyAssertionSigner builds an AssertionSigner that can produce the
// self-signed Certificate() (and report KeyID()) but CANNOT XML-DSig-sign:
// sigMethod is left empty, so SigningContext() fails loud if ever called. It is
// used ONLY by the metadata endpoint's graceful Ed25519 fallback — to publish
// the KeyDescriptor cert of an Ed25519 issuer while serving the metadata
// UNSIGNED (goxmldsig has no EdDSA signature method). It does NOT relax the
// assertion path: NewAssertionSigner (and signerForClient, which the assertion /
// SLO paths use) still rejects Ed25519, so an assertion is NEVER signed with a
// non-XML-DSig key. A nil signer still errors. x509 can self-sign an Ed25519 key
// (buildCert delegates to CreateCertificate), so the cert builds for any key
// type here.
func newCertOnlyAssertionSigner(signer crypto.Signer, pub crypto.PublicKey, kid, issuerName string) (*AssertionSigner, error) {
	if signer == nil {
		return nil, ErrUnsupportedSigningKey
	}
	return &AssertionSigner{
		signer:     signer,
		pub:        pub,
		kid:        kid,
		sigMethod:  "", // no XML-DSig method: cert-only
		issuerName: issuerName,
		notAfter:   time.Now().Add(10 * 365 * 24 * time.Hour),
	}, nil
}

// Public implements crypto.Signer: it returns the issuer's public key so
// goxmldsig's getPublicKeyAlgorithm classifies the key (RSA/ECDSA) and the
// SignatureMethod is consistent with what an SP verifies against the cert.
func (s *AssertionSigner) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer by delegating UNMODIFIED to the issuer's
// signer. The returned bytes are written verbatim by goxmldsig as the XML
// SignatureValue: RSA → PKCS#1 v1.5 (the RSA-SHA256 method); ECDSA → ASN.1 DER
// (which goxmldsig/crewjam validation, via x509.CheckSignature, expects — see
// the type doc for why this is correct, not a bug). No DER->R‖S re-encoding.
//
// digest is the PRE-HASHED message (goxmldsig computes the SHA-256 digest of
// the canonicalized SignedInfo and hands it here); opts is crypto.SHA256.
func (s *AssertionSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(r, digest, opts)
}

// SignatureMethod returns the goxmldsig XML signature-method identifier this
// signer uses (RSA-SHA256 or ECDSA-SHA256). The caller passes it to
// SigningContext.SetSignatureMethod.
func (s *AssertionSigner) SignatureMethod() string { return s.sigMethod }

// KeyID returns the JWKS kid of the underlying signing key (diagnostics).
func (s *AssertionSigner) KeyID() string { return s.kid }

// Certificate returns the self-signed X.509 certificate wrapping the issuer's
// public key, generated once and cached. The SAME cert is published in IdP
// metadata (KeyDescriptor use="signing") and embedded in every assertion's
// DSig KeyInfo, so an SP validates assertions against the cert it fetched from
// metadata. A signing key that can't be wrapped (should not happen for a
// classified RSA/ECDSA key) surfaces the generation error.
func (s *AssertionSigner) Certificate() (*x509.Certificate, error) {
	s.certOnce.Do(func() {
		s.cert, s.certErr = s.buildCert()
	})
	return s.cert, s.certErr
}

// SigningContext builds a goxmldsig SigningContext bound to this signer +
// cert, configured exactly like crewjam's IdP reference: exclusive C14N with
// an EMPTY prefix list (the prefix list MUST be empty — several C14N
// implementations mishandle non-empty lists, per crewjam) and the key-typed
// signature method. The cert bytes go into the context so the produced
// Signature carries the KeyInfo/X509Certificate an SP pins.
func (s *AssertionSigner) SigningContext() (*dsig.SigningContext, error) {
	// A cert-only signer (newCertOnlyAssertionSigner, the metadata Ed25519
	// fallback) has no XML-DSig method — refuse loudly rather than emit an
	// unsigned/invalid context. Callers gate the signed path on SignatureMethod()
	// != "" so this is defense-in-depth.
	if s.sigMethod == "" {
		return nil, ErrUnsupportedSigningKey
	}
	cert, err := s.Certificate()
	if err != nil {
		return nil, err
	}
	ctx, err := dsig.NewSigningContext(s, [][]byte{cert.Raw})
	if err != nil {
		return nil, err
	}
	// Empty prefix list, per crewjam canonicalizerPrefixList — non-empty lists
	// are unreliable across XML-C14N implementations.
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(s.sigMethod); err != nil {
		return nil, err
	}
	return ctx, nil
}

// buildCert mints a self-signed X.509 certificate over the issuer's public
// key. WHY self-signed: SAML metadata KeyDescriptors carry a bare signing
// certificate the SP pins by its bytes; there is no PKI chain to validate (an
// SP trusts "the cert in this IdP's metadata", full stop). The cert is a
// thin, standards-shaped envelope around the JWKS public key so XML-DSig's
// X509Data slot has something to hold — the signature itself is what an SP
// verifies, against this exact public key.
//
// It is self-signed WITH the issuer's own crypto.Signer (this AssertionSigner),
// so even a KMS/HSM key — whose private material never enters the process —
// produces a valid self-signature without exporting the key.
func (s *AssertionSigner) buildCert() (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("saml/idp: cert serial: %w", err)
	}
	cn := s.issuerName
	if cn == "" {
		cn = "saml-idp-signing"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              s.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	// CreateCertificate signs the template with `s` (a crypto.Signer) over
	// s.pub — the standard self-signed form. The signature algorithm is derived
	// from the key type, matching how the assertion is signed.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, s.pub, s)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: self-sign signing cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: parse self-signed cert: %w", err)
	}
	return cert, nil
}
