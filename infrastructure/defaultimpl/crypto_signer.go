package defaultimpl

import "crypto"

// cryptoSignerProvider is the seam by which a JWT issuer's signing key can
// be borrowed as a stdlib [crypto.Signer] for NON-JWT protocols (SAML 2.0 /
// XML-DSig and other PKIX consumers), WITHOUT routing through the
// JWS-specific {Ed25519,ECDSA,RSA}Signer interfaces.
//
// WHY a distinct seam (not the existing {Algo}Signer): the {Algo}Signer
// contract is "give me the JWS signing input bytes, get back a JWS-shaped
// signature" — ECDSA/RSA software signers SHA-256-HASH the message
// INTERNALLY, and the cryptosigner bridge converts ECDSA DER->R‖S to fit
// JWS (RFC 7518 §3.4). XML-DSig and PKIX libraries instead drive a
// [crypto.Signer] directly: they compute the digest themselves and hand
// Sign a PRE-HASHED digest (ECDSA/RSA) — or, for Ed25519, the raw message
// with HashFunc()==0. Reusing the {Algo}Signer would DOUBLE-HASH (the
// DSig-computed digest would be hashed again) and force a DER<->R‖S round
// trip the DSig stack neither wants nor expects. So the SAML/PKIX surface
// gets the underlying stdlib crypto.Signer unmodified.
//
// CRITICAL: a crypto.Signer only SIGNS — it never exposes the private key
// MATERIAL. Borrowing it leaks no key bytes. The key returned is the SAME
// one published in JWKS (so a SAML SP validates assertions against the
// metadata/JWKS it already trusts), and it works identically for an
// in-process software key and an external KMS/HSM key (the bridge returns
// the underlying out-of-process signer).
//
// Unexported on purpose: the public surface is the issuers' CryptoSigner()
// accessor below. An implementation that CANNOT expose a stdlib
// crypto.Signer (a hypothetical future opaque signer) simply does not
// satisfy this interface, and the accessor degrades to "no SAML signing"
// rather than panicking.
type cryptoSignerProvider interface {
	CryptoSigner() crypto.Signer
}

// CryptoSigner on the software signers returns the held private key
// directly: ed25519.PrivateKey / *ecdsa.PrivateKey / *rsa.PrivateKey are
// each a stdlib [crypto.Signer] that an XML-DSig / PKIX consumer drives
// correctly under the pre-hashed-digest contract (ECDSA/RSA receive an
// already-computed digest; Ed25519 receives the raw message with
// HashFunc()==0). This is the same key the {Algo}Signer signs JWTs with and
// the same key published in JWKS — never a copy or a different key.

func (s softwareEd25519Signer) CryptoSigner() crypto.Signer { return s.priv }

func (s softwareECDSASigner) CryptoSigner() crypto.Signer { return s.priv }

func (s softwareRSASigner) CryptoSigner() crypto.Signer { return s.priv }

// Interface guards: the software signers expose their key as a stdlib
// crypto.Signer for the SAML/PKIX seam. The cryptosigner bridge types
// satisfy cryptoSignerProvider structurally too, but their guard lives in
// the cryptosigner package (defaultimpl must not import its sub-bridge —
// that is a backwards edge).
var (
	_ cryptoSignerProvider = softwareEd25519Signer{}
	_ cryptoSignerProvider = softwareECDSASigner{}
	_ cryptoSignerProvider = softwareRSASigner{}
)

// CryptoSigner exposes this issuer's ACTIVE signing key as a stdlib
// [crypto.Signer] for NON-JWT consumers — chiefly SAML 2.0 / XML-DSig and
// other PKIX libraries that sign over a PRE-HASHED digest (the contract a
// crypto.Signer takes: ECDSA/RSA get an already-computed digest, Ed25519
// gets the raw message with HashFunc()==0). It returns (signer, publicKey,
// kid):
//
//   - signer: nil when no signer is wired, or when the wired signer cannot
//     expose a stdlib crypto.Signer (e.g. a future opaque signer that only
//     implements the JWS {Algo}Signer seam). A nil return means "this issuer
//     can't drive SAML signing" — the caller omits SAML signing rather than
//     the process panicking.
//   - publicKey + kid: the SAME public key + key id published in JWKS, so a
//     SAML SP validates assertions against the metadata/JWKS it already
//     fetched — no second trust anchor.
//
// Read under keyMu.RLock so the (signer, publicKey, kid) triple is a
// CONSISTENT snapshot even if RotateKey fires concurrently — the borrowed
// signer and the returned kid/publicKey always name the same key. For an
// external (KMS/HSM) key the returned crypto.Signer is the out-of-process
// signer the cryptosigner bridge holds, so SAML signs with the exact key in
// JWKS without the private material ever entering this process.
func (j *Ed25519JWTIssuer) CryptoSigner() (crypto.Signer, crypto.PublicKey, string) {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	if j.signer == nil {
		return nil, nil, ""
	}
	if cs, ok := j.signer.(cryptoSignerProvider); ok {
		return cs.CryptoSigner(), j.publicKey, j.keyID
	}
	return nil, nil, ""
}

// CryptoSigner exposes this ES256 issuer's active signing key as a stdlib
// [crypto.Signer] for SAML 2.0 / XML-DSig / PKIX consumers. See the Ed25519
// sibling for the full rationale (pre-hashed-digest contract, JWKS-key
// reuse, external-key support, keyMu-guarded snapshot, nil/not-a-provider
// degradation).
func (j *ECDSAJWTIssuer) CryptoSigner() (crypto.Signer, crypto.PublicKey, string) {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	if j.signer == nil {
		return nil, nil, ""
	}
	if cs, ok := j.signer.(cryptoSignerProvider); ok {
		return cs.CryptoSigner(), j.publicKey, j.keyID
	}
	return nil, nil, ""
}

// CryptoSigner exposes this RSA issuer's active signing key as a stdlib
// [crypto.Signer] for SAML 2.0 / XML-DSig / PKIX consumers. See the Ed25519
// sibling for the full rationale. The padding scheme (RS256 vs PS256) is
// NOT encoded here — a crypto.Signer's caller selects the SignerOpts at
// sign time; the SAML/DSig stack chooses the XML signature method
// independently of how this issuer signs JWTs.
func (j *RSAJWTIssuer) CryptoSigner() (crypto.Signer, crypto.PublicKey, string) {
	j.keyMu.RLock()
	defer j.keyMu.RUnlock()
	if j.signer == nil {
		return nil, nil, ""
	}
	if cs, ok := j.signer.(cryptoSignerProvider); ok {
		return cs.CryptoSigner(), j.publicKey, j.keyID
	}
	return nil, nil, ""
}
