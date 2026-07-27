package sp

import (
	"errors"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// errWeakSignatureAlgorithm is returned when an enveloped XML-DSig signature
// uses a SHA-1 SignatureMethod or DigestMethod. goxmldsig's ValidationContext
// has no algorithm allowlist of its own — it cryptographically verifies
// whatever algorithm the XML declares, including SHA-1, a collision-prone
// hash the SAML/XML-DSig ecosystem has deprecated. Callers collapse this to
// the same oracle-safe error as every other verification failure. Mirrors
// infrastructure/saml/idp/weak_signature_algorithms.go — the SP side (this
// package) verifies assertions/LogoutRequests FROM the upstream IdP and needs
// the identical no-SHA-1 posture.
var errWeakSignatureAlgorithm = errors.New("saml/sp: SHA-1 signature/digest algorithm rejected")

// weakXMLDSigAlgorithms are the SHA-1-based XML-DSig URIs goxmldsig
// implements (see russellhaering/goxmldsig's xml_constants.go) but this
// codebase refuses to accept for verification, regardless of whether the
// signature otherwise cryptographically validates.
var weakXMLDSigAlgorithms = map[string]bool{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":        true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": true,
	"http://www.w3.org/2000/09/xmldsig#sha1":            true,
}

// rejectWeakSignatureAlgorithms inspects EVERY SignatureMethod and
// DigestMethod element under root (there may be more than one Reference per
// SignedInfo) and fails closed if any use a SHA-1 algorithm URI, or if NONE
// are present at all (an enveloped signature verification is meaningless
// without a SignatureMethod to have verified against). Call this in addition
// to — never instead of — the actual cryptographic ValidationContext.Validate
// call; this only narrows which ALREADY-VALID algorithms are acceptable.
func rejectWeakSignatureAlgorithms(root *etree.Element) error {
	methods := root.FindElements(".//SignatureMethod")
	digests := root.FindElements(".//DigestMethod")
	if len(methods) == 0 || len(digests) == 0 {
		return errWeakSignatureAlgorithm
	}
	for _, m := range methods {
		if weakXMLDSigAlgorithms[m.SelectAttrValue("Algorithm", "")] {
			return errWeakSignatureAlgorithm
		}
	}
	for _, d := range digests {
		if weakXMLDSigAlgorithms[d.SelectAttrValue("Algorithm", "")] {
			return errWeakSignatureAlgorithm
		}
	}
	return nil
}

// envelopedAlgGuard is the crewjam saml.SignatureVerifier that gates the
// assertion HTTP-POST path. crewjam hands it the (detached) element it is
// about to validate plus the prepared ValidationContext; rejecting a SHA-1
// SignatureMethod/DigestMethod before delegating to the context's standard
// Validate closes the gap crewjam's default (SignatureVerifier == nil) path
// leaves open — ParseXMLResponse otherwise calls validationContext.Validate
// directly against goxmldsig's SHA-1-inclusive algorithm map.
type envelopedAlgGuard struct{}

func (envelopedAlgGuard) VerifySignature(ctx *dsig.ValidationContext, el *etree.Element) error {
	if err := rejectWeakSignatureAlgorithms(el); err != nil {
		return err
	}
	_, err := ctx.Validate(el)
	return err
}
