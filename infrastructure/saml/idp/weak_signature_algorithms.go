package idp

import (
	"errors"

	"github.com/beevik/etree"
)

// errWeakSignatureAlgorithm is returned when an enveloped XML-DSig signature
// uses a SHA-1 SignatureMethod or DigestMethod. goxmldsig's ValidationContext
// has no algorithm allowlist of its own — it cryptographically verifies
// whatever algorithm the XML declares, including SHA-1, a collision-prone
// hash the SAML/XML-DSig ecosystem has deprecated. Callers collapse this to
// the same oracle-safe invalid-request code as every other verification
// failure.
var errWeakSignatureAlgorithm = errors.New("saml/idp: SHA-1 signature/digest algorithm rejected")

// weakXMLDSigAlgorithms are the SHA-1-based XML-DSig URIs goxmldsig
// implements (see russellhaering/goxmldsig's xml_constants.go) but this
// codebase refuses to accept for verification, regardless of whether the
// signature otherwise cryptographically validates.
var weakXMLDSigAlgorithms = map[string]bool{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":   true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": true,
	"http://www.w3.org/2000/09/xmldsig#sha1":       true,
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
