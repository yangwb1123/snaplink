package idp

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	dsig "github.com/russellhaering/goxmldsig"
)

// SAML HTTP-Redirect binding DETACHED signatures (SAML Bindings 2.0 §3.4.4.1).
//
// For the HTTP-Redirect binding the SAML message XML is carried UNSIGNED in the
// (DEFLATEd, base64, URL-encoded) SAMLRequest/SAMLResponse query parameter; the
// signature is DETACHED, carried in two SIBLING query parameters SigAlg +
// Signature, computed over the URL-ENCODED query parameters concatenated in the
// EXACT order (RelayState present only when sent):
//
//	SAMLRequest=<v>&RelayState=<v>&SigAlg=<v>      (request direction)
//	SAMLResponse=<v>&RelayState=<v>&SigAlg=<v>     (response direction)
//
// This is what every real IdP/SP (Okta, Azure AD, Shibboleth) produces and
// validates. The previously-used enveloped-XML-DSig-in-the-deflated-body is
// internally consistent but NON-interoperable, so it is kept ONLY for the
// HTTP-POST binding (where the XML body IS the signed unit).
//
// CRITICAL (verification): reconstruct the signed octet string from the RAW,
// still-percent-encoded query values exactly as they arrived — never from
// re-encoded decoded values (encoders differ; the signer signed the bytes its
// own encoder emitted). The helpers below extract raw values straight out of the
// query string. This file mirrors saml/sp/redirect_sig.go (the two packages do
// not share private code, the same way they each carry their own randHex /
// unmarshalElement).

// redirectSigAlgFor maps a goxmldsig XML signature-method identifier (what an
// AssertionSigner.SignatureMethod() returns) to the SigAlg URI placed on the
// wire. Restricted to the methods the per-tenant signer can use (RSA-SHA256,
// ECDSA-SHA256).
func redirectSigAlgFor(method string) (string, bool) {
	switch method {
	case dsig.RSASHA256SignatureMethod, dsig.ECDSASHA256SignatureMethod:
		return method, true
	default:
		return "", false
	}
}

// x509SigAlgForSigAlgURI maps an inbound SigAlg URI to the stdlib
// x509.SignatureAlgorithm used to verify the detached signature via
// cert.CheckSignature. ONLY the asymmetric SHA-256 methods are accepted (no
// SHA-1) — alg-allowlist-before-verify, so an unknown/weak SigAlg rejects before
// reaching a key.
func x509SigAlgForSigAlgURI(sigAlg string) (x509.SignatureAlgorithm, bool) {
	switch sigAlg {
	case dsig.RSASHA256SignatureMethod:
		return x509.SHA256WithRSA, true
	case dsig.ECDSASHA256SignatureMethod:
		return x509.ECDSAWithSHA256, true
	default:
		return x509.UnknownSignatureAlgorithm, false
	}
}

// buildRedirectURL renders a SIGNED SAML HTTP-Redirect URL per §3.4.4.1: the
// already-serialized XML is raw-DEFLATEd + base64'd into the named parameter
// (param is "SAMLRequest" or "SAMLResponse"), then a DETACHED SigAlg+Signature
// pair is computed over the URL-encoded octet string (spec order) and appended.
// The query is assembled by HAND so the parameters stay in the fixed order over
// the exact encoded bytes the Signature is computed on.
func buildRedirectURL(signCtx *dsig.SigningContext, sigAlg, destination, param string, xml []byte, relayState string) (string, error) {
	deflated, err := rawDeflate(xml)
	if err != nil {
		return "", err
	}
	encoded := url.QueryEscape(base64.StdEncoding.EncodeToString(deflated))

	var sb strings.Builder
	sb.WriteString(param)
	sb.WriteString("=")
	sb.WriteString(encoded)
	if relayState != "" {
		sb.WriteString("&RelayState=")
		sb.WriteString(url.QueryEscape(relayState))
	}
	sb.WriteString("&SigAlg=")
	sb.WriteString(url.QueryEscape(sigAlg))
	octet := sb.String()

	sig, err := signCtx.SignString(octet)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(destination)
	if err != nil {
		return "", err
	}
	finalQuery := octet + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	if u.RawQuery != "" {
		u.RawQuery = u.RawQuery + "&" + finalQuery
	} else {
		u.RawQuery = finalQuery
	}
	return u.String(), nil
}

// rawDeflate raw-DEFLATEs b (the SAML HTTP-Redirect binding body encoding — no
// zlib header) at default compression.
func rawDeflate(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(b); err != nil {
		return nil, err
	}
	if err := fw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// rawRedirectParam extracts the RAW (still-percent-encoded) value of key out of
// a raw query string WITHOUT decoding it — required to reconstruct the §3.4.4.1
// signed octet string from exactly the bytes the peer signed. The FIRST
// occurrence wins.
func rawRedirectParam(rawQuery, key string) (string, bool) {
	for rawQuery != "" {
		var pair string
		if i := strings.IndexByte(rawQuery, '&'); i >= 0 {
			pair, rawQuery = rawQuery[:i], rawQuery[i+1:]
		} else {
			pair, rawQuery = rawQuery, ""
		}
		if pair == "" {
			continue
		}
		name := pair
		value := ""
		if j := strings.IndexByte(pair, '='); j >= 0 {
			name, value = pair[:j], pair[j+1:]
		}
		if name == key {
			return value, true
		}
	}
	return "", false
}

// verifyRedirectSignature validates the DETACHED §3.4.4.1 signature on an
// inbound HTTP-Redirect SAML message against a trust-anchor cert. param is the
// message parameter name ("SAMLRequest" for the SP's LogoutRequest). It REJECTS
// when SigAlg or Signature is absent (an unsigned redirect logout MUST NOT be
// accepted — the fail-closed "no termination without a verified signature"
// property), reconstructs the signed octet string from the RAW values in spec
// order, maps SigAlg → x509.SignatureAlgorithm (rejecting unknown/weak algs
// before verifying), and verifies via cert.CheckSignature — symmetric with
// SignString (RSA → PKCS#1 v1.5, ECDSA → ASN.1 DER), the same primitive
// goxmldsig validates enveloped signatures with.
func verifyRedirectSignature(cert *x509.Certificate, rawQuery, param string) error {
	if cert == nil {
		return errors.New("saml/idp: no trust-anchor cert for redirect signature")
	}

	msg, ok := rawRedirectParam(rawQuery, param)
	if !ok {
		return errors.New("saml/idp: redirect signature: missing " + param)
	}
	sigAlgRaw, hasSigAlg := rawRedirectParam(rawQuery, "SigAlg")
	sigRaw, hasSig := rawRedirectParam(rawQuery, "Signature")
	if !hasSigAlg || !hasSig || sigAlgRaw == "" || sigRaw == "" {
		// Fail closed: a redirect logout WITHOUT a detached signature is rejected
		// exactly as the enveloped path rejected a missing <Signature> element.
		return errors.New("saml/idp: redirect message is not signed (missing SigAlg/Signature)")
	}

	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return err
	}
	algo, ok := x509SigAlgForSigAlgURI(sigAlg)
	if !ok {
		return errors.New("saml/idp: unsupported redirect SigAlg")
	}
	sigB64, err := url.QueryUnescape(sigRaw)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}

	// Reconstruct the signed octet string from the RAW (still-encoded) values, in
	// §3.4.4.1 order. RelayState included ONLY if present on the wire.
	var sb strings.Builder
	sb.WriteString(param)
	sb.WriteString("=")
	sb.WriteString(msg)
	if relayRaw, ok := rawRedirectParam(rawQuery, "RelayState"); ok {
		sb.WriteString("&RelayState=")
		sb.WriteString(relayRaw)
	}
	sb.WriteString("&SigAlg=")
	sb.WriteString(sigAlgRaw)

	return cert.CheckSignature(algo, []byte(sb.String()), sig)
}
