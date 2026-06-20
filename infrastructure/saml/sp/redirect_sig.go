package sp

import (
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
// signature is DETACHED, carried in two SIBLING query parameters:
//
//	SigAlg    = <URL-encoded signature-algorithm URI>
//	Signature = <URL-encoded base64 of the signature>
//
// computed over the octet string formed by concatenating the URL-ENCODED query
// parameters in this EXACT order (RelayState present only when it is sent):
//
//	SAMLRequest=<v>&RelayState=<v>&SigAlg=<v>      (request direction)
//	SAMLResponse=<v>&RelayState=<v>&SigAlg=<v>     (response direction)
//
// This is what every real IdP/SP (Okta, Azure AD, Shibboleth) produces and
// validates; the previously-used enveloped-XML-DSig-in-the-deflated-body is
// internally consistent but NON-interoperable, so it is used here ONLY for the
// HTTP-POST binding (where the XML body IS the signed unit).
//
// CRITICAL (verification): the signed octet string MUST be reconstructed from
// the RAW, still-percent-encoded query values exactly as they arrived on the
// wire — never from re-encoded decoded values — because the signer signed the
// bytes its own encoder emitted (and encoders differ, e.g. space as '+' vs
// %20). The helpers below therefore extract raw values straight out of the
// query string rather than round-tripping through url.Values.

// redirectSigAlgForMethod maps a goxmldsig XML signature-method identifier (the
// value xmlSigMethodForKey returns for the SP signing key) to the SigAlg URI
// placed on the wire. Restricted to the two methods the SP keys can be
// (RSA-SHA256, ECDSA-SHA256) — the same allowlist as the enveloped path.
func redirectSigAlgForMethod(method string) (string, bool) {
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
// SHA-1, no rsa-sha1) — the alg-allowlist-before-verify posture the rest of the
// server takes (an unknown/weak SigAlg rejects rather than reaching a verify).
// This mirrors goxmldsig's own (unexported) x509SignatureAlgorithmByIdentifier
// table, scoped to what this module supports.
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
// pair is computed over the URL-encoded octet string in spec order and
// appended. The query is assembled by HAND (not url.Values.Encode) because
// signing requires the parameters in a fixed order over the exact encoded bytes
// the Signature is computed on.
func buildRedirectURL(signCtx *dsig.SigningContext, sigAlg, destination, param string, xml []byte, relayState string) (string, error) {
	deflated, err := rawDeflate(xml)
	if err != nil {
		return "", err
	}
	encoded := url.QueryEscape(base64.StdEncoding.EncodeToString(deflated))

	// Octet string per §3.4.4.1: <param>=<v>[&RelayState=<v>]&SigAlg=<v>, all
	// values URL-encoded, in this exact order; RelayState included only when set.
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
	// Append to any pre-existing query on the destination, preserving our exact
	// signed bytes (do NOT round-trip through u.Query()/Encode — that would
	// reorder/re-encode and break the signature the verifier reconstructs).
	finalQuery := octet + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	if u.RawQuery != "" {
		u.RawQuery = u.RawQuery + "&" + finalQuery
	} else {
		u.RawQuery = finalQuery
	}
	return u.String(), nil
}

// rawRedirectParam extracts the RAW (still-percent-encoded) value of key out of
// a raw query string, WITHOUT decoding it. This is required to reconstruct the
// §3.4.4.1 signed octet string from exactly the bytes the peer signed. Returns
// the raw value and whether the key was present. The FIRST occurrence wins
// (duplicate query keys are a malformed request the signature check then fails
// on anyway).
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
// message parameter name ("SAMLRequest" for an inbound LogoutRequest, or
// "SAMLResponse"). It:
//
//  1. Extracts the RAW (still-encoded) SAMLRequest/SAMLResponse, RelayState,
//     SigAlg, and Signature values from rawQuery.
//  2. REJECTS when SigAlg or Signature is absent (an unsigned redirect message
//     MUST NOT be accepted — this is the fail-closed "no termination without a
//     verified signature" property, preserved from the enveloped path).
//  3. Reconstructs the signed octet string from the RAW values in spec order
//     (RelayState included only when it was sent).
//  4. Maps SigAlg → x509.SignatureAlgorithm (rejecting any unknown/weak alg
//     BEFORE verifying) and verifies the base64-decoded Signature against the
//     pinned cert via cert.CheckSignature — symmetric with SignString
//     (RSA → PKCS#1 v1.5, ECDSA → ASN.1 DER), the same primitive goxmldsig
//     validates enveloped signatures with.
//
// A nil/empty cert list, a missing signature, an unknown alg, or a verify
// failure all return a non-nil error the caller collapses to the one
// oracle-safe code. Any ONE cert verifying is sufficient (metadata may publish
// several signing certs across a rotation).
func verifyRedirectSignature(certs []*x509.Certificate, rawQuery, param string) error {
	if len(certs) == 0 {
		return errors.New("saml/sp: no trust-anchor cert for redirect signature")
	}

	msg, ok := rawRedirectParam(rawQuery, param)
	if !ok {
		return errors.New("saml/sp: redirect signature: missing " + param)
	}
	sigAlgRaw, hasSigAlg := rawRedirectParam(rawQuery, "SigAlg")
	sigRaw, hasSig := rawRedirectParam(rawQuery, "Signature")
	if !hasSigAlg || !hasSig || sigAlgRaw == "" || sigRaw == "" {
		// Fail closed: a redirect logout WITHOUT a detached signature is rejected
		// exactly as the enveloped path rejected a missing <Signature> element.
		return errors.New("saml/sp: redirect message is not signed (missing SigAlg/Signature)")
	}

	// Decode SigAlg/Signature (these are our own inputs to interpret, not part of
	// the signed octet string).
	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return err
	}
	algo, ok := x509SigAlgForSigAlgURI(sigAlg)
	if !ok {
		// Alg-allowlist BEFORE verify: an unknown/weak SigAlg never reaches a key.
		return errors.New("saml/sp: unsupported redirect SigAlg")
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
	// §3.4.4.1 order. RelayState is included ONLY if it was present on the wire.
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
	octet := []byte(sb.String())

	// Any one pinned cert verifying the signature is acceptance.
	var lastErr error
	for _, c := range certs {
		if c == nil {
			continue
		}
		if err := c.CheckSignature(algo, octet, sig); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("saml/sp: redirect signature did not verify")
	}
	return lastErr
}
