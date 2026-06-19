package sp

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// signedRedirect serializes the (UNSIGNED) SAML element and renders a SIGNED
// HTTP-Redirect URL carrying a DETACHED §3.4.4.1 signature: the XML is
// raw-DEFLATEd + base64'd into the named query parameter (SAMLRequest or
// SAMLResponse), and a SigAlg+Signature pair computed over the URL-encoded octet
// string (in spec order, RelayState only when present) is appended. This is the
// SAML-standard redirect-binding signature every real IdP/SP validates — NOT an
// enveloped XML-DSig in the body (which was the prior, non-interoperable form).
func (a *SPAuthenticator) signedRedirect(destination, param string, el *etree.Element, relayState string) (string, error) {
	xmlBytes, err := serializeElement(el)
	if err != nil {
		return "", err
	}
	signCtx, sigAlg, err := a.redirectSigningContext()
	if err != nil {
		return "", err
	}
	return buildRedirectURL(signCtx, sigAlg, destination, param, xmlBytes, relayState)
}

// redirectSigningContext builds a goxmldsig SigningContext over the SP signing
// key (the same key the enveloped POST path uses) plus the SigAlg URI for the
// detached redirect signature. The SigningContext's SignString computes the
// §3.4.4.1 signature over the octet string. The signature bytes are written
// verbatim (RSA → PKCS#1 v1.5, ECDSA → ASN.1 DER), which the detached verifier
// (cert.CheckSignature with the matching alg) accepts — the same DER convention
// the enveloped path and the assertion signer use.
func (a *SPAuthenticator) redirectSigningContext() (*dsig.SigningContext, string, error) {
	sigAlg, ok := redirectSigAlgForMethod(a.sloSigMethod)
	if !ok {
		return nil, "", errors.New("saml/sp: unsupported SP signing method for redirect signature")
	}
	ctx, err := dsig.NewSigningContext(a.sloSigner, [][]byte{a.sloSigCert.Raw})
	if err != nil {
		return nil, "", err
	}
	if err := ctx.SetSignatureMethod(a.sloSigMethod); err != nil {
		return nil, "", err
	}
	return ctx, sigAlg, nil
}

// serializeElement renders an etree element to its XML bytes.
func serializeElement(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	return doc.WriteToBytes()
}

// rawDeflate raw-DEFLATEs b (the SAML HTTP-Redirect binding body encoding — RFC:
// no zlib header) at default compression.
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

// newSAMLID returns a crypto/rand-backed, XML-NCName-safe element ID
// ("id-"+32 hex) for outbound LogoutRequest/Response IDs — unguessable so an
// attacker can't pre-correlate. Mirrors the IdP side's randHex usage.
func newSAMLID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "id-" + hex.EncodeToString(b)
}

// unmarshalElement renders an etree element to bytes and strict-unmarshals it
// into v with the stdlib decoder (which never resolves external DTDs/entities —
// XXE-safe, complementing the xrv round-trip check already run on the raw bytes).
// Strict mode refuses malformed/overlapping tags. crewjam keeps its own
// unexported unmarshalElement; this is the SP-module-local equivalent.
func unmarshalElement(el *etree.Element, v any) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	return dec.Decode(v)
}

// decodeSLORequest decodes a wire SLO SAMLRequest into raw XML: base64, plus a
// bounded raw-inflate for the redirect binding (decompression-bomb defense).
func decodeSLORequest(samlRequestB64 string, redirectBinding bool) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(samlRequestB64)
	if err != nil {
		return nil, err
	}
	if !redirectBinding {
		return b, nil
	}
	fr := flate.NewReader(bytes.NewReader(b))
	defer fr.Close()
	out, err := io.ReadAll(io.LimitReader(fr, maxInflatedLogoutBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflatedLogoutBytes {
		return nil, errors.New("saml/sp: inflated logout request exceeds size limit")
	}
	return out, nil
}
