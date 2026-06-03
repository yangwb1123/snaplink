package sp

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"regexp"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso"
)

// ErrLogoutInvalid is the SINGLE error every inbound-LogoutRequest validation
// failure collapses to (mirrors ErrAssertionInvalid for the SSO path). Its
// Error() string IS sso.ErrSAMLRequestInvalid, and callers match it with
// errors.Is. The per-cause detail (bad signature, unknown issuer, malformed XML)
// is DISCARDED — an attacker probing the SP's SLO endpoint cannot tell a forged
// signature from a malformed request, and the response never reveals whether a
// local session existed.
var ErrLogoutInvalid = errors.New(sso.ErrSAMLRequestInvalid)

// LogoutSubject is the validated identity carried by an IdP-initiated
// LogoutRequest: the NameID to log out and an optional SessionIndex. The caller
// (the operator's SLO handler) uses these to terminate the matching local
// session(s) via the SessionManager. RequestID is the LogoutRequest's ID — the
// caller threads it into BuildLogoutResponseURL so the LogoutResponse's
// InResponseTo binds to the request.
type LogoutSubject struct {
	NameID       string
	SessionIndex string
	RequestID    string
}

// maxInflatedLogoutBytes bounds the inflated size of a DEFLATEd SLO SAMLRequest
// (decompression-bomb defense, mirroring the IdP side). A LogoutRequest is a
// few KiB; 1 MiB refuses a bomb without affecting any real request.
const maxInflatedLogoutBytes = 1 << 20

// idpSigCertRe strips whitespace out of a base64 cert blob (metadata pretty-
// printing inserts newlines/indentation), mirroring crewjam's getIDPSigningCerts.
var idpSigCertRe = regexp.MustCompile(`\s+`)

// ProcessLogoutRequest validates an IdP-initiated LogoutRequest (as
// redirected/POSTed to THIS SP's SLO endpoint) and returns the subject to log
// out. redirectBinding selects raw-DEFLATE (GET) vs plain base64 (POST).
//
// SECURITY CRUX (no local session termination without a verified signature):
// the LogoutRequest's enveloped XML-DSig is verified against the BOOT-PINNED
// upstream IdP signing certificate — the SAME trust anchor ProcessAssertion
// uses (from IDPMetadata; never a cert embedded in the request). An unsigned or
// attacker-signed LogoutRequest fails here and the caller terminates NOTHING.
// The Issuer is additionally checked against the pinned IdP entity id so a
// signature valid under a different (but somehow-trusted) cert still can't drive
// a logout for the wrong IdP.
//
// Validation pipeline (ALL failures collapse to ErrLogoutInvalid):
//
//  1. base64-decode (+ bounded inflate for the redirect binding).
//  2. XXE / round-trip safety check over the raw XML (same validator crewjam
//     uses) BEFORE unmarshal.
//  3. Verify the enveloped XML-DSig against the pinned IdP signing cert(s).
//  4. Unmarshal + check the Issuer matches the pinned IdP entity id, and that a
//     non-empty NameID is present (a logout with no subject is meaningless).
//
// relayState is opaque (echoed by the IdP); it is NOT a security input here.
func (a *SPAuthenticator) ProcessLogoutRequest(samlRequestB64, relayState string, redirectBinding bool) (*LogoutSubject, error) {
	_ = relayState // opaque; echoed back on the LogoutResponse by the caller

	raw, err := decodeSLORequest(samlRequestB64, redirectBinding)
	if err != nil {
		return nil, ErrLogoutInvalid
	}

	// (2) XXE / round-trip safety BEFORE any parse.
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, ErrLogoutInvalid
	}

	// (3) Signature: verify the enveloped DSig against the PINNED IdP cert(s).
	// This is the crux — an unsigned/forged request fails here, before the
	// caller touches any session.
	if err := a.verifyLogoutRequestSignature(raw); err != nil {
		return nil, ErrLogoutInvalid
	}

	// (4) Parse + content checks. Strict unmarshal (refuses malformed XML).
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, ErrLogoutInvalid
	}
	var req saml.LogoutRequest
	if err := unmarshalElement(doc.Root(), &req); err != nil {
		return nil, ErrLogoutInvalid
	}

	// Issuer MUST be the pinned IdP. (Defense-in-depth: the signature already
	// binds the request to a pinned cert; this rejects a request whose Issuer
	// names a different entity even if it somehow carried a trusted signature.)
	if req.Issuer == nil || req.Issuer.Value != a.sp.IDPMetadata.EntityID {
		return nil, ErrLogoutInvalid
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return nil, ErrLogoutInvalid
	}
	sessionIndex := ""
	if req.SessionIndex != nil {
		sessionIndex = req.SessionIndex.Value
	}
	return &LogoutSubject{
		NameID:       req.NameID.Value,
		SessionIndex: sessionIndex,
		RequestID:    req.ID,
	}, nil
}

// BuildLogoutResponseURL builds a SIGNED HTTP-Redirect LogoutResponse (Status
// Success) the SP returns to the upstream IdP's SLO endpoint, acknowledging an
// IdP-initiated logout. logoutRequestID is the inbound LogoutRequest's ID (binds
// InResponseTo); relayState is echoed verbatim.
//
// Requires an SP signing key (SPPrivateKey) AND a resolvable IdP SLO endpoint
// (from IdP metadata or cfg.IDPSLOURL). Without either it returns "" so the
// caller can fall back to a bare 200 (the local session is already dead; we just
// can't acknowledge it). The response is SIGNED so the IdP can authenticate that
// this SP — not an attacker — acknowledged the logout.
func (a *SPAuthenticator) BuildLogoutResponseURL(logoutRequestID, relayState string) (string, error) {
	if a.sloSigner == nil {
		return "", ErrLogoutInvalid // SLO signing is mandatory; no key ⇒ no response
	}
	idpSLO := a.sp.GetSLOBindingLocation(saml.HTTPRedirectBinding)
	if idpSLO == "" {
		return "", ErrLogoutInvalid
	}
	resp := &saml.LogoutResponse{
		ID:           newSAMLID(),
		InResponseTo: logoutRequestID,
		Version:      "2.0",
		IssueInstant: a.clock(),
		Destination:  idpSLO,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  a.cfg.EntityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	}
	signedEl, err := a.signEnveloped(resp.Element())
	if err != nil {
		return "", err
	}
	u, err := a.redirectURL(idpSLO, "SAMLResponse", signedEl, relayState)
	if err != nil {
		return "", err
	}
	return u, nil
}

// LogoutURL builds a SIGNED HTTP-Redirect LogoutRequest the SP sends to the
// upstream IdP's SLO endpoint to start SP-INITIATED logout (this server asks the
// IdP to log the user out). nameID is the subject to log out (the value the SP
// received as the assertion NameID); sessionIndex optionally narrows it;
// relayState threads through verbatim (the SDK's outer layer owns its CSRF/state
// semantics, same as the SSO LoginURL).
//
// Requires an SP signing key + a resolvable IdP SLO endpoint; returns "" when
// either is absent (the operator then surfaces "SLO not configured" rather than
// redirecting nowhere). The LogoutRequest is SIGNED so the IdP can authenticate
// it (an IdP that performs SLO requires a signed request, the mirror of THIS
// SP's mandatory-signature posture on the inbound side).
func (a *SPAuthenticator) LogoutURL(nameID, sessionIndex, relayState string) string {
	if a.sloSigner == nil || nameID == "" {
		return ""
	}
	idpSLO := a.sp.GetSLOBindingLocation(saml.HTTPRedirectBinding)
	if idpSLO == "" {
		return ""
	}
	req := &saml.LogoutRequest{
		ID:           newSAMLID(),
		Version:      "2.0",
		IssueInstant: a.clock(),
		Destination:  idpSLO,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  a.cfg.EntityID,
		},
		NameID: &saml.NameID{Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}
	signedEl, err := a.signEnveloped(req.Element())
	if err != nil {
		return ""
	}
	u, err := a.redirectURL(idpSLO, "SAMLRequest", signedEl, relayState)
	if err != nil {
		return ""
	}
	return u
}

// verifyLogoutRequestSignature validates the enveloped XML-DSig on the
// LogoutRequest root against the SP's BOOT-PINNED upstream IdP signing cert(s),
// using goxmldsig — the same engine + trust anchor crewjam validates assertions
// with. A missing Signature element, or a signature that doesn't verify against
// a pinned cert, returns an error → unsigned/forged requests are rejected.
func (a *SPAuthenticator) verifyLogoutRequestSignature(raw []byte) error {
	certs, err := a.pinnedIDPCerts()
	if err != nil {
		return err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return err
	}
	root := doc.Root()
	if root == nil {
		return errors.New("saml/sp: empty logout request")
	}
	store := &dsig.MemoryX509CertificateStore{Roots: certs}
	ctx := dsig.NewDefaultValidationContext(store)
	ctx.IdAttribute = "ID"
	if a.now != nil {
		// Pin the validation clock to the test seam so cert-validity never trips
		// on a frozen clock (real cert windows are wide; tests freeze time).
		ctx.Clock = dsig.NewFakeClockAt(a.now())
	}
	if _, err := ctx.Validate(root); err != nil {
		return err
	}
	return nil
}

// pinnedIDPCerts extracts the upstream IdP signing certificates from the pinned
// IDPMetadata (use="signing" or unset), mirroring crewjam's getIDPSigningCerts.
// These are the boot-pinned trust anchor — never a request-embedded cert.
func (a *SPAuthenticator) pinnedIDPCerts() ([]*x509.Certificate, error) {
	if a.sp.IDPMetadata == nil {
		return nil, errors.New("saml/sp: no pinned IdP metadata")
	}
	var certStrs []string
	for _, d := range a.sp.IDPMetadata.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
				continue
			}
			switch kd.Use {
			case "", "signing":
				for _, c := range kd.KeyInfo.X509Data.X509Certificates {
					certStrs = append(certStrs, c.Data)
				}
			}
		}
	}
	if len(certStrs) == 0 {
		return nil, errors.New("saml/sp: no pinned IdP signing cert")
	}
	certs := make([]*x509.Certificate, 0, len(certStrs))
	for _, s := range certStrs {
		der, err := base64.StdEncoding.DecodeString(idpSigCertRe.ReplaceAllString(s, ""))
		if err != nil {
			return nil, err
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// signEnveloped enveloped-signs el with the SP signing key (RSA/ECDSA-SHA256,
// exclusive-C14N empty-prefix — matching the IdP side + crewjam) and returns the
// signed element (Signature as the last child). Used for both SP-initiated
// LogoutRequests and the LogoutResponse acknowledgement.
func (a *SPAuthenticator) signEnveloped(el *etree.Element) (*etree.Element, error) {
	ctx, err := dsig.NewSigningContext(a.sloSigner, [][]byte{a.sloSigCert.Raw})
	if err != nil {
		return nil, err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(a.sloSigMethod); err != nil {
		return nil, err
	}
	return ctx.SignEnveloped(el)
}

// redirectURL renders signedEl into a SAML HTTP-Redirect URL: the element is
// serialized, raw-DEFLATEd, base64'd, and placed in the named query parameter
// (SAMLRequest or SAMLResponse) on the destination URL, with the RelayState
// appended verbatim when set.
func (a *SPAuthenticator) redirectURL(destination, param string, signedEl *etree.Element, relayState string) (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(signedEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(raw); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	u, err := url.Parse(destination)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
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
