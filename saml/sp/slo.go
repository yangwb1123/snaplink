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
	"regexp"
	"time"

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

// logoutMaxClockSkew is the small future-skew allowance on a LogoutRequest's
// IssueInstant (a request minted slightly ahead of this SP's clock is still
// accepted; one further in the future is a clock-forward forgery and rejected).
// Kept tiny — the freshness window absorbs ordinary drift on the past side.
const logoutMaxClockSkew = 1 * time.Minute

// idpSigCertRe strips whitespace out of a base64 cert blob (metadata pretty-
// printing inserts newlines/indentation), mirroring crewjam's getIDPSigningCerts.
var idpSigCertRe = regexp.MustCompile(`\s+`)

// ProcessLogoutRequest validates an IdP-initiated LogoutRequest (as
// redirected/POSTed to THIS SP's SLO endpoint) and returns the subject to log
// out. redirectBinding selects the HTTP-Redirect binding (raw-DEFLATE body +
// DETACHED §3.4.4.1 query-param signature) vs HTTP-POST (plain base64 +
// enveloped XML-DSig). rawQuery is the request's raw URL query string — REQUIRED
// for the redirect binding (the detached signature is reconstructed from its raw
// percent-encoded values); ignored for POST.
//
// SECURITY CRUX (no local session termination without a verified signature):
// the LogoutRequest signature is verified against the BOOT-PINNED upstream IdP
// signing certificate — the SAME trust anchor ProcessAssertion uses (from
// IDPMetadata; never a cert embedded in the request). An unsigned or
// attacker-signed LogoutRequest fails here and the caller terminates NOTHING.
// For the redirect binding the signature is the SAML-standard DETACHED
// SigAlg+Signature query pair (SAML Bindings §3.4.4.1) — what every real IdP
// sends; for POST it is the enveloped XML-DSig over the body. The Issuer is
// additionally checked against the pinned IdP entity id so a signature valid
// under a different (but somehow-trusted) cert still can't drive a logout for
// the wrong IdP.
//
// Validation pipeline (ALL failures collapse to ErrLogoutInvalid):
//
//  1. base64-decode (+ bounded inflate for the redirect binding).
//  2. XXE / round-trip safety check over the raw XML (same validator crewjam
//     uses) BEFORE unmarshal.
//  3. Verify the signature: DETACHED query-param sig (redirect) or enveloped
//     XML-DSig (POST) against the pinned IdP signing cert(s). Missing/invalid →
//     reject (fail-closed).
//  4. Unmarshal + check the Issuer matches the pinned IdP entity id, and that a
//     non-empty NameID is present (a logout with no subject is meaningless).
//  5. Freshness + replay (AFTER signature, so unsigned junk can't flood the
//     store): reject a stale/far-future IssueInstant or a LogoutRequest ID seen
//     within the freshness window (captured-signed-logout replay defense).
//
// relayState is opaque (echoed by the IdP); it is NOT a security input here.
func (a *SPAuthenticator) ProcessLogoutRequest(samlRequestB64, relayState string, redirectBinding bool, rawQuery string) (*LogoutSubject, error) {
	_ = relayState // opaque; echoed back on the LogoutResponse by the caller

	raw, err := decodeSLORequest(samlRequestB64, redirectBinding)
	if err != nil {
		return nil, ErrLogoutInvalid
	}

	// (2) XXE / round-trip safety BEFORE any parse.
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, ErrLogoutInvalid
	}

	// (3) Signature: verify against the PINNED IdP cert(s). This is the crux — an
	// unsigned/forged request fails here, before the caller touches any session.
	// Redirect binding → DETACHED §3.4.4.1 query-param signature (real-IdP
	// interop); POST binding → enveloped XML-DSig over the body.
	if redirectBinding {
		certs, err := a.pinnedIDPCerts()
		if err != nil {
			return nil, ErrLogoutInvalid
		}
		if err := verifyRedirectSignature(certs, rawQuery, "SAMLRequest"); err != nil {
			return nil, ErrLogoutInvalid
		}
	} else {
		if err := a.verifyLogoutRequestSignature(raw); err != nil {
			return nil, ErrLogoutInvalid
		}
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

	// (5) Freshness + replay — AFTER signature verification (so an attacker can't
	// flood the replay store with unsigned junk). A captured, validly-signed
	// LogoutRequest would otherwise replay indefinitely (targeted-logout DoS).
	if err := a.checkLogoutFreshnessAndReplay(req.ID, req.IssueInstant); err != nil {
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

// checkLogoutFreshnessAndReplay enforces the LogoutRequest freshness window and
// single-use ID dedup (Fix 2). It is called ONLY after the signature has been
// verified. Returns a non-nil error (the caller collapses it to the one
// oracle-safe code) when:
//
//   - IssueInstant is zero/absent (a logout with no timestamp can't be aged
//     out and is non-conformant),
//   - IssueInstant is older than the freshness window (a stale captured logout),
//   - IssueInstant is further in the FUTURE than a small skew (clock-forward
//     forgery / a request minted to outlive the window),
//   - the LogoutRequest ID has already been seen within the window (a replay).
//
// The ID is recorded with a TTL equal to the freshness window, so the dedup
// memory is naturally bounded: once a request is too old to be fresh, its ID
// entry can be pruned (a later replay fails the freshness check anyway). An
// empty ID is rejected (a request with no ID can't be deduped — and a
// conformant LogoutRequest always carries one).
func (a *SPAuthenticator) checkLogoutFreshnessAndReplay(id string, issueInstant time.Time) error {
	now := a.clock()
	window := a.logoutWindow()

	if issueInstant.IsZero() {
		return errors.New("saml/sp: logout request missing IssueInstant")
	}
	// Too old: outside the past freshness window.
	if now.Sub(issueInstant) > window {
		return errors.New("saml/sp: stale logout request")
	}
	// Too far in the future: beyond a small skew allowance.
	if issueInstant.Sub(now) > logoutMaxClockSkew {
		return errors.New("saml/sp: logout request IssueInstant in the future")
	}
	if id == "" {
		return errors.New("saml/sp: logout request missing ID")
	}
	// Dedup: remember the ID until it can no longer be fresh (now+window).
	if fresh := a.logoutReplay.checkAndRemember(id, issueInstant.Add(window), now); !fresh {
		return errors.New("saml/sp: replayed logout request")
	}
	return nil
}

// logoutWindow returns the LogoutRequest freshness window (how far in the past
// an IssueInstant may be and still be accepted). Configurable via
// SPConfig.LogoutRequestWindow; <=0 ⇒ DefaultLogoutRequestWindow.
func (a *SPAuthenticator) logoutWindow() time.Duration {
	if a.cfg.LogoutRequestWindow > 0 {
		return a.cfg.LogoutRequestWindow
	}
	return DefaultLogoutRequestWindow
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
	// HTTP-Redirect binding: UNSIGNED XML body + DETACHED §3.4.4.1 signature in
	// the SigAlg+Signature query params (not an enveloped XML-DSig).
	return a.signedRedirect(idpSLO, "SAMLResponse", resp.Element(), relayState)
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
	// HTTP-Redirect binding: UNSIGNED XML body + DETACHED §3.4.4.1 signature in
	// the SigAlg+Signature query params (real-IdP interop).
	u, err := a.signedRedirect(idpSLO, "SAMLRequest", req.Element(), relayState)
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
