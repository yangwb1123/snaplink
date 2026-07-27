package sp

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"regexp"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/yangwb1123/snaplink/interfaces/sso"
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

// PeekLogoutRequestIssuer decodes an inbound SLO LogoutRequest just far enough
// to read its Issuer element, WITHOUT verifying the signature. It exists for the
// SP-side multi-IdP SLO dispatcher: with several SPConfigs wired, the front-channel
// RelayState is the IdP's unguessable chain-state id (no provider hint), so the
// dispatcher must select the right authenticator by the request's Issuer instead.
//
// SECURITY: the returned Issuer is a LOOKUP KEY ONLY — it selects which
// authenticator's pinned trust anchor to use; it is NEVER itself a trust decision.
// The selected authenticator's ProcessLogoutRequest STILL fully validates the
// signature against that IdP's pinned cert (and re-checks the Issuer == pinned
// entity id) immediately after. A forged/wrong Issuer merely picks an authenticator
// whose cert won't validate the signature → the request is rejected. Decoding runs
// the SAME XXE-safe / decompression-bomb-bounded path ProcessLogoutRequest uses
// (decodeSLORequest → xrv round-trip check → strict unmarshal), so peeking adds no
// new parse exposure. Returns ErrLogoutInvalid (the one oracle-safe code) on any
// decode failure or a missing/empty Issuer.
func PeekLogoutRequestIssuer(samlRequestB64 string, redirectBinding bool) (string, error) {
	raw, err := decodeSLORequest(samlRequestB64, redirectBinding)
	if err != nil {
		return "", ErrLogoutInvalid
	}
	// XXE / round-trip safety BEFORE any parse (same gate as ProcessLogoutRequest).
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return "", ErrLogoutInvalid
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return "", ErrLogoutInvalid
	}
	var req saml.LogoutRequest
	if err := unmarshalElement(doc.Root(), &req); err != nil {
		return "", ErrLogoutInvalid
	}
	if req.Issuer == nil || req.Issuer.Value == "" {
		return "", ErrLogoutInvalid
	}
	return req.Issuer.Value, nil
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
	if fresh := a.logoutReplay.CheckAndRemember(id, issueInstant.Add(window), now); !fresh {
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
// Success) the SP returns to the upstream IdP's SLO RESPONSE endpoint,
// acknowledging an inbound LogoutRequest. logoutRequestID is the inbound
// LogoutRequest's ID (binds InResponseTo); relayState is echoed VERBATIM (for the
// IdP's front-channel chain it is the single-use chain-state id the IdP uses to
// resume — the SP MUST return it unchanged).
//
// The response goes to idpSLOResponseEndpoint(): cfg.IDPSLOResponseURL when set
// (the front-channel chain's /saml/slo/continue resume endpoint — the metadata
// ResponseLocation analogue), else the request endpoint
// (GetSLOBindingLocation / cfg.IDPSLOURL — the back-channel / IdP-initiated
// default, unchanged).
//
// Requires an SP signing key (SPPrivateKey) AND a resolvable IdP SLO response
// endpoint. Without either it returns "" so the caller can fall back to a bare
// 200 (the local session is already dead; we just can't acknowledge it). The
// response is SIGNED so the IdP can authenticate that this SP — not an attacker —
// acknowledged the logout.
func (a *SPAuthenticator) BuildLogoutResponseURL(logoutRequestID, relayState string) (string, error) {
	if a.sloSigner == nil {
		return "", ErrLogoutInvalid // SLO signing is mandatory; no key ⇒ no response
	}
	idpSLO := a.idpSLOResponseEndpoint()
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
	// the SigAlg+Signature query params (not an enveloped XML-DSig). The relayState
	// (chain id, for front-channel) is part of the signed octet string, so the IdP
	// re-derives + trusts the exact id the chain issued.
	return a.signedRedirect(idpSLO, "SAMLResponse", resp.Element(), relayState)
}

// idpSLOResponseEndpoint resolves where this SP redirects a LogoutResponse: the
// explicitly-configured IdP SLO RESPONSE endpoint (cfg.IDPSLOResponseURL — the
// front-channel chain's /saml/slo/continue, the metadata ResponseLocation
// analogue) when set, else the IdP's SLO REQUEST endpoint
// (GetSLOBindingLocation, fed by metadata / cfg.IDPSLOURL — the back-channel /
// IdP-initiated default). Empty when neither resolves (the caller falls back to a
// bare 200).
func (a *SPAuthenticator) idpSLOResponseEndpoint() string {
	if a.cfg.IDPSLOResponseURL != "" {
		return a.cfg.IDPSLOResponseURL
	}
	return a.sp.GetSLOBindingLocation(saml.HTTPRedirectBinding)
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
	// rejectWeakSignatureAlgorithms rejects a SHA-1 SignatureMethod/DigestMethod
	// before verifying (goxmldsig itself would accept SHA-1; see
	// weak_signature_algorithms.go), matching the detached redirect path's
	// no-SHA-1 allowlist.
	if err := rejectWeakSignatureAlgorithms(root); err != nil {
		return err
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
