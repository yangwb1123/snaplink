package idp

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso/interfaces/sso"
)

// SSO handles GET/POST /saml/sso — the SP-initiated AuthnRequest receiver.
//
// Flow (every failure collapses to the oracle-safe saml_request_invalid):
//
//  1. no-store at entry (before any branch).
//  2. Decode + inflate (Redirect) or base64-decode (POST) the SAMLRequest into
//     an AuthnRequest (XXE-safe parse).
//  3. Resolve the SP client by the AuthnRequest Issuer (registered
//     saml_sp_entity_id). O(n) over clients — noted in resolveSPClient.
//  4. If the SP requires signed requests, verify the AuthnRequest XML-DSig
//     against the SP's registered cert.
//  5. ACS-URL ALLOWLIST: the AuthnRequest's AssertionConsumerServiceURL MUST be
//     in the SP's registered saml_sp_acs_urls (or, when the request omits it,
//     fall back to the SP's first registered ACS). An unregistered ACS is
//     rejected — this is the assertion-exfiltration / open-redirect defense.
//  6. Store a single-use pending request keyed by a server-generated
//     saml_request_id; redirect the user-agent to LoginPath with
//     ?client_id=<sp>&state=<saml_request_id> to authenticate.
func (h *Handlers) SSO(w http.ResponseWriter, r *http.Request) {
	noStore(w)

	var samlRequest, relayState string
	redirectBinding := r.Method == http.MethodGet
	switch r.Method {
	case http.MethodGet:
		samlRequest = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
			return
		}
		samlRequest = r.PostForm.Get("SAMLRequest")
		relayState = r.PostForm.Get("RelayState")
	default:
		writeError(w, http.StatusMethodNotAllowed, sso.ErrSAMLRequestInvalid)
		return
	}
	if samlRequest == "" {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	authnReq, rawXML, err := parseAuthnRequest(samlRequest, redirectBinding)
	if err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	issuer := ""
	if authnReq.Issuer != nil {
		issuer = authnReq.Issuer.Value
	}
	spClient, err := h.resolveSPClient(r.Context(), issuer)
	if err != nil {
		// Unknown SP (or store error) → one collapsed code (no SP-enumeration
		// oracle).
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// Optional signed-AuthnRequest enforcement.
	if spClient.Attributes[AttrSPRequireSignedRequest] == "true" {
		if err := verifyAuthnRequestSignature(rawXML, spClient.Attributes[AttrSPSigningCert]); err != nil {
			writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
			return
		}
	}

	// ACS-URL allowlist (assertion-exfiltration defense). When the request
	// names an ACS URL it MUST be registered; when it omits one, use the SP's
	// first registered ACS (the SP delegated the choice to its registration).
	acsURL := authnReq.AssertionConsumerServiceURL
	if acsURL == "" {
		acsURL = firstACS(spClient)
	}
	if !acsAllowed(spClient, acsURL) {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// Per-SP NameID format override (registered, not request-controlled — the
	// AuthnRequest's NameIDPolicy is advisory; the registered value wins so an
	// SP can't coerce an unexpected NameID shape).
	nameIDFormat := spClient.Attributes[AttrSPNameIDFormat]

	pendingID, err := h.pending.Insert(PendingRequest{
		SPClientID:   spClient.ID,
		SPEntityID:   issuer,
		ACSURL:       acsURL,
		RequestID:    authnReq.ID,
		RelayState:   relayState,
		NameIDFormat: nameIDFormat,
	})
	if err != nil {
		// Storing the pending request failed (e.g. RNG error) — treat as an
		// internal assertion-pipeline failure, fail closed.
		h.deps.Logger.Error("saml/idp: store pending request failed", "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	// Redirect to the login orchestrator: authenticate the user against the SP
	// client, threading the saml_request_id as state so /saml/sso/finish can
	// resume. The SAML RelayState is preserved in the pending record (echoed at
	// finish), NOT leaked into the login URL.
	loc := h.loginPath() + "?" + url.Values{
		sso.KeyClientID: {spClient.ID},
		sso.KeyState:    {pendingID},
	}.Encode()
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

// verifyAuthnRequestSignature validates the AuthnRequest's enveloped XML-DSig
// against the SP's registered PEM certificate, using goxmldsig's
// ValidationContext (the same engine the SP side validates assertions with).
// The cert MUST be the one the SP registered (saml_sp_signing_cert) — the
// signature is verified against THAT pinned cert, never one embedded in the
// request. Any failure (no cert, parse error, bad/missing signature) returns a
// non-nil error the caller collapses to saml_request_invalid.
func verifyAuthnRequestSignature(rawXML []byte, certPEM string) error {
	if certPEM == "" {
		return errRequestInvalid
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errRequestInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errRequestInvalid
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawXML); err != nil {
		return errRequestInvalid
	}
	root := doc.Root()
	if root == nil {
		return errRequestInvalid
	}

	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(store)
	// goxmldsig's Validate verifies the enveloped signature on the element by
	// its DSig Reference URI against a trusted root, and refuses a cert not in
	// the store — so an attacker can't swap in their own KeyInfo cert.
	if _, err := ctx.Validate(root); err != nil {
		return errRequestInvalid
	}
	return nil
}
