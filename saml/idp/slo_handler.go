package idp

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
)

// sloAutoPostForm is the HTTP-POST auto-submit form that delivers the signed
// LogoutResponse back to the SP's REGISTERED SLO URL. html/template escapes
// every interpolated value; all three values are server-controlled (the SLO URL
// is from the registered allowlist, the response is base64, the RelayState is
// the SP's own echoed value), so nothing can break out of an attribute.
var sloAutoPostForm = template.Must(template.New("saml-idp-slo-post").Parse(`<!DOCTYPE html>
<html>
<head><title>Submitting...</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{{.SLOURL}}">
<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}
<noscript><input type="submit" value="Continue" /></noscript>
</form>
</body>
</html>`))

type sloAutoPostData struct {
	SLOURL       string
	SAMLResponse string
	RelayState   string
}

// SLO handles GET/POST /saml/slo — the SP-initiated Single Logout receiver. A
// downstream SP redirects/POSTs a SIGNED LogoutRequest here to terminate the
// subject's session at this IdP.
//
// SECURITY CRUX (no session termination without a verified signature):
//
//  1. no-store at entry (before any branch).
//  2. Decode the LogoutRequest (XXE-safe, decompression-bomb-bounded — the same
//     pipeline /saml/sso uses).
//  3. Resolve the SP client by the LogoutRequest Issuer (registered
//     saml_sp_entity_id). Unknown SP → one collapsed saml_request_invalid.
//  4. AUTHENTICATE THE LOGOUT: verify the LogoutRequest's enveloped XML-DSig
//     against the SP's REGISTERED signing cert (saml_sp_signing_cert). This is
//     REQUIRED — a SLO that terminates a session MUST be signed; an unsigned or
//     attacker-signed request is rejected and NO session is touched. (Unlike the
//     AuthnRequest path, where signing is opt-in, SLO signing is mandatory: a
//     logout is a destructive action a forged request must not trigger.)
//  5. Terminate ONLY the matching subject session(s) for the request's NameID
//     (optionally narrowed to a SessionIndex that belongs to that subject) via
//     the SessionManager — never a broad/global wipe.
//  6. Reply with a SIGNED LogoutResponse (Status Success) to the SP's REGISTERED
//     SLO URL (saml_sp_slo_url allowlist) — never a request-supplied URL.
//
// Oracle-safety: every validation failure (malformed, unknown SP, missing/bad
// signature, SLO URL not registered) collapses to ONE saml_request_invalid with
// no cause detail. Session termination is best-effort + does NOT leak whether a
// session existed: a LogoutResponse Success is returned whether or not a session
// matched (SAML §3.7.3.2 permits Success when there was nothing to terminate),
// so a probe cannot use SLO to enumerate live sessions.
func (h *Handlers) SLO(w http.ResponseWriter, r *http.Request) {
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

	logoutReq, rawXML, err := parseLogoutRequest(samlRequest, redirectBinding)
	if err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	issuer := ""
	if logoutReq.Issuer != nil {
		issuer = logoutReq.Issuer.Value
	}
	spClient, err := h.resolveSPClient(r.Context(), issuer)
	if err != nil {
		// Unknown SP (or store error) → one collapsed code (no SP-enumeration
		// oracle).
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (4) MANDATORY signature validation. A SLO request MUST carry a valid
	// enveloped XML-DSig over the SP's registered cert. Missing cert, missing
	// signature, or a signature that doesn't verify against the PINNED cert all
	// reject here — BEFORE any session is touched. This is the crux: a
	// forged/unsigned LogoutRequest can NOT terminate a session.
	if err := verifyLogoutRequestSignature(rawXML, spClient.Attributes[AttrSPSigningCert]); err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (5) Terminate ONLY the matching subject session(s). NameID is the SSO
	// subject (the IdP minted assertions with NameID == user.ID). A blank NameID
	// is meaningless for a targeted logout → reject (never a global wipe).
	nameID := ""
	if logoutReq.NameID != nil {
		nameID = logoutReq.NameID.Value
	}
	if nameID == "" {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}
	sessionIndex := ""
	if logoutReq.SessionIndex != nil {
		sessionIndex = logoutReq.SessionIndex.Value
	}
	terminated := h.terminateSubjectSessions(r.Context(), nameID, sessionIndex)

	// (6) Audit the logout (best-effort; provider "saml-idp"). Recorded
	// regardless of whether a session was found, so the audit trail captures the
	// attempt without the wire response leaking existence.
	h.recordSLO(r, spClient.ID, issuer, nameID, terminated)

	// (6, cont.) Reply with a SIGNED LogoutResponse to the SP's REGISTERED SLO
	// URL only. If the SP registered no SLO URL there is nowhere to send the
	// response — the session is already terminated, so return 200 with no body
	// (the kill happened; we simply can't acknowledge it). If a signer can't be
	// resolved (e.g. an Ed25519 tenant key), fail closed with the IdP-internal
	// code — but the session was ALREADY terminated (logout is fail-safe: we
	// don't resurrect a session because we couldn't sign the acknowledgement).
	sloURL := firstSLO(spClient)
	if sloURL == "" || !sloAllowed(spClient, sloURL) {
		w.WriteHeader(http.StatusOK)
		return
	}

	signer, err := h.signerForClient(spClient)
	if err != nil {
		h.deps.Logger.Error("saml/idp: SLO response signer resolution failed", "client_id", spClient.ID, "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	respB64, err := buildLogoutResponse(h.entityID(), sloURL, logoutReq.ID, signer, h.deps.now())
	if err != nil {
		h.deps.Logger.Error("saml/idp: build LogoutResponse failed", "client_id", spClient.ID, "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	w.Header().Set(sso.HeaderContentType, "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = sloAutoPostForm.Execute(w, sloAutoPostData{
		SLOURL:       sloURL,
		SAMLResponse: respB64,
		RelayState:   relayState,
	})
}

// terminateSubjectSessions destroys the sessions belonging to nameID (the SSO
// subject), optionally narrowed to a single sessionIndex. It returns the number
// of sessions destroyed (for audit only — never surfaced on the wire).
//
// SECURITY: termination is scoped to the SUBJECT named in the (already
// signature-verified) LogoutRequest. A sessionIndex is honored ONLY when the
// named session actually belongs to nameID — a sessionIndex pointing at another
// subject's session is IGNORED (it does NOT destroy that session and does NOT
// error), so a logout request can never reach across subjects. With no
// sessionIndex, every active session for the subject is destroyed (full SLO).
// This is never a global wipe: the set is always bounded to one subject.
func (h *Handlers) terminateSubjectSessions(ctx context.Context, nameID, sessionIndex string) int {
	sessions, err := h.deps.SessionManager.ListByUser(ctx, nameID)
	if err != nil {
		// A lookup outage means we can't enumerate the subject's sessions. Log +
		// continue (the response is still a Success — the SP must treat its own
		// state as terminated; this IdP's session, if any, lapses by expiry).
		h.deps.Logger.Error("saml/idp: SLO list sessions failed", "error", err)
		return 0
	}
	destroyed := 0
	for _, s := range sessions {
		if s == nil {
			continue
		}
		// When a SessionIndex is supplied, destroy only the session whose id
		// matches it (and, by construction of ListByUser, belongs to nameID). The
		// IdP does not currently emit a SessionIndex into assertions, so most SPs
		// send none → full logout for the subject.
		if sessionIndex != "" && s.ID != sessionIndex {
			continue
		}
		if err := h.deps.SessionManager.Destroy(ctx, s.ID); err != nil {
			// Best-effort: a single destroy failure doesn't abort the others (one
			// stuck session must not block terminating the rest). Logged, not
			// surfaced.
			h.deps.Logger.Error("saml/idp: SLO destroy session failed", "error", err)
			continue
		}
		destroyed++
	}
	return destroyed
}

// recordSLO records a logout audit event for a processed SP-initiated SLO.
// provider is "saml-idp"; the SP entityID + subject ride on Metadata via
// SetMeta (NEVER e.Metadata = map{} — that clobbers geo/tenant enrichment,
// AGENTS.md §2). Nil recorder = no-op.
func (h *Handlers) recordSLO(r *http.Request, clientID, spEntityID, subject string, terminated int) {
	if h.deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:     audit.EventLogout,
		Outcome:  audit.OutcomeSuccess,
		Provider: "saml-idp",
		ClientID: clientID,
		ActorID:  subject,
	}
	audit.SetMeta(e, "saml_sp_entity_id", spEntityID)
	audit.SetMeta(e, "saml_slo_sessions_terminated", fmt.Sprintf("%d", terminated))
	h.deps.AuditRecorder.Record(r.Context(), e)
}

// verifyLogoutRequestSignature validates the LogoutRequest's enveloped XML-DSig
// against the SP's REGISTERED PEM certificate, using goxmldsig's
// ValidationContext (the SAME engine verifyAuthnRequestSignature and the SP side
// use). The cert is the one the SP registered (saml_sp_signing_cert) — the
// signature is verified against THAT pinned cert, never one embedded in the
// request, so an attacker can't swap in their own KeyInfo cert.
//
// Crucially, a request with NO Signature element fails: goxmldsig's Validate
// returns an error when there is no signature to verify, so an unsigned
// LogoutRequest is rejected here (the SLO-signing-is-mandatory invariant). An
// empty/invalid registered cert also rejects. Any failure returns a non-nil
// error the caller collapses to saml_request_invalid.
func verifyLogoutRequestSignature(rawXML []byte, certPEM string) error {
	if certPEM == "" {
		// No registered SP cert ⇒ no way to authenticate the logout ⇒ reject. A
		// SAML SP that performs SLO MUST register its signing cert.
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
	// goxmldsig verifies the enveloped signature on the element by its DSig
	// Reference URI against a trusted root, and refuses a cert not in the store.
	// An element WITHOUT a Signature child yields an error → unsigned requests
	// are rejected (no session termination without a verified signature).
	if _, err := ctx.Validate(root); err != nil {
		return errRequestInvalid
	}
	return nil
}

// buildLogoutResponse constructs a base64-encoded SAML LogoutResponse (Status
// Success) whose root element is enveloped-XML-DSig signed with the per-tenant
// key behind signer (the SAME key published in metadata + used for assertions).
// destination is the SP's REGISTERED SLO URL (never request-supplied);
// inResponseTo binds the response to the SP's LogoutRequest ID; `now` is injected
// for deterministic tests.
//
// The response is signed (not left bare) so the SP can authenticate that the
// IdP — not an attacker — acknowledged the logout, mirroring the assertion
// signing posture. A signing failure aborts WITHOUT emitting anything.
func buildLogoutResponse(issuer, destination, inResponseTo string, signer *AssertionSigner, now time.Time) (string, error) {
	if signer == nil {
		return "", ErrUnsupportedSigningKey
	}
	resp := &saml.LogoutResponse{
		ID:           "id-" + randHex(),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	}

	signedEl, err := signLogoutResponse(resp, signer)
	if err != nil {
		return "", err
	}

	doc := etree.NewDocument()
	doc.SetRoot(signedEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("saml/idp: serialize logout response: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// signLogoutResponse enveloped-signs the LogoutResponse element with signer and
// returns the signed element (Signature attached as the last child, the shape
// crewjam's SignLogoutResponse and the SP-side validateSignature expect). A
// signing failure is returned, never swallowed.
func signLogoutResponse(resp *saml.LogoutResponse, signer *AssertionSigner) (*etree.Element, error) {
	ctx, err := signer.SigningContext()
	if err != nil {
		return nil, err
	}
	el := resp.Element()
	signedEl, err := ctx.SignEnveloped(el)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: sign logout response: %w", err)
	}
	return signedEl, nil
}
