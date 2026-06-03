package idp

import (
	"context"
	"html/template"
	"net/http"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
)

// autoPostForm is the SAML HTTP-POST binding auto-submit form. It POSTs the
// base64 SAMLResponse + RelayState to the SP's REGISTERED ACS. html/template
// escapes every interpolated value, so even though the values are
// server-controlled (the ACS is registered, the SAMLResponse is base64, the
// RelayState is the SP's own echoed value) nothing can break out of an
// attribute. The script auto-submits; the visible button is a no-JS fallback.
var autoPostForm = template.Must(template.New("saml-idp-post").Parse(`<!DOCTYPE html>
<html>
<head><title>Submitting...</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="{{.ACSURL}}">
<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}
<noscript><input type="submit" value="Continue" /></noscript>
</form>
</body>
</html>`))

type autoPostData struct {
	ACSURL       string
	SAMLResponse string
	RelayState   string
}

// Finish handles POST /saml/sso/finish — resumes an SP-initiated login after
// the user authenticated at /auth/login, mints + signs the assertion, and
// returns the auto-POST form to the SP's REGISTERED ACS.
//
// Flow:
//
//  1. no-store at entry.
//  2. Read session_id + saml_request_id from the POST body.
//  3. CONSUME the pending request (single-use; DELETE-on-read). Unknown,
//     expired, or already-consumed → saml_request_invalid (oracle-safe).
//  4. Validate the session is LIVE (SessionManager.Get; expired/revoked/unknown
//     → the SAME saml_request_invalid — no session-presence oracle).
//  5. Load the authenticated user (for the assertion attributes).
//  6. Resolve the SP client → per-tenant signing key via IssuerForClient +
//     CryptoSigner(). FAIL CLOSED (500 saml_assertion_failed) if no signer —
//     NEVER fall back to another tenant's key.
//  7. Build + enveloped-XML-DSig-sign the assertion; POST to the registered ACS.
//  8. Audit login_success (provider "saml-idp", SP entityID via SetMeta).
func (h *Handlers) Finish(w http.ResponseWriter, r *http.Request) {
	noStore(w)

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, sso.ErrSAMLRequestInvalid)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}
	sessionID := r.PostForm.Get(sso.KeySessionID)
	samlRequestID := r.PostForm.Get(sso.KeyState)
	if sessionID == "" || samlRequestID == "" {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (3) Single-use consume. Unknown/expired/consumed all return !ok →
	// collapse to one code.
	pending, ok := h.pending.Consume(samlRequestID)
	if !ok {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (4) Live-session check. A captured/expired/revoked session id collapses
	// to the SAME code as an unknown pending request — no oracle distinguishing
	// "bad session" from "bad request".
	session, err := h.deps.SessionManager.Get(r.Context(), sessionID)
	if err != nil || session == nil || session.Revoked {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (5) Load the authenticated user. A missing user is treated as a request
	// failure (the session named a user that no longer exists) — same code.
	user, err := h.deps.UserProvider.GetByID(r.Context(), session.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (6) Resolve the SP client + its per-tenant signer. The SP client is the
	// one named in the pending record (validated at /saml/sso). FAIL CLOSED on
	// any signer-resolution failure.
	spClient, err := h.deps.ClientStore.Get(r.Context(), pending.SPClientID)
	if err != nil || spClient == nil {
		// The SP client vanished between /saml/sso and finish — can't sign for
		// it. Internal failure, fail closed.
		h.deps.Logger.Error("saml/idp: SP client not found at finish", "client_id", pending.SPClientID, "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}
	signer, err := h.signerForClient(spClient)
	if err != nil {
		// Per-tenant key can't drive XML-DSig (e.g. Ed25519 issuer) or the
		// issuer is unresolvable. NEVER fall back to another tenant's key — fail
		// closed with the IdP-internal code.
		h.deps.Logger.Error("saml/idp: resolve per-tenant signer failed", "client_id", spClient.ID, "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	// (7) Build + sign the assertion (the assertion is signed inside
	// BuildResponse; a signing failure aborts WITHOUT emitting anything).
	now := h.deps.now()
	samlResponse, err := BuildResponse(pending, user, signer, h.entityID(), h.deps.AssertionTTL, now)
	if err != nil {
		h.deps.Logger.Error("saml/idp: build assertion failed", "client_id", spClient.ID, "error", err)
		writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
		return
	}

	// (8) Audit login_success on the SAME recorder the rest of the server uses.
	h.recordAssertion(r, spClient.ID, pending.SPEntityID, user.ID)

	// (9) Record the subject->SP session in the SAML session index so a later
	// SP-initiated SLO can fan out a signed LogoutRequest to this SP. Only when
	// the index is wired (nil ⇒ fan-out disabled ⇒ this is a no-op, byte-
	// identical to the pre-fan-out behavior). Best-effort: a record failure is
	// logged, never surfaced — it MUST NOT fail an otherwise-successful login.
	h.recordSessionIndex(r.Context(), spClient, pending.SPEntityID, user.ID)

	// Return the auto-POST form to the REGISTERED ACS (pending.ACSURL, never a
	// response-controlled URL). The pending request was already consumed, so
	// this is single-use.
	w.Header().Set(sso.HeaderContentType, "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = autoPostForm.Execute(w, autoPostData{
		ACSURL:       pending.ACSURL,
		SAMLResponse: samlResponse,
		RelayState:   pending.RelayState,
	})
}

// recordAssertion records a login_success audit event for an issued SAML
// assertion. provider is "saml-idp"; the SP entityID rides on Metadata via
// SetMeta (NEVER e.Metadata = map{} — that would clobber geo/tenant
// enrichment, AGENTS.md §2). Nil recorder = no-op.
func (h *Handlers) recordAssertion(r *http.Request, clientID, spEntityID, userID string) {
	if h.deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:     audit.EventLogin,
		Outcome:  audit.OutcomeSuccess,
		Provider: "saml-idp",
		ClientID: clientID,
		ActorID:  userID,
	}
	audit.SetMeta(e, "saml_sp_entity_id", spEntityID)
	h.deps.AuditRecorder.Record(r.Context(), e)
}

// recordSessionIndex records this subject->SP session in the SAML session index
// (for the SLO fan-out). It captures the SP's REGISTERED SLO URL + binding from
// the LIVE client (server-side config, never request input), the SP entity id,
// and the subject (== the assertion NameID == user.ID). The SessionIndex is
// EMPTY because the IdP does not currently stamp a per-session SessionIndex into
// assertions (so a fanned-out LogoutRequest carries no SessionIndex ⇒ the SP
// does full-subject logout, the documented behavior). Nil index ⇒ no-op.
//
// An SP that registered NO SLO URL is still recorded (with an empty SPSLOUrl);
// the fan-out skips it (nowhere to deliver) — but recording it keeps the index a
// faithful picture of the subject's SP sessions for RemoveAll. Best-effort: a
// record error is logged, never surfaced.
func (h *Handlers) recordSessionIndex(ctx context.Context, spClient *sso.Client, spEntityID, subject string) {
	if h.deps.SessionIndex == nil {
		return
	}
	if err := h.deps.SessionIndex.Record(ctx, subject, SAMLSPSession{
		SPEntityID:   spEntityID,
		SPClientID:   spClient.ID,
		SPSLOUrl:     firstSLO(spClient),
		SPBinding:    spSLOBinding(spClient),
		NameID:       subject,
		SessionIndex: "", // IdP emits no per-session SessionIndex (full-subject logout)
	}); err != nil {
		h.deps.Logger.Error("saml/idp: record session index failed", "client_id", spClient.ID, "error", err)
	}
}
