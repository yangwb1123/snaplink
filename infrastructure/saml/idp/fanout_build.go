package idp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"github.com/snaplink/sso/platform/audit"
)

// buildLogoutRequestRedirect builds a SIGNED HTTP-Redirect LogoutRequest URL
// (DETACHED §3.4.4.1 signature, UNSIGNED body) the IdP sends to a target SP's
// registered SLO URL during fan-out. issuer is this IdP's entity id (the SP
// validates Issuer == its pinned IdP entity id); nameID is the subject;
// sessionIndex narrows the SP's termination when non-empty. Mirrors
// buildLogoutResponseRedirect but for a LogoutRequest (param "SAMLRequest", with
// a NameID/SessionIndex instead of an InResponseTo/Status). A signing failure
// aborts WITHOUT emitting anything (no unsigned request on the wire).
func buildLogoutRequestRedirect(issuer, destination, nameID, sessionIndex string, signer *AssertionSigner, now time.Time) (string, error) {
	if signer == nil {
		return "", ErrUnsupportedSigningKey
	}
	sigAlg, ok := redirectSigAlgFor(signer.SignatureMethod())
	if !ok {
		return "", ErrUnsupportedSigningKey
	}
	signCtx, err := signer.SigningContext()
	if err != nil {
		return "", err
	}
	req := newFanoutLogoutRequest(issuer, destination, nameID, sessionIndex, now)
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("saml/idp: serialize logout request: %w", err)
	}
	return buildRedirectURL(signCtx, sigAlg, destination, "SAMLRequest", raw, "")
}

// buildLogoutRequestPOST builds a base64-encoded, ENVELOPED-XML-DSig-signed
// LogoutRequest for the HTTP-POST binding fan-out (mirrors buildLogoutResponse,
// for a LogoutRequest). The root element is enveloped-signed with the per-tenant
// key (the same key the target SP pinned), so saml/sp's POST-binding
// verifyLogoutRequestSignature accepts it. A signing failure aborts WITHOUT
// emitting anything.
func buildLogoutRequestPOST(issuer, destination, nameID, sessionIndex string, signer *AssertionSigner, now time.Time) (string, error) {
	if signer == nil {
		return "", ErrUnsupportedSigningKey
	}
	req := newFanoutLogoutRequest(issuer, destination, nameID, sessionIndex, now)
	signedEl, err := signLogoutRequest(req, signer)
	if err != nil {
		return "", err
	}
	doc := etree.NewDocument()
	doc.SetRoot(signedEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("saml/idp: serialize logout request: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// newFanoutLogoutRequest constructs the crewjam LogoutRequest the fan-out signs
// + delivers. The Issuer is this IdP (NameQualifier-equivalent); the NameID is
// the subject; the SessionIndex is added only when non-empty. The IssueInstant
// is `now` (the SP enforces a freshness window on it). The ID is a crypto-random
// "id-"+hex (unguessable, so an attacker can't pre-correlate the dedup key).
func newFanoutLogoutRequest(issuer, destination, nameID, sessionIndex string, now time.Time) *saml.LogoutRequest {
	req := &saml.LogoutRequest{
		ID:           "id-" + randHex(),
		Version:      "2.0",
		IssueInstant: now,
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		NameID: &saml.NameID{Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}
	return req
}

// signLogoutRequest enveloped-signs the LogoutRequest element with signer and
// returns the signed element (Signature attached as the last child — the shape
// saml/sp's enveloped POST-binding validator expects). A signing failure is
// returned, never swallowed.
func signLogoutRequest(req *saml.LogoutRequest, signer *AssertionSigner) (*etree.Element, error) {
	ctx, err := signer.SigningContext()
	if err != nil {
		return nil, err
	}
	el := req.Element()
	signedEl, err := ctx.SignEnveloped(el)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: sign logout request: %w", err)
	}
	return signedEl, nil
}

// getSLO issues the redirect-binding LogoutRequest as a GET to the SP's SLO URL
// (the URL already carries the signed SAMLRequest + SigAlg + Signature query
// params). A non-2xx is a delivery failure. client is the bounded fan-out client
// (the package default, or the test-injected one — see Handlers.fanoutClient).
func getSLO(ctx context.Context, client *http.Client, reqURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("saml/idp: SP SLO returned status %d", resp.StatusCode)
	}
	return nil
}

// postSLOForm POSTs the POST-binding LogoutRequest (base64 SAMLRequest in a
// form-urlencoded body) to the SP's SLO URL. A non-2xx is a delivery failure.
func postSLOForm(ctx context.Context, client *http.Client, sloURL, samlRequestB64 string) error {
	form := url.Values{"SAMLRequest": {samlRequestB64}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sloURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("saml/idp: SP SLO returned status %d", resp.StatusCode)
	}
	return nil
}

// recordFanoutSuccess / recordFanoutFailure emit the per-SP fan-out outcome as a
// logout_notified audit event (the SAML analogue of the OIDC BCL
// RecordLogoutNotify*). Bounded cardinality: provider "saml-idp" + outcome +
// (the SP entity id, a bounded operator-controlled dimension) — NO trace/request
// id. Nil recorder ⇒ no-op. These run on the detached goroutine over a
// background context (there is no live request ctx), so the Event is built
// directly (mirrors recordSLO) rather than via EventFromRequest.
//
// The failure Reason is ALWAYS one of the fixed fanoutReason* constants — NEVER
// a raw err.Error(). A transport error string embeds the destination URL
// (`Post "https://host/...": ...`), which would leak the fan-out target (and
// confirm an SSRF probe) into the audit sink. The full error is logged via the
// logger only (dispatchOne). Callers MUST pass a fanoutReason* constant.
func (h *Handlers) recordFanoutSuccess(ctx context.Context, clientID string, t SAMLSPSession) {
	if h.deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:     audit.EventLogoutNotified,
		Outcome:  audit.OutcomeSuccess,
		Provider: "saml-idp",
		ClientID: clientID,
		ActorID:  t.NameID,
	}
	audit.SetMeta(e, "saml_sp_entity_id", t.SPEntityID)
	audit.SetMeta(e, "saml_slo_fanout", "true")
	h.deps.AuditRecorder.Record(ctx, e)
}

func (h *Handlers) recordFanoutFailure(ctx context.Context, t SAMLSPSession, reason string) {
	if h.deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:     audit.EventLogoutNotified,
		Outcome:  audit.OutcomeFailure,
		Provider: "saml-idp",
		ClientID: t.SPClientID,
		ActorID:  t.NameID,
		Reason:   reason,
	}
	audit.SetMeta(e, "saml_sp_entity_id", t.SPEntityID)
	audit.SetMeta(e, "saml_slo_fanout", "true")
	h.deps.AuditRecorder.Record(ctx, e)
}
