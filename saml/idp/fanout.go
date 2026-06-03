package idp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"github.com/snaplink/sso/audit"
)

// SAML SLO BACK-CHANNEL FAN-OUT (global single logout).
//
// This is the SAML analogue of OIDC Back-Channel Logout (server_extensions.go
// fanOutBackchannelLogout). On an SP-initiated logout the IdP, after terminating
// its OWN session for the subject, pushes a SIGNED SAML LogoutRequest to EVERY
// OTHER SP the subject has an active SAML session with (read from the
// SAMLSessionIndex), so those SPs terminate their local sessions too — the
// standard SLO chain. It is:
//
//   - SIGNED per-target-SP with the SAME per-tenant key that SP pinned at boot
//     (signerForClient(targetSP)) — so each target SP's saml/sp
//     ProcessLogoutRequest accepts it (the request's enveloped/detached signature
//     verifies against the pinned IdP cert, Issuer == this IdP's entity id,
//     non-empty NameID). The request is NEVER emitted unsigned (a signing failure
//     drops that one SP, logged, never an unsigned request on the wire).
//   - DELIVERED only to the SP's REGISTERED SLO URL (AttrSPSLOUrls, captured at
//     issuance + re-validated against the live client at dispatch) — never a
//     request-supplied destination.
//   - ASYNC + BEST-EFFORT + BOUNDED: a detached, supervised goroutine
//     (context.Background() + a per-SP timeout + recover()) so a slow/dead SP
//     NEVER blocks the initiator's LogoutResponse. A dead SP drops its request
//     (logged + audited as a logout_notified failure); the global logout still
//     returns Success to the initiator.
//   - EXCLUDES the initiating SP (it already knows it is logging out) by its
//     entity id.
//
// Disabled (nil index) ⇒ this file is never reached (the SLO handler short-
// circuits), so the single-SP SLO behavior is byte-identical.

// fanoutPerSPTimeout bounds a single SP's LogoutRequest delivery. Mirrors the
// OIDC BCL DefaultBackchannelLogoutTimeout (5s): long enough for a healthy SP to
// 2xx, short enough that a hung SP's goroutine reclaims promptly.
const fanoutPerSPTimeout = 5 * time.Second

// fanoutMaxConcurrent bounds the parallel fan-out so a subject federated to many
// SPs does not emit a connection burst (mirrors DefaultBackchannelLogoutMaxConcurrent).
// A serial loop would stack each SP's timeout linearly; an unbounded
// goroutine-per-SP would burst N connections. The bounded pool keeps p99 at
// roughly timeout × ceil(N/max).
const fanoutMaxConcurrent = 8

// fanoutHTTPClient is the bounded HTTP client the fan-out dispatches with. The
// per-request deadline is enforced via the request context (fanoutPerSPTimeout);
// this client-level Timeout is a belt-and-suspenders ceiling on the whole
// round-trip. No redirects are followed (a registered SLO URL is the exact
// endpoint; an SP that 30x-redirects a logout is not followed to an unvetted
// location).
var fanoutHTTPClient = &http.Client{
	Timeout: fanoutPerSPTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Fanout pushes a signed SAML LogoutRequest to every OTHER SP the subject has an
// active SAML session with, EXCLUDING excludeSPEntityID (the SP that initiated
// the logout; pass "" to notify all). It reads the SAMLSessionIndex, dispatches
// async + best-effort + bounded, then RemoveAll(subject) so no stale subject->SP
// rows leak.
//
// It is exported so an operator's forked main can drive IdP-INITIATED global
// logout (e.g. from /end_session or an admin action) WITHOUT this module
// invasively hooking the core SessionManager: the operator calls
// handlers.Fanout(ctx, subject, "") from their own logout flow. The SP-initiated
// /saml/slo path calls it internally with the initiating SP excluded.
//
// Behavior:
//   - nil index ⇒ no-op (fan-out disabled).
//   - The index read + RemoveAll happen SYNCHRONOUSLY (cheap, in-memory) so the
//     caller's request returns with the index already cleaned; the network
//     dispatch runs in a detached goroutine that outlives the request.
//   - A blank subject is a no-op (nothing to log out).
func (h *Handlers) Fanout(ctx context.Context, subject, excludeSPEntityID string) {
	if h.deps.SessionIndex == nil || subject == "" {
		return
	}

	rows, err := h.deps.SessionIndex.ListBySubject(ctx, subject)
	if err != nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out list sessions failed", "error", err, "subject", subject)
		return
	}

	// Filter to the OTHER SPs (exclude the initiator) with a registered SLO URL.
	// Done synchronously BEFORE spawning so the count of work is known and the
	// initiating SP is never sent its own logout.
	targets := make([]SAMLSPSession, 0, len(rows))
	for _, row := range rows {
		if row.SPEntityID == "" || row.SPEntityID == excludeSPEntityID {
			continue
		}
		if row.SPSLOUrl == "" {
			// SP registered no SLO URL ⇒ nowhere to deliver; skip.
			continue
		}
		targets = append(targets, row)
	}

	// Clean the index NOW (the subject is being logged out everywhere). Done
	// before the async dispatch so a re-login during the (slow) dispatch starts a
	// fresh row set rather than racing the cleanup. Best-effort.
	if err := h.deps.SessionIndex.RemoveAll(ctx, subject); err != nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out index cleanup failed", "error", err, "subject", subject)
	}

	if len(targets) == 0 {
		return
	}

	// Detached supervised dispatch: the request that triggered the logout has
	// returned, so context.Background() is the correct PARENT (inheriting the
	// request ctx would cancel the dispatch the instant the response is written).
	// A per-SP deadline is added inside dispatchOne.
	go h.fanoutDispatch(targets)
}

// fanoutDispatch runs the bounded parallel delivery of the LogoutRequests. It is
// the detached-goroutine body: a top-level recover() so a panic in the dispatch
// (e.g. a signer edge case) can't crash the process from a bare goroutine, and a
// bounded worker pool over the targets.
func (h *Handlers) fanoutDispatch(targets []SAMLSPSession) {
	defer func() {
		if r := recover(); r != nil {
			h.deps.Logger.Error("saml/idp: SLO fan-out dispatch panicked", "panic", r)
		}
	}()

	max := fanoutMaxConcurrent
	if max > len(targets) {
		max = len(targets)
	}
	work := make(chan SAMLSPSession, len(targets))
	for _, t := range targets {
		work <- t
	}
	close(work)

	var wg sync.WaitGroup
	wg.Add(max)
	for i := 0; i < max; i++ {
		go func() {
			defer wg.Done()
			for t := range work {
				h.dispatchOne(t)
			}
		}()
	}
	wg.Wait()
}

// dispatchOne builds + delivers ONE SP's signed LogoutRequest, bounded by a
// per-SP timeout and wrapped in recover() (a panic in one SP's delivery must not
// take down the worker / process). Every outcome is recorded as a
// logout_notified audit event (success/failure) — the bounded-cardinality
// observability seam the module exposes (provider "saml-idp"; the SAML analogue
// of the OIDC BCL per-RP RecordLogoutNotify*; no high-cardinality dimensions).
//
// SECURITY: the SP client is re-resolved FRESH from the ClientStore by the
// recorded SPClientID (so a deleted/rotated SP is handled and the per-tenant
// signing key is resolved through the SAME signerForClient path issuance used),
// and the SLO URL is taken from that LIVE client's REGISTERED allowlist (not
// blindly from the recorded row) — a request-supplied or stale-unregistered URL
// can never be a fan-out destination.
func (h *Handlers) dispatchOne(t SAMLSPSession) {
	ctx, cancel := context.WithTimeout(context.Background(), fanoutPerSPTimeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("panic: %v", r)
			h.deps.Logger.Error("saml/idp: SLO fan-out to SP panicked", "sp_entity_id", t.SPEntityID, "panic", r)
			h.recordFanoutFailure(ctx, t, reason)
		}
	}()

	// Re-resolve the live client (authoritative for the signing key + the
	// registered SLO allowlist).
	spClient, err := h.deps.ClientStore.Get(ctx, t.SPClientID)
	if err != nil || spClient == nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out SP client not found", "sp_client_id", t.SPClientID, "sp_entity_id", t.SPEntityID, "error", err)
		h.recordFanoutFailure(ctx, t, "sp client not found")
		return
	}

	// The destination MUST be in the live client's REGISTERED SLO allowlist. The
	// recorded SPSLOUrl is the fast path; re-validate it against the current
	// client so a since-deregistered URL is refused (never a stale/open redirect).
	sloURL := t.SPSLOUrl
	if !sloAllowed(spClient, sloURL) {
		// Fall back to the client's current first registered SLO URL (the SP may
		// have re-registered a different one since issuance).
		sloURL = firstSLO(spClient)
	}
	if sloURL == "" || !sloAllowed(spClient, sloURL) {
		h.deps.Logger.Error("saml/idp: SLO fan-out no registered SLO URL", "sp_entity_id", t.SPEntityID)
		h.recordFanoutFailure(ctx, t, "no registered slo url")
		return
	}

	// Resolve the per-tenant signer for THIS SP (the key that SP pinned). Fail
	// closed for this one SP (no unsigned LogoutRequest is ever emitted).
	signer, err := h.signerForClient(spClient)
	if err != nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out signer resolution failed", "sp_entity_id", t.SPEntityID, "error", err)
		h.recordFanoutFailure(ctx, t, "signer resolution failed")
		return
	}

	if err := h.deliverLogoutRequest(ctx, sloURL, t, signer); err != nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out delivery failed", "sp_entity_id", t.SPEntityID, "url", sloURL, "error", err)
		h.recordFanoutFailure(ctx, t, err.Error())
		return
	}
	h.recordFanoutSuccess(ctx, spClient.ID, t)
}

// deliverLogoutRequest builds the signed LogoutRequest in the SP's REGISTERED
// binding and POSTs/GETs it to the SP's SLO URL. The request shape is EXACTLY
// what saml/sp ProcessLogoutRequest validates:
//   - Issuer == this IdP's entity id (h.entityID()),
//   - non-empty NameID (the subject),
//   - redirect binding → DETACHED §3.4.4.1 SigAlg+Signature over the octet
//     string (the default; saml/sp validates this for the redirect binding),
//   - post binding     → enveloped XML-DSig over the body (saml/sp validates
//     this for the POST binding).
//
// A non-2xx (redirect) / non-2xx (post) response is a delivery failure (the SP
// is still considered logged out best-effort, but the failure is recorded).
func (h *Handlers) deliverLogoutRequest(ctx context.Context, sloURL string, t SAMLSPSession, signer *AssertionSigner) error {
	now := h.deps.now()

	switch normalizeBinding(t.SPBinding) {
	case BindingPost:
		body, err := buildLogoutRequestPOST(h.entityID(), sloURL, t.NameID, t.SessionIndex, signer, now)
		if err != nil {
			return fmt.Errorf("build POST logout request: %w", err)
		}
		return postSLOForm(ctx, sloURL, body)
	default: // BindingRedirect
		reqURL, err := buildLogoutRequestRedirect(h.entityID(), sloURL, t.NameID, t.SessionIndex, signer, now)
		if err != nil {
			return fmt.Errorf("build redirect logout request: %w", err)
		}
		return getSLO(ctx, reqURL)
	}
}

// normalizeBinding maps a recorded SPBinding to a known binding (defaulting to
// redirect), tolerant of the crewjam binding URIs or empty.
func normalizeBinding(b string) string {
	switch b {
	case BindingPost, saml.HTTPPostBinding:
		return BindingPost
	default:
		return BindingRedirect
	}
}

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
// params). A non-2xx is a delivery failure.
func getSLO(ctx context.Context, reqURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := fanoutHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("saml/idp: SP SLO returned status %d", resp.StatusCode)
	}
	return nil
}

// postSLOForm POSTs the POST-binding LogoutRequest (base64 SAMLRequest in a
// form-urlencoded body) to the SP's SLO URL. A non-2xx is a delivery failure.
func postSLOForm(ctx context.Context, sloURL, samlRequestB64 string) error {
	form := url.Values{"SAMLRequest": {samlRequestB64}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sloURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := fanoutHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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
