package idp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// SAML FRONT-CHANNEL Single Logout (the browser-redirect SLO chain).
//
// This complements the back-channel fan-out (fanout.go) for SPs that are NOT
// reachable from the IdP — the traditional/common SAML SLO mode. Instead of the
// IdP POSTing LogoutRequests to SPs directly, it redirects the USER'S BROWSER
// sequentially through each front-channel SP's SLO endpoint:
//
//	IdP /saml/slo  ──(302, signed LogoutRequest)──▶  SP-A's SLO URL
//	   SP-A terminates its local session, then:
//	SP-A  ──(302, signed LogoutResponse, RelayState=stateID)──▶  IdP /saml/slo/continue
//	   IdP validates SP-A's LogoutResponse sig, advances the chain:
//	IdP  ──(302, signed LogoutRequest)──▶  SP-B's SLO URL ──▶ ... ──▶ /saml/slo/continue
//	   after the LAST SP:
//	IdP  ──(302, IdP's LogoutResponse to the INITIATOR's registered SLO URL)──▶ done
//
// SECURITY (the chain must be unforgeable):
//   - The chain is driven by an UNGUESSABLE, SINGLE-USE state id (crypto/rand,
//     256-bit) held in logoutChainStore. Each /continue hop CONSUMES the current
//     id and (when SPs remain) ROTATES to a fresh id — a consumed/unknown/expired
//     id collapses to ONE saml_request_invalid (no chain-state oracle, no replay,
//     no step-skipping).
//   - Every outbound LogoutRequest is SIGNED (detached §3.4.4.1) with the TARGET
//     SP's per-tenant key. The inbound LogoutResponse at /continue is signature-
//     VALIDATED against THAT SP's REGISTERED cert before the chain advances — a
//     forged LogoutResponse cannot advance or complete the chain.
//   - The chain ONLY visits SPs read from the SESSION INDEX (registered SPs the
//     subject was actually logged into), with https-only SLO URLs (the same
//     isHTTPSURL SSRF gate the fan-out uses). The final redirect target is the
//     INITIATOR's REGISTERED SLO URL — never a request-supplied value.
//   - no-store on every hop.
//
// nil session-index / no front-channel SPs ⇒ no chain (byte-identical to the
// back-channel-only behavior).

// DefaultLogoutChainTTL bounds how long a front-channel logout chain stays
// resumable across its browser hops. 5 minutes spans a normal multi-SP redirect
// chain (each hop is a fast browser round-trip) without keeping stale chain
// state around. Mirrors the DPoP/JWT iat-window + SAML logout-freshness posture.
const DefaultLogoutChainTTL = 5 * time.Minute

// DefaultLogoutChainCapacity caps the in-memory chain store so a flood of
// SP-initiated logouts can't grow it without bound; the oldest insert is evicted
// past the cap (the same hard-cap discipline as the PendingStore).
const DefaultLogoutChainCapacity = 10000

// chainSP is one front-channel SP still to visit in a logout chain: its entity
// id, resolved client id (for the per-tenant signing key + the live registered
// SLO allowlist), and the SLO URL captured at issuance. The destination is
// re-validated against the LIVE client at each hop (signerForClient + sloAllowed
// + https gate), so a since-deregistered/rotated SP is handled and the SLO URL
// is never blindly trusted from the recorded row.
type chainSP struct {
	SPEntityID string
	SPClientID string
	SPSLOUrl   string
}

// logoutChainState is the per-chain correlation state, keyed by an UNGUESSABLE
// single-use id. It carries the subject, the front-channel SPs not yet visited,
// and how to return to the INITIATOR after the last SP (its entity id, the
// initiator's REGISTERED SLO URL, the inbound LogoutRequest ID the final
// LogoutResponse InResponseTo binds, and the initiator's RelayState echoed
// verbatim on that final response). Every field is server-derived at chain start
// from the (signature-verified) initiating request + the registered client store
// — never request-influenceable beyond the value the initiator signed.
type logoutChainState struct {
	// Subject is the NameID being logged out everywhere (the initiating
	// LogoutRequest's already-verified NameID). Stamped into each chained
	// LogoutRequest.
	Subject string

	// Remaining is the front-channel SPs not yet visited, in order. The HEAD is
	// the SP the current redirect targets; a /continue hop pops it and advances to
	// the next.
	Remaining []chainSP

	// InitiatorEntityID is the SP that started the chain (its entity id). Carried
	// for diagnostics/audit; it was already excluded from Remaining at start.
	InitiatorEntityID string

	// InitiatorClientID resolves the initiator's per-tenant signing key + live
	// registered SLO allowlist for the FINAL LogoutResponse back to it.
	InitiatorClientID string

	// InitiatorSLOUrl is the initiator's REGISTERED SLO URL the final
	// LogoutResponse is redirected to (allowlist-validated at start AND re-checked
	// against the live client at completion). Empty ⇒ the initiator registered no
	// SLO URL ⇒ the chain completes with a bare 200 (nowhere to acknowledge).
	InitiatorSLOUrl string

	// InitiatorRequestID is the initiating LogoutRequest's ID — the final
	// LogoutResponse's InResponseTo (SP-side correlation).
	InitiatorRequestID string

	// InitiatorRelayState is the initiator's opaque RelayState, echoed verbatim on
	// the final LogoutResponse (SAML requires it returned unchanged).
	InitiatorRelayState string

	// ExpiresAt is the absolute deadline after which this chain is pruned and a
	// /continue for it is treated as unknown (oracle-safe).
	ExpiresAt time.Time
}

// startFrontChannelChain begins the browser-redirect SLO chain after the IdP
// session has been terminated. front is the (already-partitioned) front-channel
// target set (SPs the subject was logged into, excluding the initiator, https
// SLO URLs); spClient is the (signature-verified) INITIATING SP client; logoutReq
// is its LogoutRequest (for the final InResponseTo); relayState is the
// initiator's RelayState. It 302s the browser to the FIRST front-channel SP's SLO
// URL carrying a signed LogoutRequest + RelayState=stateID (the initiator's
// LogoutResponse is deferred to the END of the chain), or — when every candidate
// fails to resolve — completes straight to the initiator. It ALWAYS writes a
// response (the caller returns after it). A nil/empty front is a no-op (the caller
// only invokes it with a non-empty front).
func (h *Handlers) startFrontChannelChain(w http.ResponseWriter, front []SAMLSPSession, spClient *sso.Client, logoutReq *saml.LogoutRequest, subject, relayState string) {
	if len(front) == 0 {
		return
	}

	remaining := make([]chainSP, 0, len(front))
	for _, row := range front {
		remaining = append(remaining, chainSP{
			SPEntityID: row.SPEntityID,
			SPClientID: row.SPClientID,
			SPSLOUrl:   row.SPSLOUrl,
		})
	}

	// The initiator's registered SLO URL is the FINAL return target. Resolve it
	// from the LIVE initiating client (server config, never request input); an
	// unregistered/non-allowlisted/non-https value drops it (the chain then
	// completes with a bare 200 — nowhere to acknowledge to the initiator).
	initiatorSLO := firstSLO(spClient)
	if initiatorSLO != "" && (!sloAllowed(spClient, initiatorSLO) || !isHTTPSURL(initiatorSLO)) {
		initiatorSLO = ""
	}

	state := logoutChainState{
		Subject:             subject,
		Remaining:           remaining,
		InitiatorEntityID:   spClient.Attributes[AttrSPEntityID],
		InitiatorClientID:   spClient.ID,
		InitiatorSLOUrl:     initiatorSLO,
		InitiatorRequestID:  logoutReq.ID,
		InitiatorRelayState: relayState,
	}

	h.advanceChain(w, state)
}

// advanceChain redirects the browser to the NEXT front-channel SP in state, or
// completes the chain (returns to the initiator) when none remain. It is the
// single state-machine step shared by chain start (startFrontChannelChain) and
// each /continue hop (SLOContinue):
//
//   - pop the head SP, re-resolve it against the LIVE client (per-tenant signer +
//     registered SLO allowlist + https SSRF gate, mirroring dispatchOne),
//   - store the chain under a FRESH single-use id (the id ROTATES every hop so a
//     consumed id is never replayable),
//   - sign a DETACHED §3.4.4.1 LogoutRequest carrying that id as RelayState (the
//     RelayState is part of the signed octet string, so the SP echoes it back
//     unforged), and 302 the browser to the SP's SLO URL.
//
// A SP that can't be targeted (deregistered, no https SLO URL, or no XML-DSig
// signer) is SKIPPED so one broken SP never strands the chain; when Remaining
// empties, completeChain returns to the initiator. It always writes a response
// (a 302 or the completion).
func (h *Handlers) advanceChain(w http.ResponseWriter, state logoutChainState) {
	now := h.deps.now()
	for len(state.Remaining) > 0 {
		next := state.Remaining[0]

		signer, sloURL, ok := h.resolveChainSP(next)
		if !ok {
			// This SP can't be targeted; skip it and advance — its session lapses by
			// its own expiry.
			state.Remaining = state.Remaining[1:]
			continue
		}

		// Store the chain under a FRESH id BEFORE the redirect so the /continue hop
		// finds exactly this (rotated) state. The previous id was already consumed
		// by the hop that got us here, so this id is single-use per step.
		stateID, err := h.chains.insert(state, now)
		if err != nil {
			// RNG failure storing the chain — fail closed for the chain (the IdP
			// session is already terminated; we just can't drive the browser chain).
			h.deps.Logger.Error("saml/idp: front-channel SLO store chain failed", "error", err)
			writeError(w, http.StatusInternalServerError, sso.ErrSAMLAssertionFailed)
			return
		}

		// Sign the LogoutRequest OVER the chain id as RelayState (§3.4.4.1 order:
		// SAMLRequest + RelayState + SigAlg) so the SP echoes the exact id back and
		// an attacker can't swap it mid-flight.
		reqURL, berr := buildLogoutRequestRedirectWithRelay(h.entityID(), sloURL, state.Subject, "", stateID, signer, now)
		if berr != nil {
			// Should not happen (signer already resolved). Skip this SP and advance;
			// the orphaned chain entry expires harmlessly.
			h.deps.Logger.Error("saml/idp: front-channel SLO build request failed", "sp_entity_id", next.SPEntityID, "error", berr)
			state.Remaining = state.Remaining[1:]
			continue
		}

		noStore(w)
		w.Header().Set("Location", reqURL)
		w.WriteHeader(http.StatusFound)
		return
	}

	// No SPs left — return to the initiator with the IdP's LogoutResponse.
	h.completeChain(w, state)
}

// resolveChainSP re-resolves a chain SP against the LIVE client store and returns
// its per-tenant signer + the registered, allowlisted, https SLO URL the next
// LogoutRequest is redirected to. It returns ok=false when the SP can't be
// targeted: deregistered/missing client, no allowlisted https SLO URL, or no
// XML-DSig signer (e.g. an Ed25519 tenant key). Every gate mirrors dispatchOne
// (the back-channel SSRF + per-tenant-key posture) — the destination is NEVER
// blindly trusted from the recorded row.
func (h *Handlers) resolveChainSP(sp chainSP) (*AssertionSigner, string, bool) {
	spClient, err := h.deps.ClientStore.Get(context.Background(), sp.SPClientID)
	if err != nil || spClient == nil {
		h.deps.Logger.Error("saml/idp: front-channel SLO SP client not found", "sp_client_id", sp.SPClientID, "sp_entity_id", sp.SPEntityID, "error", err)
		return nil, "", false
	}

	// Destination MUST be in the LIVE client's REGISTERED SLO allowlist; the
	// recorded URL is the fast path, re-validated, then fall back to the client's
	// current first registered SLO URL.
	sloURL := sp.SPSLOUrl
	if !sloAllowed(spClient, sloURL) {
		sloURL = firstSLO(spClient)
	}
	if sloURL == "" || !sloAllowed(spClient, sloURL) {
		h.deps.Logger.Error("saml/idp: front-channel SLO no registered SLO URL", "sp_entity_id", sp.SPEntityID)
		return nil, "", false
	}

	// SSRF gate (CRITICAL): https-only, mirroring dispatchOne. Even an allowlisted
	// registered URL is refused if it is not absolute https. The full URL is never
	// logged (only the scheme).
	if !isHTTPSURL(sloURL) {
		scheme := ""
		if u, perr := url.Parse(sloURL); perr == nil {
			scheme = u.Scheme
		}
		h.deps.Logger.Error("saml/idp: front-channel SLO refused non-https SLO URL", "sp_entity_id", sp.SPEntityID, "scheme", scheme)
		return nil, "", false
	}

	signer, err := h.signerForClient(spClient)
	if err != nil {
		h.deps.Logger.Error("saml/idp: front-channel SLO signer resolution failed", "sp_entity_id", sp.SPEntityID, "error", err)
		return nil, "", false
	}
	return signer, sloURL, true
}

// completeChain ends the chain by redirecting the browser back to the INITIATOR
// with the IdP's signed LogoutResponse (Status Success, detached §3.4.4.1) to the
// initiator's REGISTERED SLO URL — the standard chain terminus. When the
// initiator registered no (allowlisted, https) SLO URL, or its signer can't be
// resolved, it falls back to a bare 200 (every SP in the chain was already logged
// out; we simply can't acknowledge to the initiator). no-store on every path.
func (h *Handlers) completeChain(w http.ResponseWriter, state logoutChainState) {
	noStore(w)

	// Re-resolve the initiator's live client (the SLO URL must still be registered
	// + allowlisted + https at completion — never a stale/open redirect).
	if state.InitiatorSLOUrl == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	spClient, err := h.deps.ClientStore.Get(context.Background(), state.InitiatorClientID)
	if err != nil || spClient == nil || !sloAllowed(spClient, state.InitiatorSLOUrl) || !isHTTPSURL(state.InitiatorSLOUrl) {
		w.WriteHeader(http.StatusOK)
		return
	}
	signer, err := h.signerForClient(spClient)
	if err != nil {
		// Per-tenant key can't drive XML-DSig — the chain is done regardless (every
		// SP was logged out); we just can't sign the final acknowledgement.
		h.deps.Logger.Error("saml/idp: front-channel SLO completion signer failed", "client_id", state.InitiatorClientID, "error", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	respURL, err := buildLogoutResponseRedirect(h.entityID(), state.InitiatorSLOUrl, state.InitiatorRequestID, state.InitiatorRelayState, signer, h.deps.now())
	if err != nil {
		h.deps.Logger.Error("saml/idp: front-channel SLO build completion response failed", "client_id", state.InitiatorClientID, "error", err)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Location", respURL)
	w.WriteHeader(http.StatusFound)
}

// SLOContinue handles GET /saml/slo/continue — the front-channel chain RESUME
// endpoint. A front-channel SP, after terminating its local session, redirects
// the browser HERE with a signed LogoutResponse + RelayState=chain-state-id. The
// IdP:
//
//  1. no-store at entry (before any branch).
//  2. PEEKS the chain by the RelayState id (non-consuming). Unknown / expired →
//     one collapsed saml_request_invalid (no chain-state oracle).
//  3. Validates the inbound LogoutResponse's DETACHED §3.4.4.1 signature against
//     the SP it was REDIRECTED TO (the chain head's REGISTERED cert) — a forged /
//     unsigned / attacker-signed LogoutResponse fails HERE, BEFORE the chain is
//     consumed, so it neither advances the chain NOR burns the legitimate chain's
//     single-use state.
//  4. CONSUMES the chain (SINGLE-USE) only after the signature verifies — a
//     replayed (already-consumed) id loses the consume race and is rejected
//     (oracle-safe). The chain id ROTATES on the next hop.
//  5. ADVANCES: pop the acknowledged SP, redirect to the next front-channel SP
//     (fresh single-use id), or complete to the initiator when none remain.
//
// GET only (the front-channel binding is HTTP-Redirect). Every failure collapses
// to saml_request_invalid; the chain is never advanced on a bad/forged input.
func (h *Handlers) SLOContinue(w http.ResponseWriter, r *http.Request) {
	noStore(w)

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, sso.ErrSAMLRequestInvalid)
		return
	}

	stateID := r.URL.Query().Get("RelayState")
	samlResponse := r.URL.Query().Get("SAMLResponse")
	if stateID == "" || samlResponse == "" {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	now := h.deps.now()

	// (2) Non-consuming peek — unknown/expired is indistinguishable (oracle-safe).
	state, ok := h.chains.peek(stateID, now)
	if !ok {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// The chain head is the SP the previous hop redirected TO — the one whose
	// signed LogoutResponse we now expect. A chain with no remaining head is
	// structurally impossible (we only insert a chain with a non-empty Remaining),
	// but guard anyway (oracle-safe).
	if len(state.Remaining) == 0 {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}
	ackSP := state.Remaining[0]

	// (3) Validate the LogoutResponse signature against the ACKNOWLEDGING SP's
	// REGISTERED cert (the same cert the IdP authenticates that SP's inbound
	// LogoutRequests with) — BEFORE consuming, so a forged response neither
	// advances nor burns the chain.
	if err := h.verifyChainLogoutResponse(r.Context(), ackSP, samlResponse, r.URL.RawQuery); err != nil {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (4) Signature verified — NOW consume the chain (single-use). A replayed id
	// (already consumed by the legit hop) loses this race → rejected.
	state, ok = h.chains.consume(stateID, now)
	if !ok {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}
	if len(state.Remaining) == 0 {
		writeError(w, http.StatusBadRequest, sso.ErrSAMLRequestInvalid)
		return
	}

	// (5) The head SP acknowledged — advance to the rest (or complete to the
	// initiator). advanceChain pops the head and drives the next 302 (fresh
	// single-use id) or completeChain.
	state.Remaining = state.Remaining[1:]
	h.advanceChain(w, state)
}

// verifyChainLogoutResponse validates the inbound DETACHED §3.4.4.1 LogoutResponse
// at /saml/slo/continue against the acknowledging SP's REGISTERED signing cert,
// and checks the response Issuer == that SP's entity id (defense-in-depth: the
// signature already binds it to the pinned cert; this rejects a response whose
// Issuer names a different entity even if it somehow carried a trusted signature).
// Every failure returns a non-nil error the caller collapses to one oracle-safe
// code. The SP's cert is the one IT registered (saml_sp_signing_cert) — a SAML SP
// that performs front-channel SLO MUST register its signing cert (the same cert
// the IdP authenticates that SP's LogoutRequests with).
func (h *Handlers) verifyChainLogoutResponse(ctx context.Context, ackSP chainSP, samlResponseB64, rawQuery string) error {
	spClient, err := h.deps.ClientStore.Get(ctx, ackSP.SPClientID)
	if err != nil || spClient == nil {
		return errRequestInvalid
	}
	cert, err := parseSPSigningCert(spClient.Attributes[AttrSPSigningCert])
	if err != nil {
		return errRequestInvalid
	}
	// DETACHED signature over the raw §3.4.4.1 octet string (SAMLResponse [+
	// RelayState] + SigAlg), reconstructed from the exact wire bytes.
	if err := verifyRedirectSignature(cert, rawQuery, "SAMLResponse"); err != nil {
		return errRequestInvalid
	}

	// Parse + check the Issuer matches the acknowledging SP (the redirect binding
	// carries a raw-DEFLATEd body).
	resp, err := parseLogoutResponse(samlResponseB64, true)
	if err != nil {
		return errRequestInvalid
	}
	wantIssuer := spClient.Attributes[AttrSPEntityID]
	if resp.Issuer == nil || wantIssuer == "" || resp.Issuer.Value != wantIssuer {
		return errRequestInvalid
	}
	return nil
}

// buildLogoutRequestRedirectWithRelay builds a SIGNED HTTP-Redirect LogoutRequest
// URL (DETACHED §3.4.4.1 signature, UNSIGNED body) carrying relayState as part of
// the signed octet string (SAML Bindings §3.4.4.1: SAMLRequest + RelayState +
// SigAlg). It is the front-channel analogue of buildLogoutRequestRedirect (which
// passes no RelayState) — the chain MUST carry its single-use state id as
// RelayState so the SP echoes it back verbatim to /saml/slo/continue, and the
// IdP signs OVER it so an attacker can't swap the chain id mid-flight. A signing
// failure aborts WITHOUT emitting anything.
func buildLogoutRequestRedirectWithRelay(issuer, destination, nameID, sessionIndex, relayState string, signer *AssertionSigner, now time.Time) (string, error) {
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
	return buildRedirectURL(signCtx, sigAlg, destination, "SAMLRequest", raw, relayState)
}

// parseLogoutResponse decodes + XXE-validates + unmarshals a wire SAMLResponse
// into a crewjam LogoutResponse. redirectBinding selects raw-DEFLATE (the
// front-channel chain's binding) vs plain base64. Every failure returns
// errRequestInvalid (collapsed, oracle-safe). The SLO-response analogue of
// parseLogoutRequest — crewjam v0.5.1 exposes no IdP-side LogoutResponse parser,
// so we decode through the same hardened pipeline.
func parseLogoutResponse(samlResponse string, redirectBinding bool) (*saml.LogoutResponse, error) {
	raw, err := decodeAuthnRequest(samlResponse, redirectBinding)
	if err != nil {
		return nil, errRequestInvalid
	}
	if err := validateXMLRoundTrip(raw); err != nil {
		return nil, errRequestInvalid
	}
	var resp saml.LogoutResponse
	if err := xmlUnmarshalStrict(raw, &resp); err != nil {
		return nil, errRequestInvalid
	}
	return &resp, nil
}
