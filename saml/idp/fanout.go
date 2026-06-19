package idp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
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

// fanoutMaxInflightDispatches caps the number of CONCURRENT fan-out dispatch
// goroutines across ALL in-flight logouts (each Fanout() spawns one
// fanoutDispatch, which itself fans out to up to fanoutMaxConcurrent SPs, each
// up to fanoutPerSPTimeout). Without a global ceiling, O(concurrent-logouts)
// dispatch goroutines accumulate under sustained logout pressure. The semaphore
// is acquired NON-BLOCKING before spawning; when full, the dispatch is DROPPED
// (logged) rather than spawned — best-effort, mirroring the rest of the fan-out
// posture (the initiator has already logged out locally; a dropped fan-out only
// delays remote SP termination until their own session expiry). 64 ≈ 8× the
// per-dispatch SP concurrency, so the steady-state worst case is bounded at
// fanoutMaxInflightDispatches × fanoutMaxConcurrent outbound connections.
const fanoutMaxInflightDispatches = 64

// fanoutDispatchSem is the package-level global ceiling on concurrent fan-out
// dispatch goroutines (see fanoutMaxInflightDispatches). A buffered channel used
// as a counting semaphore: a non-blocking send acquires a slot, a receive
// (in fanoutDispatch's defer) releases it.
var fanoutDispatchSem = make(chan struct{}, fanoutMaxInflightDispatches)

// fanout failure reasons are a SMALL FIXED set recorded in the logout_notified
// audit event's Reason. They MUST NOT embed the destination URL or a raw
// transport error: an HTTP error string is `Post "https://host/...": ...`,
// which would leak the fan-out target (and confirm an SSRF probe) into the audit
// sink. The full error is logged via the logger (operator diagnostics) — only
// these bounded strings reach the audit record.
const (
	fanoutReasonSPClientNotFound = "sp client not found"
	fanoutReasonNoRegisteredSLO  = "no registered slo url"
	fanoutReasonNonHTTPSSLOURL   = "non-https slo url"
	fanoutReasonSignFailed       = "sign failed"
	fanoutReasonDeliveryFailed   = "delivery failed"
	fanoutReasonPanic            = "dispatch panic"
)

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

// isHTTPSURL reports whether raw is an absolute https URL with a host. This is
// the SSRF gate on the fan-out destination: a registered SP's saml_sp_slo_url is
// operator config, but a non-https value (http:// internal/IMDS target,
// file://, a scheme-relative or hostless garbage URL) would turn the IdP's
// signed-LogoutRequest dispatch into a server-side request to an
// attacker/internal endpoint. Mirrors caep.ValidateReceiverEndpoint exactly
// (the CAEP receiver-endpoint https policy). Enforced at dispatch (runtime gate)
// AND at issuance (recordSessionIndex never indexes a non-https SLO URL).
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}

// partitionSLOTargets splits the index rows for a subject into the BACK-channel
// and FRONT-channel target sets, EXCLUDING excludeSPEntityID (the initiating SP)
// and any row with no registered SLO URL (nowhere to deliver). It is the shared
// classifier both the exported Fanout (back-channel only, server-side) and the
// SP-initiated /saml/slo handler (back-channel async + front-channel chain) use,
// so the partition rule lives in ONE place. The split is by SPChannel:
// ChannelFrontchannel rows go to front, everything else (the default
// ChannelBackchannel) to back.
func partitionSLOTargets(rows []SAMLSPSession, excludeSPEntityID string) (back, front []SAMLSPSession) {
	for _, row := range rows {
		if row.SPEntityID == "" || row.SPEntityID == excludeSPEntityID {
			continue
		}
		if row.SPSLOUrl == "" {
			// SP registered no SLO URL ⇒ nowhere to deliver; skip.
			continue
		}
		if row.SPChannel == ChannelFrontchannel {
			front = append(front, row)
		} else {
			back = append(back, row)
		}
	}
	return back, front
}

// Fanout pushes a signed SAML LogoutRequest to every OTHER BACK-channel SP the
// subject has an active SAML session with, EXCLUDING excludeSPEntityID (the SP
// that initiated the logout; pass "" to notify all). It reads the
// SAMLSessionIndex, dispatches async + best-effort + bounded, then
// RemoveAll(subject) so no stale subject->SP rows leak.
//
// It is exported so an operator's forked main can drive IdP-INITIATED global
// logout (e.g. from /end_session or an admin action) WITHOUT this module
// invasively hooking the core SessionManager: the operator calls
// handlers.Fanout(ctx, subject, "") from their own logout flow. The SP-initiated
// /saml/slo path drives the back-channel + front-channel split itself (see SLO).
//
// FRONT-channel SPs are SKIPPED here (logged): the front-channel chain needs the
// USER'S BROWSER to redirect through each SP, which a server-side IdP-initiated
// call has no access to — those SP sessions lapse by their own session expiry.
// Their rows are still cleaned by the RemoveAll below.
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

	// Partition synchronously BEFORE spawning so the work is known and the
	// initiating SP is never sent its own logout.
	back, front := partitionSLOTargets(rows, excludeSPEntityID)
	if len(front) > 0 {
		// IdP-initiated server-side logout cannot drive a browser-redirect chain;
		// log + skip those SPs (their sessions lapse by expiry). The SP-initiated
		// /saml/slo path drives the chain (it has the browser).
		h.deps.Logger.Error("saml/idp: SLO fan-out skipping front-channel SPs (no browser for the redirect chain)", "subject", subject, "count", len(front))
	}

	// Clean the index NOW (the subject is being logged out everywhere). Done
	// before the async dispatch so a re-login during the (slow) dispatch starts a
	// fresh row set rather than racing the cleanup. Best-effort.
	if err := h.deps.SessionIndex.RemoveAll(ctx, subject); err != nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out index cleanup failed", "error", err, "subject", subject)
	}

	h.dispatchBackchannel(subject, back)
}

// splitSLOTargets reads the SAMLSessionIndex for subject ONCE, partitions it into
// the BACK-channel + FRONT-channel target sets (excluding excludeSPEntityID, the
// initiator), and CLEANS the index (RemoveAll) — all synchronously. It is the
// SP-initiated /saml/slo entry point's read: the caller dispatches the
// back-channel set async (dispatchBackchannel) AND drives the front-channel set
// through the browser chain (startFrontChannelChain). Cleaning the index here is
// safe because the front-channel chain carries its SP list in its OWN single-use
// chain state (it does not re-read the index). A nil index ⇒ (nil, nil): no
// fan-out + no chain (byte-identical to the single-SP SLO). A blank subject or a
// list error ⇒ (nil, nil) too.
func (h *Handlers) splitSLOTargets(ctx context.Context, subject, excludeSPEntityID string) (back, front []SAMLSPSession) {
	if h.deps.SessionIndex == nil || subject == "" {
		return nil, nil
	}
	rows, err := h.deps.SessionIndex.ListBySubject(ctx, subject)
	if err != nil {
		h.deps.Logger.Error("saml/idp: SLO list sessions failed", "error", err, "subject", subject)
		return nil, nil
	}
	back, front = partitionSLOTargets(rows, excludeSPEntityID)

	// Clean the index NOW (the subject is being logged out everywhere). Done before
	// either dispatch so a re-login during the (slow) back-channel dispatch / the
	// (browser-paced) front-channel chain starts a fresh row set rather than racing
	// the cleanup. Best-effort.
	if err := h.deps.SessionIndex.RemoveAll(ctx, subject); err != nil {
		h.deps.Logger.Error("saml/idp: SLO index cleanup failed", "error", err, "subject", subject)
	}
	return back, front
}

// dispatchBackchannel spawns the detached, supervised, bounded async delivery of
// signed LogoutRequests to a back-channel target slice (already partitioned +
// index-cleaned by the caller). A nil/empty slice is a no-op. It is shared by the
// exported Fanout and the SP-initiated /saml/slo handler so both use the same
// concurrency-ceiling + dispatch path.
func (h *Handlers) dispatchBackchannel(subject string, targets []SAMLSPSession) {
	if len(targets) == 0 {
		return
	}

	// Global ceiling on concurrent dispatch goroutines. Acquire NON-BLOCKING:
	// when the semaphore is saturated (too many in-flight logouts), DROP this
	// dispatch (best-effort, mirroring the dead-SP posture) rather than spawn an
	// unbounded goroutine. The slot is released in fanoutDispatch's defer.
	select {
	case fanoutDispatchSem <- struct{}{}:
	default:
		h.deps.Logger.Error("saml/idp: SLO fan-out dispatch dropped (concurrency ceiling reached)", "subject", subject, "targets", len(targets))
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
	// Release the global dispatch slot when this goroutine exits (acquired
	// non-blocking in Fanout). Separate defer so it runs even if the dispatch
	// panics (the recover below is unrelated to slot accounting).
	defer func() { <-fanoutDispatchSem }()
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
			h.deps.Logger.Error("saml/idp: SLO fan-out to SP panicked", "sp_entity_id", t.SPEntityID, "panic", r)
			h.recordFanoutFailure(ctx, t, fanoutReasonPanic)
		}
	}()

	// Re-resolve the live client (authoritative for the signing key + the
	// registered SLO allowlist).
	spClient, err := h.deps.ClientStore.Get(ctx, t.SPClientID)
	if err != nil || spClient == nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out SP client not found", "sp_client_id", t.SPClientID, "sp_entity_id", t.SPEntityID, "error", err)
		h.recordFanoutFailure(ctx, t, fanoutReasonSPClientNotFound)
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
		h.recordFanoutFailure(ctx, t, fanoutReasonNoRegisteredSLO)
		return
	}

	// SSRF gate (CRITICAL): the destination MUST be https. Even an allowlisted,
	// registered SLO URL is refused if it is not an absolute https URL — an
	// http:// / internal / IMDS (169.254.169.254) / file:// target would turn the
	// IdP's signed-LogoutRequest dispatch into a server-side request to an
	// attacker/internal endpoint (signed-SAML SSRF amplification). Mirrors the
	// CAEP receiver-endpoint https policy (caep.ValidateReceiverEndpoint). The
	// full URL is NEVER logged here (only the scheme), so a probe can't confirm a
	// target via the operator log either. Defense-in-depth: a non-https SLO URL
	// also never enters the session index (recordSessionIndex), so this gate is
	// the second line.
	parsed, perr := url.Parse(sloURL)
	if perr != nil || parsed.Scheme != "https" {
		scheme := ""
		if parsed != nil {
			scheme = parsed.Scheme
		}
		h.deps.Logger.Error("saml/idp: SLO fan-out refused non-https SLO URL", "sp_entity_id", t.SPEntityID, "scheme", scheme)
		h.recordFanoutFailure(ctx, t, fanoutReasonNonHTTPSSLOURL)
		return
	}

	// Resolve the per-tenant signer for THIS SP (the key that SP pinned). Fail
	// closed for this one SP (no unsigned LogoutRequest is ever emitted).
	signer, err := h.signerForClient(spClient)
	if err != nil {
		h.deps.Logger.Error("saml/idp: SLO fan-out signer resolution failed", "sp_entity_id", t.SPEntityID, "error", err)
		h.recordFanoutFailure(ctx, t, fanoutReasonSignFailed)
		return
	}

	if err := h.deliverLogoutRequest(ctx, sloURL, t, signer); err != nil {
		// Log the FULL error (with the URL) for operator diagnostics; the audit
		// record gets only the fixed reason (the raw err embeds the destination
		// URL — see fanoutReasonDeliveryFailed).
		h.deps.Logger.Error("saml/idp: SLO fan-out delivery failed", "sp_entity_id", t.SPEntityID, "url", sloURL, "error", err)
		h.recordFanoutFailure(ctx, t, fanoutReasonDeliveryFailed)
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
	client := h.fanoutClient()

	switch normalizeBinding(t.SPBinding) {
	case BindingPost:
		body, err := buildLogoutRequestPOST(h.entityID(), sloURL, t.NameID, t.SessionIndex, signer, now)
		if err != nil {
			return fmt.Errorf("build POST logout request: %w", err)
		}
		return postSLOForm(ctx, client, sloURL, body)
	default: // BindingRedirect
		reqURL, err := buildLogoutRequestRedirect(h.entityID(), sloURL, t.NameID, t.SessionIndex, signer, now)
		if err != nil {
			return fmt.Errorf("build redirect logout request: %w", err)
		}
		return getSLO(ctx, client, reqURL)
	}
}

// fanoutClient returns the HTTP client the fan-out dispatches with: the optional
// Deps.FanoutHTTPClient test/operator seam when set, else the package-default
// bounded fanoutHTTPClient (5s timeout, no redirects). The seam exists so a test
// can inject httptest.NewTLSServer().Client() (which trusts the test cert) to
// exercise the now-https-only fan-out over TLS; production leaves it nil and
// gets the hardened default. A non-nil override is still subject to the same
// https destination gate (isHTTPSURL / the dispatchOne scheme check) and the
// per-SP timeout context — the seam only swaps the transport's trust roots, not
// the SSRF policy.
func (h *Handlers) fanoutClient() *http.Client {
	if h.deps.FanoutHTTPClient != nil {
		return h.deps.FanoutHTTPClient
	}
	return fanoutHTTPClient
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
