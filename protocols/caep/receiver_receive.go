package caep

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// knownReceiverEvent reports whether the receiver knows how to ACT on an
// SSF event URI. Only the revocation-relevant CAEP/RISC events are
// actionable; any other URI is ignored (ack + no-op), so a transmitter
// emitting a richer event set never causes a spurious action or an error.
func knownReceiverEvent(uri string) bool {
	switch uri {
	case EventURICAEPSessionRevoked,
		EventURIRISCAccountDisabled,
		EventURICAEPTokenClaimsChange,
		EventURICAEPTokenRevoked:
		return true
	default:
		return false
	}
}

// Receive validates one inbound SET (the compact-JWS body) and, when fully
// valid AND mapped to a local subject, revokes that subject's local access.
// It returns a ReceiverResult the HTTP handler renders into an ack (202) or
// an SSF error (400). It NEVER returns an error for a validation failure —
// the failure is encoded in ReceiverResult.RejectCode (oracle-safe). A
// non-nil error means a transient internal failure (e.g. a revoke-store
// outage AFTER full validation) the handler maps to a 500; the validated
// intent is real, so the transmitter should retry.
//
// Validation order (each trust failure collapses to the SAME coarse
// ErrReceiverInvalidKey so the wire reveals no detail):
//
//  1. parse the compact JWS + read its claims enough to find `iss`.
//  2. iss-allowlist: `iss` MUST name a configured trusted transmitter.
//  3. signature: verify against THAT transmitter's JWKS via
//     VerifyCompactJWS (alg-allowlist BEFORE signature; no alg=none/HS*).
//  4. typ: the JOSE header `typ` MUST be secevent+jwt.
//  5. aud-binding: `aud` MUST contain this server's audience.
//  6. temporal: a SET MUST carry iat and/or exp (neither ⇒ reject), within
//     the configured skew.
//  7. jti replay: MarkSeen — a seen jti rejects (fail-closed).
//  8. events: keep only KNOWN actionable URIs (honoring the transmitter's
//     AllowedEvents). No actionable event ⇒ ack + no-op.
//  9. subject mapping: map sub_id → local user. Unmapped ⇒ ack + no-op.
//  10. action: revoke the mapped subject's sessions + refresh tokens.
func (r *Receiver) Receive(ctx context.Context, setBody string) (ReceiverResult, error) {
	// Steps 1-7: authenticate + validate the SET. A non-ok return carries the
	// oracle-safe rejected result (the failure code is baked in); ok==true
	// means the SET is FULLY VALIDATED and we ACK from here on.
	entry, c, rejected, ok := r.authenticateSET(ctx, setBody)
	if !ok {
		return rejected, nil
	}

	// ---- The SET is now FULLY VALIDATED. From here we ACK (202) even if
	// there is nothing to do; only unknown subjects/events remain, which
	// are no-ops, not errors. ----

	// (8) actionable events — keep only KNOWN URIs the transmitter is
	// allowed to trigger. An unknown / disallowed event is ignored.
	eventTypes := selectActionableEvents(c.Events, entry.allowedEvents)
	if len(eventTypes) == 0 {
		// Valid SET, but it carries no event this receiver acts on. Ack it.
		r.auditReceived(ctx, c.Iss, nil, "")
		if r.metric != nil {
			r.metric(ReceiverOutcomeNoop)
		}
		return ReceiverResult{Acked: true, Issuer: c.Iss}, nil
	}

	// Steps 9-10: resolve the subject + revoke. A resolver/revoke store error
	// returns (ReceiverResult{}, err) — NOT acked, NOT a reject — so the
	// handler maps it to a 500/retry; the validated intent is real.
	return r.actOnSubject(ctx, entry, &c, eventTypes)
}

// authenticateSET runs validation steps 1-7 against an inbound SET body. On
// success it returns the matched trusted entry + the verified claims with
// ok==true. On any failure it returns ok==false and a rejected ReceiverResult
// carrying the oracle-safe code: a splitCompactJWS miss is the ONLY
// ErrReceiverInvalidRequest; EVERY other validation failure collapses to the
// SAME coarse ErrReceiverInvalidKey so the wire reveals no detail. FAIL-CLOSED:
// an unavailable trust bundle, a jti store error, or a replayed jti all reject.
func (r *Receiver) authenticateSET(ctx context.Context, setBody string) (trustedEntry, inboundSETClaims, ReceiverResult, bool) {
	var zero inboundSETClaims
	// (1) Parse enough of the SET to learn its issuer, WITHOUT trusting it yet
	// (the signature is checked in step 3) — only to SELECT the trust bundle. A
	// malformed body is the one shape error distinct from a trust failure.
	header, payload, ok := splitCompactJWS(setBody)
	if !ok {
		return trustedEntry{}, zero, r.reject(ErrReceiverInvalidRequest), false
	}
	var pre struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &pre); err != nil || pre.Iss == "" {
		return trustedEntry{}, zero, r.reject(ErrReceiverInvalidKey), false // no iss ⇒ no bundle ⇒ untrusted
	}

	// (2) iss-allowlist — the trust gate, BEFORE any signature work. An
	// unavailable/empty bundle fails closed (must never accept).
	entry, trustedIss := r.trusted[pre.Iss]
	if !trustedIss {
		return trustedEntry{}, zero, r.reject(ErrReceiverInvalidKey), false
	}
	keys, err := entry.jwks.GetJWKS(ctx)
	if err != nil || len(keys) == 0 {
		return trustedEntry{}, zero, r.reject(ErrReceiverInvalidKey), false
	}

	// (3-5) signature (alg-allowlist BEFORE sig; no alg=none/symmetric) + typ +
	// iss-match + aud-binding against THIS transmitter's bundle.
	c, rejected, ok := r.verifyAndBindClaims(setBody, header, keys, entry, pre.Iss)
	if !ok {
		return trustedEntry{}, zero, rejected, false
	}

	if rejected, ok := r.checkTemporalAndReplay(ctx, &c); !ok {
		return trustedEntry{}, zero, rejected, false
	}
	return entry, c, ReceiverResult{}, true
}

// verifyAndBindClaims runs validation steps 3-5 on a SET already matched to a
// trusted bundle: signature + alg-allowlist via VerifyCompactJWS (the SAME
// alg-confusion-safe, kid-bound verifier the SPIFFE path uses — no alg=none, no
// symmetric), the secevent+jwt typ gate (so a plain access/id token signed by
// the same key can never be replayed as a SET), the defense-in-depth iss-match
// (the signed body's iss MUST equal the pre-parsed one the bundle was selected
// by), and STRICT aud-binding. Every failure collapses to ErrReceiverInvalidKey.
func (r *Receiver) verifyAndBindClaims(setBody string, header []byte, keys []core.JWK, entry trustedEntry, preIss string) (inboundSETClaims, ReceiverResult, bool) {
	var c inboundSETClaims
	verifiedPayload, err := security.VerifyCompactJWS(setBody, keys, entry.allowedAlgs)
	if err != nil {
		return c, r.reject(ErrReceiverInvalidKey), false
	}
	if !headerTypIsSET(header) {
		return c, r.reject(ErrReceiverInvalidKey), false
	}
	if err := json.Unmarshal(verifiedPayload, &c); err != nil {
		return c, r.reject(ErrReceiverInvalidKey), false
	}
	if c.Iss != preIss {
		return c, r.reject(ErrReceiverInvalidKey), false
	}
	if !c.Aud.Contains(r.audience) {
		return c, r.reject(ErrReceiverInvalidKey), false
	}
	return c, ReceiverResult{}, true
}

// checkTemporalAndReplay runs validation steps 6-7 on already-verified claims.
//
// (6) temporal freshness: a SET MUST carry at least one temporal claim (iat or
// exp). With NEITHER, both window checks are skipped (freshness bypass) AND,
// lacking exp, the jti replay key lives only DefaultJTIReplayWindow — so the
// same no-temporal SET replays INDEFINITELY past that window, re-revoking each
// time. So a no-freshness SET is rejected (fail-closed). When present, exp must
// not be already past and iat not too far in the future (bounded by the skew).
//
// (7) jti replay: a SET MUST carry a jti (RFC 8417 §2.2); a missing jti is
// rejected (accepting "" would let an attacker strip the claim to bypass the
// guard). The replay key is bounded by exp+skew when exp is present, else the
// default window from now. FAIL-CLOSED: a seen jti OR a store error rejects (an
// external-driven revocation primitive must not double-act, nor act on store
// uncertainty). The ack-even-on-no-op boundary in Receive sits AFTER MarkSeen.
// All failures collapse to the SAME coarse ErrReceiverInvalidKey.
func (r *Receiver) checkTemporalAndReplay(ctx context.Context, c *inboundSETClaims) (ReceiverResult, bool) {
	now := r.now()
	skew := r.maxClockSkew
	if c.Exp == 0 && c.Iat == 0 {
		return r.reject(ErrReceiverInvalidKey), false
	}
	if c.Exp != 0 && now.Add(-skew).After(time.Unix(c.Exp, 0)) {
		return r.reject(ErrReceiverInvalidKey), false
	}
	if c.Iat != 0 && now.Add(skew).Before(time.Unix(c.Iat, 0)) {
		return r.reject(ErrReceiverInvalidKey), false
	}
	if c.Jti == "" {
		return r.reject(ErrReceiverInvalidKey), false
	}
	replayExpiry := now.Add(security.DefaultJTIReplayWindow)
	if c.Exp != 0 {
		replayExpiry = time.Unix(c.Exp, 0).Add(skew)
	}
	first, mErr := r.jtiReplay.MarkSeen(ctx, jtiNamespaceKey(c.Iss, c.Jti), replayExpiry)
	if mErr != nil {
		if r.logger != nil {
			r.logger.Error("ssf: jti replay store error", "iss", c.Iss, "error", mErr.Error())
		}
		return r.reject(ErrReceiverInvalidKey), false
	}
	if !first {
		// Replayed SET — already actioned within its window; reject so it does
		// not double-act (indistinguishable from any other trust failure).
		return r.reject(ErrReceiverInvalidKey), false
	}
	return ReceiverResult{}, true
}

// selectActionableEvents (step 8) keeps only KNOWN event URIs the transmitter
// is allowed to trigger. An unknown / disallowed event is ignored. A nil
// allowedEvents means all known events are honored.
func selectActionableEvents(events map[string]json.RawMessage, allowedEvents map[string]struct{}) []string {
	var eventTypes []string
	for uri := range events {
		if !knownReceiverEvent(uri) {
			continue
		}
		if allowedEvents != nil {
			if _, ok := allowedEvents[uri]; !ok {
				continue
			}
		}
		eventTypes = append(eventTypes, uri)
	}
	return eventTypes
}

// actOnSubject runs validation steps 9-10 on a fully-validated SET carrying at
// least one actionable event.
//
// (9) subject mapping — the precision crux: resolve the SET subject to a LOCAL
// user id. An unmapped subject is a NO-OP (ack, no revocation) — never a
// guessed/partial match. A transient resolver error returns (ReceiverResult{},
// err) — NOT acked, NOT a reject — so it fails closed (no action) yet the
// handler maps it to a 500/retry rather than silently dropping a real
// revocation; the validated intent is real.
//
// (10) action — revoke ALL of the mapped subject's local access. Every
// actionable event (session-revoked / account-disabled / token-claims-change /
// token-revoked) is conservatively handled by the SAME full-subject revocation
// (sessions + refresh tokens) — the safe superset of each. A revoke store error
// is likewise surfaced as (ReceiverResult{}, err) for retry (not acked-as-done);
// the attempt is still audited.
func (r *Receiver) actOnSubject(ctx context.Context, entry trustedEntry, c *inboundSETClaims, eventTypes []string) (ReceiverResult, error) {
	sub := c.subjectID()
	localSub, mapped, rErr := r.resolver.ResolveLocalSubject(ctx, entry.subjectMode, entry.provider, sub)
	if rErr != nil {
		if r.logger != nil {
			r.logger.Error("ssf: subject resolve error", "iss", c.Iss, "error", rErr.Error())
		}
		return ReceiverResult{}, rErr
	}
	if !mapped {
		r.auditReceived(ctx, c.Iss, eventTypes, "")
		if r.metric != nil {
			r.metric(ReceiverOutcomeNoop)
		}
		return ReceiverResult{Acked: true, Issuer: c.Iss, EventTypes: eventTypes}, nil
	}

	res, revErr := r.revoker.RevokeAllForSubject(ctx, localSub)
	if revErr != nil {
		r.auditRevocation(ctx, c.Iss, eventTypes, localSub, res, false)
		if r.logger != nil {
			r.logger.Error("ssf: revocation failed after valid SET", "iss", c.Iss, "subject", localSub, "error", revErr.Error())
		}
		return ReceiverResult{}, revErr
	}

	r.auditRevocation(ctx, c.Iss, eventTypes, localSub, res, true)
	if r.metric != nil {
		r.metric(ReceiverOutcomeRevoked)
	}
	return ReceiverResult{
		Acked:        true,
		Acted:        true,
		Issuer:       c.Iss,
		EventTypes:   eventTypes,
		LocalSubject: localSub,
		Revocation:   res,
	}, nil
}

// reject builds a rejected result + bumps the rejected metric. Centralizing
// it keeps every validation-failure path emitting the SAME coarse code +
// metric (no oracle, consistent observability).
func (r *Receiver) reject(code string) ReceiverResult {
	if r.metric != nil {
		r.metric(ReceiverOutcomeRejected)
	}
	return ReceiverResult{Acked: false, RejectCode: code}
}

// auditReceived records the ssf_event_received event for a valid SET that
// did nothing actionable (unknown event or unmapped subject). SAFE fields
// only (iss + event types + local subject) — NEVER the raw SET.
func (r *Receiver) auditReceived(ctx context.Context, iss string, eventTypes []string, localSubject string) {
	if r.recorder == nil {
		return
	}
	e := &audit.Event{
		Type:    EventSSFEventReceived,
		Outcome: audit.OutcomeSuccess,
		ActorID: localSubject,
	}
	audit.SetMeta(e, metaSSFIssuer, iss)
	audit.SetMeta(e, metaSSFEvents, strings.Join(eventTypes, " "))
	r.recorder.Record(ctx, e)
}

// auditRevocation records the ssf_revocation event when a validated SET
// drove a local revocation (success or a failed attempt).
func (r *Receiver) auditRevocation(ctx context.Context, iss string, eventTypes []string, localSubject string, res RevocationResult, ok bool) {
	if r.recorder == nil {
		return
	}
	e := &audit.Event{
		Type:    EventSSFRevocation,
		Outcome: audit.OutcomeSuccess,
		ActorID: localSubject,
	}
	if !ok {
		e.Outcome = audit.OutcomeFailure
	}
	audit.SetMeta(e, metaSSFIssuer, iss)
	audit.SetMeta(e, metaSSFEvents, strings.Join(eventTypes, " "))
	r.recorder.Record(ctx, e)
}

// Audit metadata keys the receiver writes (via SetMeta, never raw SET).
const (
	metaSSFIssuer = "ssf_issuer"
	metaSSFEvents = "ssf_events"
)

// subjectID returns the SET's subject identifier, preferring sub_id and
// falling back to a top-level `sub` string (carried by transmitters that
// don't use the RFC 9493 sub_id object).
func (c *inboundSETClaims) subjectID() setSubjectID {
	if c.SubID != nil {
		return *c.SubID
	}
	if c.Sub != "" {
		return setSubjectID{Format: subjectFormatOpaque, ID: c.Sub}
	}
	return setSubjectID{}
}

// jtiNamespaceKey namespaces the replay key by issuer so two transmitters
// that happen to mint colliding jti values can't cause one's SET to
// suppress the other's (the jti uniqueness guarantee is per-issuer).
func jtiNamespaceKey(iss, jti string) string {
	return "ssf:" + iss + ":" + jti
}
