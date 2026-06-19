package caep

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/security"
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
	// (1) Parse enough of the SET to learn its issuer, WITHOUT trusting any
	// of it yet (the signature is checked in step 3). VerifyCompactJWS also
	// reparses the header internally for the alg/kid gate; we read the
	// payload `iss` here only to SELECT which trust bundle to verify
	// against. A malformed body is the one shape error distinct from a
	// trust failure.
	header, payload, ok := splitCompactJWS(setBody)
	if !ok {
		return r.reject(ErrReceiverInvalidRequest), nil
	}
	var pre struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &pre); err != nil || pre.Iss == "" {
		// No issuer ⇒ cannot select a trust bundle ⇒ untrusted.
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (2) iss-allowlist — the trust gate. An issuer not in the configured
	// set is rejected BEFORE any signature work: only configured,
	// authenticated transmitters may ever trigger a revocation.
	entry, trustedIss := r.trusted[pre.Iss]
	if !trustedIss {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	keys, err := entry.jwks.GetJWKS(ctx)
	if err != nil || len(keys) == 0 {
		// The trust bundle is unavailable — treat as not-authenticatable
		// (fail-closed). A misconfigured/empty bundle must never accept.
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (3) signature + alg-allowlist (no alg=none, no symmetric) against
	// THIS transmitter's bundle. Reuses the SAME verifier the SPIFFE path
	// uses — alg-confusion-safe, kid-bound, on-curve EC checks.
	verifiedPayload, err := security.VerifyCompactJWS(setBody, keys, entry.allowedAlgs)
	if err != nil {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (4) typ gate: the JOSE header MUST declare secevent+jwt, so a plain
	// access/id token signed by the same upstream key can never be replayed
	// here as a SET (the inverse of the issuers' at+jwt typ gate).
	if !headerTypIsSET(header) {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	var c inboundSETClaims
	if err := json.Unmarshal(verifiedPayload, &c); err != nil {
		return r.reject(ErrReceiverInvalidKey), nil
	}
	// Defense-in-depth: the verified payload's iss MUST still equal the one
	// we selected the bundle by (a mismatch would mean the unverified
	// pre-parse disagreed with the signed body — reject).
	if c.Iss != pre.Iss {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (5) STRICT aud-binding — refuse a SET not addressed to THIS receiver.
	if !c.Aud.Contains(r.audience) {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (6) temporal freshness. A SET MUST carry at least one temporal claim
	// (iat or exp). With NEITHER, both window checks below would be skipped,
	// so the SET bypasses freshness entirely; worse, with no exp the jti
	// replay key lives only DefaultJTIReplayWindow (below), so the same
	// no-temporal SET replays INDEFINITELY past that window, re-triggering a
	// revocation each time. A push-delivery SET with no freshness claim is
	// non-conformant for replay-safety → reject (fail-closed). When present,
	// we bound exp (not already past) and iat (not too far in the future) by
	// the skew; the jti-replay key (below) is bounded by exp+skew when exp is
	// present, else the default window from now (and since a fresh iat ≈ now,
	// that is effectively iat+window for the iat-only case — never unbounded,
	// because a no-temporal SET is rejected above).
	now := r.now()
	skew := r.maxClockSkew
	if c.Exp == 0 && c.Iat == 0 {
		return r.reject(ErrReceiverInvalidKey), nil
	}
	if c.Exp != 0 && now.Add(-skew).After(time.Unix(c.Exp, 0)) {
		return r.reject(ErrReceiverInvalidKey), nil
	}
	if c.Iat != 0 && now.Add(skew).Before(time.Unix(c.Iat, 0)) {
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// (7) jti replay — consume the jti so a replayed SET cannot re-trigger.
	// A SET MUST carry a jti (RFC 8417 §2.2); a missing jti is rejected
	// rather than silently accepted (accepting "" would let an attacker
	// strip the claim to bypass the replay guard). Fail-closed: a seen jti,
	// OR a store error, rejects (an external-driven revocation primitive
	// must not double-act, and must not act on store uncertainty).
	if c.Jti == "" {
		return r.reject(ErrReceiverInvalidKey), nil
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
		return r.reject(ErrReceiverInvalidKey), nil
	}
	if !first {
		// Replayed SET — already actioned within its window. Reject so it
		// does not double-act, but the rejection is indistinguishable from
		// any other trust failure on the wire.
		return r.reject(ErrReceiverInvalidKey), nil
	}

	// ---- The SET is now FULLY VALIDATED. From here we ACK (202) even if
	// there is nothing to do; only unknown subjects/events remain, which
	// are no-ops, not errors. ----

	// (8) actionable events — keep only KNOWN URIs the transmitter is
	// allowed to trigger. An unknown / disallowed event is ignored.
	var eventTypes []string
	for uri := range c.Events {
		if !knownReceiverEvent(uri) {
			continue
		}
		if entry.allowedEvents != nil {
			if _, ok := entry.allowedEvents[uri]; !ok {
				continue
			}
		}
		eventTypes = append(eventTypes, uri)
	}
	if len(eventTypes) == 0 {
		// Valid SET, but it carries no event this receiver acts on. Ack it.
		r.auditReceived(ctx, c.Iss, nil, "")
		if r.metric != nil {
			r.metric(ReceiverOutcomeNoop)
		}
		return ReceiverResult{Acked: true, Issuer: c.Iss}, nil
	}

	// (9) subject mapping — the precision crux. Resolve the SET subject to a
	// LOCAL user id. A subject with no known local mapping is a NO-OP (ack,
	// no revocation) — never a guessed/partial match.
	sub := c.subjectID()
	localSub, mapped, rErr := r.resolver.ResolveLocalSubject(ctx, entry.subjectMode, entry.provider, sub)
	if rErr != nil {
		// A transient resolver failure: fail-closed (no action) and do NOT
		// ack, so the transmitter may retry rather than silently dropping a
		// real revocation. Surfaced as an internal error → 500.
		if r.logger != nil {
			r.logger.Error("ssf: subject resolve error", "iss", c.Iss, "error", rErr.Error())
		}
		return ReceiverResult{}, rErr
	}
	if !mapped {
		// Unmapped subject ⇒ no wrongful revocation. Ack + no-op.
		r.auditReceived(ctx, c.Iss, eventTypes, "")
		if r.metric != nil {
			r.metric(ReceiverOutcomeNoop)
		}
		return ReceiverResult{Acked: true, Issuer: c.Iss, EventTypes: eventTypes}, nil
	}

	// (10) action — revoke ALL of the mapped subject's local access. Every
	// actionable event here (session-revoked / account-disabled /
	// token-claims-change / token-revoked) is conservatively handled by the
	// SAME full-subject revocation: killing the subject's sessions + refresh
	// tokens is the safe superset of each. Token-claims-change is the
	// weakest signal but still revokes (the previously-trusted tokens should
	// no longer be honored).
	res, revErr := r.revoker.RevokeAllForSubject(ctx, localSub)
	if revErr != nil {
		// The SET was valid + mapped; the revoke is the safe direction, so a
		// store error here is surfaced (the transmitter retries) rather than
		// acked-as-done. We still audit the attempt.
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
