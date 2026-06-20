package main

import (
	"net/http"
	"time"

	gw "github.com/go-webauthn/webauthn/webauthn"

	"github.com/snaplink/sso/domains/authenticators/webauthn"
	"github.com/snaplink/sso/platform/audit"
)

func recordWebAuthnRegistered(deps *webauthnDeps, r *http.Request, cred *gw.Credential) {
	if deps == nil || deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventWebAuthnRegistered,
		Outcome:   audit.OutcomeSuccess,
		Provider:  "webauthn",
		ActorIP:   audit.ClientIP(r),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now().UTC(),
	}
	audit.SetMeta(e, "aaguid", webauthn.CredentialAAGUID(cred.Authenticator.AAGUID))
	deps.AuditRecorder.Record(r.Context(), e)
}

// recordWebAuthnAttestationDenied emits the failure audit event for an
// attestation-policy rejection, carrying the rejected AAGUID + the gating
// mode + the operator-side reason. Nil-safe when no recorder is wired.
func recordWebAuthnAttestationDenied(deps *webauthnDeps, r *http.Request, denied *webauthn.AttestationDeniedError) {
	if deps == nil || deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventWebAuthnAttestationDenied,
		Outcome:   audit.OutcomeFailure,
		Provider:  "webauthn",
		ActorIP:   audit.ClientIP(r),
		UserAgent: r.UserAgent(),
		Reason:    denied.Error(),
		Timestamp: time.Now().UTC(),
	}
	audit.SetMeta(e, "aaguid", denied.AAGUID)
	audit.SetMeta(e, "policy_mode", string(denied.Mode))
	// reason distinguishes an AAGUID-list miss from a none-attestation
	// downgrade (aaguid_not_permitted | attestation_format_none) so operators
	// can see WHY a registration was rejected — an internal audit field, never
	// the wire code (both stay the generic attestation_denied disposition).
	audit.SetMeta(e, "reason", denied.Reason)
	deps.AuditRecorder.Record(r.Context(), e)
}

// recordWebAuthnRegistration increments the registration counter
// for the given outcome. Nil-safe: when metrics are disabled
// (deps.Metrics nil), emit is silently skipped.
func recordWebAuthnRegistration(deps *webauthnDeps, outcome string) {
	if deps == nil || deps.Metrics == nil {
		return
	}
	deps.Metrics.WebAuthnRegistrationsTotal.WithLabelValues(outcome).Inc()
}

// recordWebAuthnAssertion mirrors recordWebAuthnRegistration for the
// login-finish path.
func recordWebAuthnAssertion(deps *webauthnDeps, outcome string) {
	if deps == nil || deps.Metrics == nil {
		return
	}
	deps.Metrics.WebAuthnAssertionsTotal.WithLabelValues(outcome).Inc()
}
