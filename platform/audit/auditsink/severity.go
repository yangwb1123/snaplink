package auditsink

import "github.com/snaplink/sso/platform/audit/auditspi"

// severityLevel is the SDK's ONE internal severity scale, derived from
// Outcome plus a small per-EventType override table. Every wire format
// (CEF 0-10, OCSF severity_id 1-6, syslog 0-7) projects this single scale
// into its own range instead of maintaining three independent judgment
// calls — an event escalated here is escalated identically everywhere it is
// exported, and a future formatter (roadmap item 19: Kafka/NATS) inherits
// the same classification for free.
type severityLevel int

const (
	severityInfo severityLevel = iota
	severityLow
	severityMedium
	severityHigh
	severityCritical
)

// severityOverrides pins specific event types above (or below) the
// outcome-derived default — an account lockout or a detected anomaly is
// meaningfully more severe than an ordinary login failure, and a routine
// read-only admin query is less severe than a mutation. Types absent from
// this table fall back to outcomeSeverity(e.Outcome) in eventSeverity.
var severityOverrides = map[auditspi.EventType]severityLevel{
	// credential/session compromise signals — the highest tier, since these
	// indicate an attacker in possession of live credentials/material.
	auditspi.EventRefreshTokenReuse:       severityCritical,
	auditspi.EventPasswordCompromised:     severityCritical,
	auditspi.EventFAPIComplianceViolation: severityCritical,

	// active lockout / denial / anomaly signals.
	auditspi.EventAccountLocked:                   severityHigh,
	auditspi.EventAnomalyDetected:                 severityHigh,
	auditspi.EventWebAuthnAttestationDenied:       severityHigh,
	auditspi.EventRefreshRotationVelocityExceeded: severityHigh,
	auditspi.EventSigningKeyAggregationDegraded:   severityHigh,
	auditspi.EventBootstrapLockLost:               severityHigh,
	auditspi.EventPartialRevokeFailure:            severityHigh,
	auditspi.EventSigningKeyAdoptionErrorsTotal:   severityHigh,

	// bulk-revocation / mass-deletion admin actions — medium: intentional
	// and usually authorized, but high-blast-radius and worth flagging.
	auditspi.EventTenantTokensRevoked:       severityMedium,
	auditspi.EventTenantSessionsRevoked:     severityMedium,
	auditspi.EventAdminTokenRevoked:         severityMedium,
	auditspi.EventAdminUserDeleted:          severityMedium,
	auditspi.EventAdminClientDeleted:        severityMedium,
	auditspi.EventAdminTenantDeleted:        severityMedium,
	auditspi.EventAdminSubjectErased:        severityMedium,
	auditspi.EventSubjectSelfErased:         severityMedium,
	auditspi.EventAdminDeviceSecretsRevoked: severityMedium,
	auditspi.EventInvalidationBusDegraded:   severityMedium,
	auditspi.EventPasswordWeak:              severityLow,

	// routine read-only queries — informational regardless of volume.
	auditspi.EventClientAccess:    severityInfo,
	auditspi.EventPermissionQuery: severityInfo,
}

// eventSeverity classifies e: an explicit override wins; otherwise a
// failed/denied outcome is Medium and a successful one is Info. This mirrors
// the two-input design called out in the SIEM formats grounding doc —
// Outcome alone is too coarse (a failed permission_query isn't a security
// event) but a full per-type severity table would duplicate the override
// map's job for the common case.
func eventSeverity(e *auditspi.Event) severityLevel {
	if lvl, ok := severityOverrides[e.Type]; ok {
		return lvl
	}
	if e.Outcome == auditspi.OutcomeFailure {
		return severityMedium
	}
	return severityInfo
}

// toCEFSeverity projects the internal scale onto CEF's 0-10 range (per the
// CEF spec: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High).
func toCEFSeverity(lvl severityLevel) int {
	switch lvl {
	case severityCritical:
		return 10
	case severityHigh:
		return 8
	case severityMedium:
		return 5
	case severityLow:
		return 3
	default:
		return 1
	}
}

// toOCSFSeverityID projects onto OCSF's severity_id enum (1=Informational,
// 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal). This SDK never assigns 6 —
// Fatal implies an unrecoverable process-level event, which is outside the
// scope of an application audit trail.
func toOCSFSeverityID(lvl severityLevel) int {
	switch lvl {
	case severityCritical:
		return 5
	case severityHigh:
		return 4
	case severityMedium:
		return 3
	case severityLow:
		return 2
	default:
		return 1
	}
}

// toSyslogSeverity projects onto RFC 5424's 0-7 severity (lower = MORE
// severe: 0 Emergency .. 7 Debug). This SDK never emits 0/1 (Emergency/Alert
// imply operator paging on a single log line — no audit event on its own
// warrants that) or 7 (Debug — audit events are never debug-level noise).
func toSyslogSeverity(lvl severityLevel) int {
	switch lvl {
	case severityCritical:
		return 2
	case severityHigh:
		return 3
	case severityMedium:
		return 4
	case severityLow:
		return 5
	default:
		return 6
	}
}
