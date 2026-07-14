// Package threataction implements the Active ITDR detection-to-response
// bridge — a Threat Executor SPI + Policy Engine that translates anomaly
// detection signals into security actions (session suspension, refresh
// token family revocation, MFA step-up challenge, admin notification)
// without changing the request hot path.
//
// # Architecture
//
// The existing anomaly subsystem (domains/anomaly.Runner +
// domains/tokenanomaly.Detector) produces signals that go to audit +
// webhook — they "smoke alarm" but never "call the fire department".
// This package adds an off-request-path response executor that translates
// detection findings into policy actions.
//
// Execution contract: FAIL-OPEN. A threat-executor error (store
// unavailable, action backend timeout) MUST NOT escalate — it is logged,
// metric'd, and the next threat proceeds. A single broken executor
// (e.g., SMTP server down) must not block session-revocation executors
// from acting on the SAME threat.
//
// Thread safety: every type in this package is safe for concurrent use.
// The ThreatExecutors composite holds its own internal lock for rate-
// limiter state; ThreatPolicyStore implementations are responsible for
// their own concurrency safety.
package threataction

import (
	"time"
)

// Threat is one actionable signal — produced by either anomaly.Detector
// or tokenanomaly.Detector and consumed by a ThreatExecutor. It carries
// everything the executor needs to decide AND act.
type Threat struct {
	// Type matches anomaly.Signal.Type or tokenanomaly.Finding.Type.
	Type string // "impossible_travel", "velocity_burst", "rate_spike", etc.

	// Severity mirrors anomaly.Signal.Severity.
	Severity string // "info", "warn", "critical"

	// SubjectID is the affected user.
	SubjectID string

	// ClientID is the OAuth client, when scoped to one client.
	ClientID string

	// FamilyID is the refresh token family, when the threat is token-scoped.
	FamilyID string

	// TenantID scopes the action to a tenant.
	TenantID string

	// Evidence is structured detail from the detector. Used by policy
	// evaluation for conditional matching (e.g. "only suspend when
	// evidence.distance_km > 5000").
	Evidence map[string]string

	// TraceID for log correlation.
	TraceID string
}

// Action is one response action to execute. Multiple actions can result
// from one Threat (suspend session AND notify admin).
type Action string

const (
	// ActionNoop is the default (no action) — log + metric only,
	// matching current behavior.
	ActionNoop Action = "noop"

	// ActionSuspend suspends the user's active session(s).
	ActionSuspend Action = "suspend"

	// ActionRevoke revokes the refresh token family.
	ActionRevoke Action = "revoke"

	// ActionStepUpMFA tags the session for MFA on the next login.
	ActionStepUpMFA Action = "step_up_mfa"

	// ActionNotify sends an admin notification (email/webhook).
	ActionNotify Action = "notify"

	// ActionChallenge requires additional verification on the next auth.
	ActionChallenge Action = "challenge"
)

// ActionResult reports what was done for one action.
type ActionResult struct {
	Action Action
	OK     bool
	Detail string // human-readable: "session s_abc123 suspended"
}

// Severity levels matching anomaly.Severity and tokenanomaly.Severity.
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
)

// Threat type identifiers. Drawn from the anomaly and tokenanomaly
// packages so the policy engine can match on them without importing
// those packages.
const (
	ThreatImpossibleTravel = "impossible_travel"
	ThreatVelocityBurst    = "velocity_burst"
	ThreatNewCountry       = "new_country"
	ThreatRateSpike        = "rate_spike"
	ThreatMultiGeo         = "multi_geo"
	ThreatVelocity         = "velocity"
	ThreatBruteForce       = "brute_force_spray"
	ThreatNewDevice        = "new_device"
)

// Meta keys carried on audit events emitted by the executor.
const (
	MetaKeyThreatType    = "threat.type"
	MetaKeyThreatAction  = "threat.action"
	MetaKeyThreatSubject = "threat.subject"
	MetaKeyThreatDetail  = "threat.detail"

	// EventThreatActionExecuted is the audit event type emitted for every
	// non-Noop action the executor takes.
	EventThreatActionExecuted = "threat_action_executed"
)

// rateLimitEntry tracks one rate-limit bucketed key.
type rateLimitEntry struct {
	count     int
	windowEnd time.Time
}

// RateLimitKey builds the rate-limit key for a (subject, type, action) tuple.
func RateLimitKey(subjectID, threatType string, action Action) string {
	return subjectID + "\x00" + threatType + "\x00" + string(action)
}
