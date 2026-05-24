package metrics

// Metric names emitted by the SSO server. All prefixed `sso_` so
// they don't collide with metrics an embedding app emits on the same
// registry. Treat as wire contract — renames are a major-version
// break.
const (
	NameHTTPRequestsTotal          = "sso_http_requests_total"
	NameHTTPRequestDuration        = "sso_http_request_duration_seconds"
	NameLoginAttemptsTotal         = "sso_login_attempts_total"
	NameTokensIssuedTotal          = "sso_tokens_issued_total"
	NameRiskDecisionsTotal         = "sso_risk_decisions_total"
	NameMFAChallengesTotal         = "sso_mfa_challenges_total"
	NameMFACompletionsTotal        = "sso_mfa_completions_total"
	NameRetentionPrunedTotal       = "sso_retention_pruned_total"
	NameRetentionPruneErrTotal     = "sso_retention_prune_errors_total"
	NameWebAuthnRegistrationsTotal = "sso_webauthn_registrations_total"
	NameWebAuthnAssertionsTotal    = "sso_webauthn_assertions_total"
	NameLoginDuration              = "sso_login_duration_seconds"
	NameMFACompletionDuration      = "sso_mfa_completion_duration_seconds"
	NameAnomaliesDetectedTotal     = "sso_anomalies_detected_total"
	NameAnomalyDispatchDropsTotal  = "sso_anomaly_dispatch_drops_total"
	NameAnomalyInspectErrorsTotal  = "sso_anomaly_inspect_errors_total"
	NameSigningKeyRotationsTotal   = "sso_signing_key_rotations_total"
)

// Label names used by the metric vectors. Bounded cardinality by
// design — see the doc on each collector for the rationale.
const (
	LabelMethod      = "method"
	LabelStatusClass = "status_class"
	LabelProvider    = "provider"
	LabelOutcome     = "outcome"
	LabelStrategy    = "strategy"
	LabelDecision    = "decision"
	LabelMFAMethod   = "mfa_method"
	LabelSubsystem   = "subsystem" // audit | snapshot | push_approvals
	LabelAnomalyType = "anomaly_type"
	LabelSeverity    = "severity"
	LabelDropReason  = "reason"
	LabelDetector    = "detector"
)

// Status class label values, bucketed into the four standard HTTP
// status families (no 1xx in practice from the SSO surface).
const (
	StatusClass1xx = "1xx"
	StatusClass2xx = "2xx"
	StatusClass3xx = "3xx"
	StatusClass4xx = "4xx"
	StatusClass5xx = "5xx"
)
