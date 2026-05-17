package metrics

// Metric names emitted by the SSO server. All prefixed `sso_` so
// they don't collide with metrics an embedding app emits on the same
// registry. Treat as wire contract — renames are a major-version
// break.
const (
	NameHTTPRequestsTotal   = "sso_http_requests_total"
	NameHTTPRequestDuration = "sso_http_request_duration_seconds"
	NameLoginAttemptsTotal  = "sso_login_attempts_total"
	NameTokensIssuedTotal   = "sso_tokens_issued_total"
	NameRiskDecisionsTotal  = "sso_risk_decisions_total"
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
