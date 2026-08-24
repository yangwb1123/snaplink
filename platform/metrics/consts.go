package metrics

// Metric names emitted by the SSO server. All prefixed `sso_` so
// they don't collide with metrics an embedding app emits on the same
// registry. Treat as wire contract — renames are a major-version
// break.
const (
	NameHTTPRequestsTotal               = "sso_http_requests_total"
	NameHTTPRequestDuration             = "sso_http_request_duration_seconds"
	NameLoginAttemptsTotal              = "sso_login_attempts_total"
	NameTokensIssuedTotal               = "sso_tokens_issued_total"
	NameRiskDecisionsTotal              = "sso_risk_decisions_total"
	NameConditionalAccessDecisionsTotal = "sso_conditional_access_decisions_total"
	NameAuthHookExecutionDuration       = "sso_auth_hook_execution_duration_seconds"
	NameNotificationDeliveryFailed      = "sso_notifications_delivery_failed_total"
	NameSessionTrustStepUpTotal         = "sso_zero_trust_session_stepup_total"
	NameMFAChallengesTotal              = "sso_mfa_challenges_total"
	NameMFACompletionsTotal             = "sso_mfa_completions_total"
	NameRetentionPrunedTotal            = "sso_retention_pruned_total"
	NameRetentionPruneErrTotal          = "sso_retention_prune_errors_total"
	NameWebAuthnRegistrationsTotal      = "sso_webauthn_registrations_total"
	NameWebAuthnAssertionsTotal         = "sso_webauthn_assertions_total"
	NameLoginDuration                   = "sso_login_duration_seconds"
	NameMFACompletionDuration           = "sso_mfa_completion_duration_seconds"
	NameAnomaliesDetectedTotal          = "sso_anomalies_detected_total"
	NameAnomalyDispatchDropsTotal       = "sso_anomaly_dispatch_drops_total"
	NameAnomalyDispatchedTotal          = "sso_anomaly_dispatch_received_total"
	NameAnomalyInspectErrorsTotal       = "sso_anomaly_inspect_errors_total"
	NameSigningKeyRotationsTotal        = "sso_signing_key_rotations_total"
	NameFAPIViolationsTotal             = "sso_fapi_violations_total"
	NameSigningOperationsTotal          = "sso_signing_operations_total"
	NameSigningDuration                 = "sso_signing_operation_duration_seconds"
	NameSigningBackendUp                = "sso_signing_backend_up"
	NameCredentialHealthSignals         = "sso_credential_health_signals_total"

	NameSigningKeyAdoptionErrorsTotal = "sso_signing_key_adoption_errors_total"
	NameSigningKeyAggregationUp       = "sso_signing_key_aggregation_up"
	NameSigningKeyCutoverTotal        = "sso_signing_key_cutover_total"

	NameInvalidationBusUp              = "sso_invalidation_bus_up"
	NameInvalidationBusReconnectsTotal = "sso_invalidation_bus_reconnects_total"

	NameNetPolicyClassifierUp              = "sso_netpolicy_classifier_up"
	NameNetPolicyClassifierReconnectsTotal = "sso_netpolicy_classifier_reconnects_total"

	NameCIBAPingTotal = "sso_ciba_ping_total"

	NameCORSBlockedTotal = "sso_cors_blocked_total"

	NameCAEPSetsTotal = "sso_caep_sets_total"

	NameSSFSetsReceivedTotal = "sso_ssf_sets_received_total"

	NameTokenRevocationsPropagatedTotal = "sso_token_revocations_propagated_total"

	NameClientStoreCacheTotal = "sso_client_store_cache_total"

	NameRefreshRotationVelocityExceededTotal = "sso_refresh_rotation_velocity_exceeded_total"

	NameLoginAttemptsByTenantTotal = "sso_login_attempts_by_tenant_total"
	NameTokensIssuedByTenantTotal  = "sso_tokens_issued_by_tenant_total"

	// Token-usage telemetry (opt-in via WithTokenUsageRecorder + WithMetrics).
	NameTokenUsageEventsTotal    = "sso_token_usage_events_total"
	NameTokenUsageDroppedTotal   = "sso_token_usage_dropped_total"
	NameTokenUsageTrackedBuckets = "sso_token_usage_tracked_buckets"

	// Token-policy engine (opt-in via WithTokenPolicy + WithMetrics).
	NameTokenPolicyEvaluationsTotal   = "sso_token_policy_evaluations_total"
	NameTokenPolicyDenialsTotal       = "sso_token_policy_denials_total"
	NameTokenPolicyRenewRequiredTotal = "sso_token_policy_renew_required_total"
	// NameTokenPolicyRoleResolutionErrorsTotal counts failed tenant-roster
	// lookups at the session seam (fail-open: roles stay empty and role
	// selectors stop matching). No labels — a per-tenant/user label would be
	// unbounded (§5); the logged error carries the identifiers.
	NameTokenPolicyRoleResolutionErrorsTotal = "sso_token_policy_role_resolution_errors_total"

	// Token-behavior anomaly detection (opt-in via WithTokenAnomalyDetector +
	// WithMetrics). Bounded labels: the closed finding-type set × severity.
	NameTokenAnomalyFindingsTotal = "sso_token_anomaly_findings_total"

	// Signup funnel metrics — self-service registration conversion
	// pipeline. Operators graph started → verified → completed to find
	// the drop-off step (verification email never arrived, link expired,
	// user abandoned, etc.).
	NameSignupStartedTotal          = "sso_signup_started_total"
	NameSignupVerifiedTotal         = "sso_signup_verified_total"
	NameSignupCompletedTotal        = "sso_signup_completed_total"
	NamePasswordResetRequestedTotal = "sso_password_reset_requested_total"
	NamePasswordResetCompletedTotal = "sso_password_reset_completed_total"

	// NameConnectionHealthProbesTotal counts admin-triggered B2B enterprise-
	// connection reachability probes. See platform/metrics.go's field doc.
	NameConnectionHealthProbesTotal = "sso_connection_health_probes_total"

	// NameFeatureGateEnabled is a startup snapshot: 1 while a protocol
	// surface's routes are mounted, 0 while an operator explicitly turned
	// it off via feature_gates. Set once at boot (gates are not runtime-
	// mutable), not a request-path counter.
	NameFeatureGateEnabled = "sso_feature_gate_enabled"

	NameConfigDriftDetectedTotal = "sso_config_drift_detected_total"

	// Disaster-recovery degraded-service posture. NameDegradationMode is a state
	// gauge (active mode == 1); NameDegradedRejectionsTotal counts gate refusals.
	NameDegradationMode         = "sso_degradation_mode"
	NameDegradedRejectionsTotal = "sso_degraded_rejections_total"

	// NameRateLimitHitsTotal counts requests the rate limiter rejected
	// (interfaces/ratelimit), by resolved tenant. Zero traffic when
	// WithRateLimit isn't wired.
	NameRateLimitHitsTotal = "sso_rate_limit_hits_total"

	// Signing-key hygiene: pruning stale peer-adopted verify-only keys
	// (PruneVerifyKeys), the resulting verify-set memory footprint, and
	// per-kid signing usage. See credential_rotation.go for the register +
	// observe helpers — kept there (near budget) rather than growing
	// metrics_ctor.go further.
	NameSigningKeyPrunedTotal   = "sso_signing_key_pruned_total"
	NameSigningVerifyKeySetSize = "sso_signing_verify_key_set_size"
	NameSigningUsageTotal       = "sso_signing_key_usage_total"

	// gRPC-plane per-RPC observability (wired by the server's gRPC
	// interceptors in interfaces/grpcserver; zero traffic when no gRPC
	// interceptor is wired). grpc_service is bounded to the registered
	// service set + "other" (registration closes before Serve), code_class
	// to the fixed ok|client|server table in docs/observability.md.
	NameGRPCRequestsTotal   = "sso_grpc_requests_total"
	NameGRPCRequestDuration = "sso_grpc_request_duration_seconds"
	NameAuthzChecksTotal    = "sso_authz_checks_total"
)

// Label names used by the metric vectors. Bounded cardinality by
// design — see the doc on each collector for the rationale.
const (
	LabelMethod          = "method"
	LabelStatusClass     = "status_class"
	LabelProvider        = "provider"
	LabelOutcome         = "outcome"
	LabelStrategy        = "strategy"
	LabelDecision        = "decision"
	LabelAction          = "action" // bounded: allow | deny | require_step_up (CAP verdicts)
	LabelMFAMethod       = "mfa_method"
	LabelSubsystem       = "subsystem" // audit | snapshot | push_approvals
	LabelAnomalyType     = "anomaly_type"
	LabelSeverity        = "severity"
	LabelDropReason      = "reason"
	LabelDetector        = "detector"
	LabelFAPIRule        = "rule"      // bounded: the 5 fapi:* baseline rule ids
	LabelFAPIMode        = "mode"      // inspection | enforce
	LabelAlg             = "alg"       // bounded: eddsa | es256 | rs256 | ps256
	LabelSignal          = "signal"    // bounded: weak | compromised
	LabelReason          = "reason"    // bounded per metric; see AdoptionReason* below
	LabelTenant          = "tenant"    // bounded by an operator allowlist + the "other" bucket
	LabelDirection       = "direction" // bounded: published | adopted
	LabelFeature         = "feature"   // bounded: the fixed FeatureGates surface names
	LabelKind            = "kind"      // bounded: access | refresh | id
	LabelEndpoint        = "endpoint"  // bounded: token | introspect | userinfo
	LabelDegradationMode = "mode"      // bounded: the 5 degraded-service modes
	LabelPreflight       = "preflight" // true|false

	// LabelKid is the signing-key kid dimension on sso_signing_key_usage_total.
	// Bounded by the issuing replica's own rotation policy — at most a
	// handful of kids are ever "active or recently demoted" per alg at once,
	// changing only on a RotateKey call, never on request input (§5).
	LabelKid = "kid"

	// LabelConnectionType is the B2B enterprise-connection protocol —
	// domains/connections.ConnectionType's wire values, bounded to oidc | saml.
	LabelConnectionType = "type"

	// gRPC-plane labels (sso_grpc_* vectors). grpc_service is the full
	// service name from the registered-service allowlist, or GRPCServiceOther;
	// code_class is the fixed ok|client|server table.
	LabelGRPCService   = "grpc_service"
	LabelGRPCCodeClass = "code_class"
)

// gRPC code-class label values, bounded to the three fixed classes (§5). The
// mapping table (which gRPC codes land in which class) is a const switch in
// interfaces/grpcserver/metrics.go and is reproduced verbatim in
// docs/observability.md — treat it as wire contract.
const (
	GRPCCodeClassOK     = "ok"
	GRPCCodeClassClient = "client"
	GRPCCodeClassServer = "server"
)

// GRPCServiceOther is the single fallback bucket every RPC method whose
// service is NOT in the registered-service allowlist collapses to (including
// a failed type assertion on the server handle), capping grpc_service label
// cardinality at registered service count + 1. Mirrors sanitizeMethod's
// "other" in the HTTP middleware.
const GRPCServiceOther = "other"

// TenantLabelUnknown is the sso_rate_limit_hits_total fallback bucket used
// when no tenant resolver is wired at all (single-tenant deployments, or a
// multi-tenant deployment that hasn't opted a resolver into rate-limit
// observability). Distinct from TenantLabelOther (a resolved-but-unlisted
// tenant): this means "tenant resolution never ran for this request".
const TenantLabelUnknown = "unknown"

// Token-policy evaluation outcomes (sso_token_policy_evaluations_total),
// bounded to two values (§5). The per-denial breakdown lives on
// sso_token_policy_denials_total's LabelReason (bounded to the closed
// tokenpolicy.DenyReason set) — never on client/subject labels.
const (
	PolicyDecisionAllow = "allow"
	PolicyDecisionDeny  = "deny"
)

// Cross-replica token-revocation propagation directions
// (sso_token_revocations_propagated_total), bounded to two values (§5):
//   - published: this replica PUBLISHED a KindTokenRevoked Event after a local
//     /token/revoke (the origin side).
//   - adopted: this replica ADDED a peer-published revoked token to its own
//     deny-set (the receiver side). No token/jti label (§5 bounded cardinality).
const (
	RevocationDirectionPublished = "published"
	RevocationDirectionAdopted   = "adopted"
)

// TenantLabelOther is the single fallback bucket every tenant NOT on the
// operator-supplied allowlist maps to, capping per-tenant metric
// cardinality at len(allowlist)+1. Mirrors how MFA labels are restricted to
// SupportedMethods() before they reach the registry (§5).
const TenantLabelOther = "other"

// CORS block reasons are a closed vocabulary so request input never becomes
// a Prometheus label value.
const CORSBlockReasonDisallowedOrigin = "disallowed_origin"

// Signing-key adoption-error reasons, bounded to the three failure modes the
// aggregation adoption path can hit for a peer JWK: it failed to decode
// (malformed/off-curve/weak material), it decoded but the issuer rejected
// AdoptVerifyKey (e.g. a local kid collision), or applying the registry event
// panicked (a bug in a pluggable, operator-supplied core.TokenIssuer — see
// applySigningKeyEventSafe). Bounded cardinality by design.
const (
	AdoptionReasonDecode = "decode"
	AdoptionReasonAdopt  = "adopt"
	AdoptionReasonPanic  = "panic"
)

// Coordinated signing-key cutover outcomes (sso_signing_key_cutover_total),
// bounded to the four actions a replica can take on a received cross-replica
// KindSigningKeyRotation Event. No kid/replica label (§5 bounded cardinality):
//   - deferred: a retire timer was armed for the demoted kid at the carried
//     deadline (the common path — the verify window was widened).
//   - extended: a later deadline REPLACED an earlier pending one for the same
//     kid (still only ever pushing the retire LATER — fail-safe).
//   - adopted_only: the demoted kid was already gone / never local, so only the
//     new-kid verify-only adoption applied (no retire to defer).
//   - noop: a garbage/empty/already-superseded Event that changed nothing — the
//     pure fail-safe path (the local grace-window fallback governs).
const (
	CutoverOutcomeDeferred    = "deferred"
	CutoverOutcomeExtended    = "extended"
	CutoverOutcomeAdoptedOnly = "adopted_only"
	CutoverOutcomeNoop        = "noop"
)

// Invalidation-bus reconnect outcomes (sso_invalidation_bus_reconnects_total),
// bounded to the two transitions the self-healing subscriber loop can record on
// the `reason` label (§5 bounded cardinality; no per-event/per-kind label):
//   - degraded: the bus Subscribe channel closed while the run context was still
//     live (watch death / leader change / network blip) and the loop flipped
//     into the degraded state — this replica STOPPED applying cross-replica
//     invalidations until it resubscribes.
//   - reconnected: a degraded loop successfully resubscribed and resumed
//     applying invalidations.
const (
	InvalidationBusReasonDegraded    = "degraded"
	InvalidationBusReasonReconnected = "reconnected"
)

// Network-policy classifier reconnect outcomes
// (sso_netpolicy_classifier_reconnects_total), bounded to the two transitions
// the self-healing Watch loop can record on the `reason` label (§5 bounded
// cardinality; no per-policy label):
//   - degraded: the Store.Watch channel closed while the run context was still
//     live (etcd watch compaction / leader change / network blip) and the loop
//     flipped degraded — this replica STOPPED applying policy updates and is
//     serving a frozen snapshot until it resubscribes.
//   - reconnected: a degraded loop successfully resubscribed, re-listed (so it
//     catches any change missed during the gap), and resumed applying updates.
const (
	NetPolicyClassifierReasonDegraded    = "degraded"
	NetPolicyClassifierReasonReconnected = "reconnected"
)

// Credential-health signal label values, bounded to two.
const (
	SignalWeak        = "weak"
	SignalCompromised = "compromised"
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
