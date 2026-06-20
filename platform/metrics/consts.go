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
	NameAnomalyDispatchedTotal     = "sso_anomaly_dispatch_received_total"
	NameAnomalyInspectErrorsTotal  = "sso_anomaly_inspect_errors_total"
	NameSigningKeyRotationsTotal   = "sso_signing_key_rotations_total"
	NameFAPIViolationsTotal        = "sso_fapi_violations_total"
	NameSigningOperationsTotal     = "sso_signing_operations_total"
	NameSigningDuration            = "sso_signing_operation_duration_seconds"
	NameSigningBackendUp           = "sso_signing_backend_up"
	NameCredentialHealthSignals    = "sso_credential_health_signals_total"

	NameSigningKeyAdoptionErrorsTotal = "sso_signing_key_adoption_errors_total"
	NameSigningKeyAggregationUp       = "sso_signing_key_aggregation_up"
	NameSigningKeyCutoverTotal        = "sso_signing_key_cutover_total"

	NameInvalidationBusUp              = "sso_invalidation_bus_up"
	NameInvalidationBusReconnectsTotal = "sso_invalidation_bus_reconnects_total"

	NameNetPolicyClassifierUp              = "sso_netpolicy_classifier_up"
	NameNetPolicyClassifierReconnectsTotal = "sso_netpolicy_classifier_reconnects_total"

	NameCIBAPingTotal = "sso_ciba_ping_total"

	NameCAEPSetsTotal = "sso_caep_sets_total"

	NameSSFSetsReceivedTotal = "sso_ssf_sets_received_total"

	NameTokenRevocationsPropagatedTotal = "sso_token_revocations_propagated_total"

	NameClientStoreCacheTotal = "sso_client_store_cache_total"

	NameRefreshRotationVelocityExceededTotal = "sso_refresh_rotation_velocity_exceeded_total"

	NameLoginAttemptsByTenantTotal = "sso_login_attempts_by_tenant_total"
	NameTokensIssuedByTenantTotal  = "sso_tokens_issued_by_tenant_total"
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
	LabelFAPIRule    = "rule"      // bounded: the 5 fapi:* baseline rule ids
	LabelFAPIMode    = "mode"      // inspection | enforce
	LabelAlg         = "alg"       // bounded: eddsa | es256 | rs256 | ps256
	LabelSignal      = "signal"    // bounded: weak | compromised
	LabelReason      = "reason"    // bounded per metric; see AdoptionReason* below
	LabelTenant      = "tenant"    // bounded by an operator allowlist + the "other" bucket
	LabelDirection   = "direction" // bounded: published | adopted
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

// Signing-key adoption-error reasons, bounded to the two failure modes the
// aggregation adoption path can hit for a peer JWK: it failed to decode
// (malformed/off-curve/weak material) or it decoded but the issuer rejected
// AdoptVerifyKey (e.g. a local kid collision). Bounded cardinality by design.
const (
	AdoptionReasonDecode = "decode"
	AdoptionReasonAdopt  = "adopt"
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
