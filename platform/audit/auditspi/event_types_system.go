package auditspi

// Bootstrap framework events — one per Step run/skip on first boot
// (or whenever a new Step is added later).
const (
	EventBootstrapStepApplied EventType = "bootstrap_step_applied"
	EventBootstrapStepSkipped EventType = "bootstrap_step_skipped"
	EventBootstrapStepFailed  EventType = "bootstrap_step_failed"
)

// Bootstrap distributed-lock events — multi-replica coordination.
const (
	EventBootstrapLockAcquired  EventType = "bootstrap_lock_acquired"
	EventBootstrapLockReleased  EventType = "bootstrap_lock_released"
	EventBootstrapLockLost      EventType = "bootstrap_lock_lost"
	EventBootstrapLockContended EventType = "bootstrap_lock_contended"
)

// Snapshot lifecycle events — admin-plane export/restore/delete.
const (
	EventSnapshotExported EventType = "snapshot_exported"
	EventSnapshotRestored EventType = "snapshot_restored"
	EventSnapshotDeleted  EventType = "snapshot_deleted"
)

// Release lifecycle events — admin-app pin / rollback.
const (
	EventReleaseRegistered EventType = "release_registered"
	EventReleasePinned     EventType = "release_pinned"
	EventReleaseRolledBack EventType = "release_rolled_back"
	EventReleaseDeleted    EventType = "release_deleted"
)

// Signing-key rotation events.
const (
	EventSigningKeyRotated              EventType = "signing_key_rotated"
	EventSigningKeyAggregationDegraded  EventType = "signing_key_aggregation_degraded"
	EventSigningKeyAggregationRecovered EventType = "signing_key_aggregation_recovered"
	EventSigningKeyRotationCoordinated  EventType = "signing_key_rotation_coordinated"
	EventSigningKeyAdoptionErrorsTotal  EventType = "signing_key_adoption_errors"
)

// CAEP / OpenID Shared Signals events.
const (
	EventCAEPSetSent EventType = "caep_set_sent"
)

// SSF receiver events.
const (
	EventSSFSetReceived EventType = "ssf_set_received"
)

// Feature-gate (protocol-surface attack-surface reduction) events. Emitted
// once at server boot, only when at least one gate was explicitly disabled —
// a deployment that never touches feature_gates produces no new audit
// traffic here.
const (
	EventFeatureGatesDisabled EventType = "feature_gates_disabled"
)

// Idempotency capture-loss events. Fail-open degradation canary: emitted
// when a request carried an Idempotency-Key but reached commit without a
// capture wrapper installed (a regression that silently disabled replay
// protection before). The response is unchanged; the event makes the
// degradation observable. Metadata carries a sha-256 prefix of the key,
// never the raw key.
const (
	EventIdempotencyCaptureMissing EventType = "idempotency_capture_missing"
)

// Cluster invalidation bus events.
const (
	EventInvalidationBusDegraded    EventType = "invalidation_bus_degraded"
	EventInvalidationBusReconnected EventType = "invalidation_bus_reconnected"
)

// Zero-trust continuous-verification events. Emitted off the request path by the
// ContinuousVerificationAgent when a live session's decayed trust falls below the
// configured floor and it is marked for step-up.
const (
	EventSessionTrustStepUp EventType = "session_trust_stepup"
)

// Enterprise-connection runtime events. Emitted when a resolved B2B
// connection's upstream authenticator cannot be built from its stored Config —
// an operator-visible misconfiguration signal. The failure detail lands ONLY
// here (and in the server log): the login response collapses to the same
// unsupported_provider shape as an unknown provider (anti-enumeration).
const (
	EventConnectionAuthenticatorBuildFailed EventType = "connection_authenticator_build_failed"
)
