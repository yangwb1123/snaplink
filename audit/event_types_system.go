package audit

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
	EventSigningKeyRotated                  EventType = "signing_key_rotated"
	EventSigningKeyAggregationDegraded      EventType = "signing_key_aggregation_degraded"
	EventSigningKeyAggregationRecovered     EventType = "signing_key_aggregation_recovered"
	EventSigningKeyRotationCoordinated      EventType = "signing_key_rotation_coordinated"
	EventSigningKeyAdoptionErrorsTotal      EventType = "signing_key_adoption_errors"
)

// CAEP / OpenID Shared Signals events.
const (
	EventCAEPSetSent EventType = "caep_set_sent"
)

// SSF receiver events.
const (
	EventSSFSetReceived EventType = "ssf_set_received"
)

// Cluster invalidation bus events.
const (
	EventInvalidationBusDegraded   EventType = "invalidation_bus_degraded"
	EventInvalidationBusReconnected EventType = "invalidation_bus_reconnected"
)
