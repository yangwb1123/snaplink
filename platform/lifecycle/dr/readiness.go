package dr

import (
	"context"
	"fmt"
	"time"
)

// Status is the point-in-time DR readiness snapshot served by the admin
// status endpoint and mirrored (Ready/Reason only) into the Prometheus
// gauges. Every field is a plain value (no live references) so a caller can
// safely json.Marshal it after the call returns.
type Status struct {
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`

	// RPOTargetSeconds / RTOTargetSeconds are the configured targets this
	// verdict was measured against. 0 means the operator left the target
	// unset — Ready then reports true as soon as ANY replica exists (no RPO
	// commitment to violate).
	RPOTargetSeconds float64 `json:"rpo_target_seconds,omitempty"`
	RTOTargetSeconds float64 `json:"rto_target_seconds,omitempty"`

	// ReplicationLagSeconds is the age of the last verified replica at the
	// moment Status was computed. 0 with LastReplicationAt nil means no
	// replication has ever succeeded.
	ReplicationLagSeconds float64    `json:"replication_lag_seconds"`
	LastReplicationAt     *time.Time `json:"last_replication_at,omitempty"`
	LastReplicationError  string     `json:"last_replication_error,omitempty"`

	// RTOHistory is the tracker's bounded measured-RTO history, oldest
	// first. Empty until an operator times a recovery via
	// RecoveryTimeTracker.Start/Stop (e.g. a DR drill).
	RTOHistory []RecoveryRecord `json:"rto_history,omitempty"`

	// Retention is the DR target dir's current replica inventory, oldest
	// first. RetentionError is set instead when the target dir couldn't be
	// listed (e.g. unmounted) — a listing failure does NOT flip Ready by
	// itself; the age check above already covers staleness.
	Retention      []ReplicaFile `json:"retention,omitempty"`
	RetentionError string        `json:"retention_error,omitempty"`
}

// DRReadiness aggregates a SnapshotReplicator's live replication lag against
// an RPO target, plus a RecoveryTimeTracker's measured-RTO history, into the
// single readiness verdict the admin status endpoint and (opt-in) /readyz
// check both read.
//
// REPORT-ONLY per the package doc: Evaluate/ReadyCheck NEVER touch auth
// traffic. A stale or missing replica is an operator page, not a 503 for
// real users — wiring ReadyCheck into /readyz is an explicit operator
// choice (dr.gate_readiness) precisely because that opt-in DOES affect
// this replica's rotation status.
type DRReadiness struct {
	Replicator *SnapshotReplicator
	Tracker    *RecoveryTimeTracker

	// RPOTarget is the maximum acceptable replica staleness. <=0 disables
	// the age comparison (Ready is true whenever any replica exists).
	RPOTarget time.Duration
	// RTOTarget is carried through to Status for operator comparison
	// against RTOHistory; it does not affect the Ready verdict (RTO is only
	// known after a drill, so there is nothing live to gate on).
	RTOTarget time.Duration

	now func() time.Time
}

// NewDRReadiness wires a DRReadiness over an existing replicator + tracker.
// Either may be nil (a tracker-less readiness still reports replication
// lag; a replicator-less one reports "not configured").
func NewDRReadiness(replicator *SnapshotReplicator, tracker *RecoveryTimeTracker, rpoTarget, rtoTarget time.Duration) *DRReadiness {
	return &DRReadiness{
		Replicator: replicator, Tracker: tracker,
		RPOTarget: rpoTarget, RTOTarget: rtoTarget,
		now: time.Now,
	}
}

// Evaluate computes the live go/no-go verdict without paying for the
// tracker history or target-dir listing Status() also gathers — the shape
// ReadyCheck and the Prometheus collector both want on every call/scrape.
func (d *DRReadiness) Evaluate() (ready bool, lagSeconds float64, reason string) {
	if d == nil || d.Replicator == nil {
		return false, 0, "dr: replicator not configured"
	}
	lastSuccess, ok := d.Replicator.LastSuccess()
	if !ok {
		return false, 0, "dr: no successful replication yet"
	}
	lag := d.now().Sub(lastSuccess).Seconds()
	if d.RPOTarget > 0 && lag > d.RPOTarget.Seconds() {
		return false, lag, "dr: replication lag exceeds RPO target"
	}
	return true, lag, ""
}

// ReadyCheck adapts Evaluate to the func(context.Context) error shape every
// /readyz probe in this codebase expects. Deliberately a bare func (not a
// named type) so cmd can assign it directly to sso.ReadyCheck without this
// package importing interfaces/sso (would violate the layer gate: platform
// may not import interfaces).
func (d *DRReadiness) ReadyCheck(_ context.Context) error {
	ready, lag, reason := d.Evaluate()
	if !ready {
		return fmt.Errorf("%s (lag=%.0fs)", reason, lag)
	}
	return nil
}

// Status computes the full admin-status-endpoint payload: the Evaluate
// verdict plus the RTO history and retention inventory. ctx is accepted for
// call-site symmetry with other admin read endpoints; nothing here does I/O
// that needs cancellation (Inventory is a local directory listing).
func (d *DRReadiness) Status(_ context.Context) Status {
	ready, lag, reason := d.Evaluate()
	st := Status{Ready: ready, Reason: reason, ReplicationLagSeconds: lag}
	if d.RPOTarget > 0 {
		st.RPOTargetSeconds = d.RPOTarget.Seconds()
	}
	if d.RTOTarget > 0 {
		st.RTOTargetSeconds = d.RTOTarget.Seconds()
	}
	d.fillReplicatorStatus(&st)
	if d.Tracker != nil {
		st.RTOHistory = d.Tracker.History()
	}
	return st
}

// fillReplicatorStatus adds the replicator-derived fields (last success
// time/error, retention inventory) to st. Split out of Status to keep both
// under the function-length budget.
func (d *DRReadiness) fillReplicatorStatus(st *Status) {
	if d.Replicator == nil {
		return
	}
	if ts, ok := d.Replicator.LastSuccess(); ok {
		t := ts
		st.LastReplicationAt = &t
	}
	st.LastReplicationError = d.Replicator.LastError()
	inv, err := d.Replicator.Inventory()
	if err != nil {
		st.RetentionError = err.Error()
		return
	}
	st.Retention = inv
}
