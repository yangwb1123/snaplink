package dr

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Recovery step names, in execution order. Stable strings: they appear in the
// RecoveryReport JSON the admin DR status endpoint surfaces (as last_drill),
// so treat them as part of that report-card contract.
const (
	StepVerifyIntegrity = "verify_integrity"
	StepPromoteReplica  = "promote_replica"
	StepRestoreState    = "restore_state"
	StepReadinessProbe  = "readiness_probe"
)

// Step outcome labels recorded in StepResult.Outcome.
const (
	StepSuccess = "success"
	StepFailure = "failure"
	StepSkipped = "skipped"
)

// OperationRecovery labels the RecoveryTimeTracker measurement an orchestrated
// recovery records, so a drill's total duration lands in the SAME measured-RTO
// history a manual restore does (surfaced on the admin status endpoint and the
// sso_dr_last_recovery_seconds gauge).
const OperationRecovery = "dr_recovery"

// errStepSkipped is the sentinel a step returns to signal "seam not wired,
// skip me" — distinct from a real failure so the sequence keeps going.
var errStepSkipped = errors.New("dr: step skipped (seam not configured)")

// StepResult is one recovery step's typed outcome + timing.
type StepResult struct {
	Name            string  `json:"name"`
	Outcome         string  `json:"outcome"`
	DurationSeconds float64 `json:"duration_seconds"`
	Detail          string  `json:"detail,omitempty"`
	Error           string  `json:"error,omitempty"`
}

// RecoveryReport is the DR "report card": the ordered per-step outcomes of one
// RecoveryOrchestrator.Run plus the measured RTO against the configured target.
// Every field is a plain value so a caller can json.Marshal it after Run
// returns (it is what GET /api/v1/admin/dr/status embeds as last_drill).
type RecoveryReport struct {
	StartedAt          time.Time    `json:"started_at"`
	Succeeded          bool         `json:"succeeded"`
	ReplicaName        string       `json:"replica_name,omitempty"`
	AbortedAtStep      string       `json:"aborted_at_step,omitempty"`
	Steps              []StepResult `json:"steps"`
	MeasuredRTOSeconds float64      `json:"measured_rto_seconds"`
	RTOTargetSeconds   float64      `json:"rto_target_seconds,omitempty"`
	RTOWithinTarget    bool         `json:"rto_within_target"`
}

// OrchestratorConfig wires a RecoveryOrchestrator. Replicator + Verifier are
// required (the safety gate); the rest are optional so a drill can exercise
// the sequence with the no-op Memory* seams.
type OrchestratorConfig struct {
	Replicator *SnapshotReplicator
	Verifier   ReplicaIntegrityVerifier
	Promoter   ReplicaPromoter
	Restorer   StateRestorer
	Readiness  *DRReadiness
	Tracker    *RecoveryTimeTracker
	RTOTarget  time.Duration
}

// RecoveryOrchestrator runs the stepwise DR recovery sequence documented in
// docs/dr-framework.md §6: (1) verify the latest replica's integrity, (2)
// promote the replica, (3) restore control-plane state, (4) run the readiness
// probe — timing the whole thing as a measured RTO. A failed step ABORTS the
// sequence: later steps are marked skipped and the report records where it
// stopped, because failing over onto unverified or broken data is worse than
// not failing over at all.
//
// REPORT-ONLY like the rest of this package: Run mutates only the wired seams
// (a real promoter/restorer, or the no-op Memory* ones in a drill) and this
// orchestrator's own last-report field. It never touches live auth traffic.
type RecoveryOrchestrator struct {
	replicator *SnapshotReplicator
	verifier   ReplicaIntegrityVerifier
	promoter   ReplicaPromoter
	restorer   StateRestorer
	readiness  *DRReadiness
	tracker    *RecoveryTimeTracker
	rtoTarget  time.Duration

	now func() time.Time

	mu         sync.Mutex
	lastReport *RecoveryReport
}

// NewRecoveryOrchestrator validates the required seams and returns a ready
// orchestrator.
func NewRecoveryOrchestrator(cfg OrchestratorConfig) (*RecoveryOrchestrator, error) {
	if cfg.Replicator == nil {
		return nil, errors.New("dr: orchestrator requires a replicator")
	}
	if cfg.Verifier == nil {
		return nil, errors.New("dr: orchestrator requires an integrity verifier")
	}
	return &RecoveryOrchestrator{
		replicator: cfg.Replicator,
		verifier:   cfg.Verifier,
		promoter:   cfg.Promoter,
		restorer:   cfg.Restorer,
		readiness:  cfg.Readiness,
		tracker:    cfg.Tracker,
		rtoTarget:  cfg.RTOTarget,
		now:        time.Now,
	}, nil
}

// runState threads the fetched replica between steps.
type runState struct {
	replicaName string
	replicaData []byte
}

type namedStep struct {
	name string
	fn   func(context.Context, *runState) (detail string, err error)
}

// Run executes the recovery sequence and returns the report (never nil). The
// report is also retained as LastReport for the admin status endpoint + the
// last-drill metric.
func (o *RecoveryOrchestrator) Run(ctx context.Context) *RecoveryReport {
	start := o.clock()
	var timer *RecoveryTimer
	if o.tracker != nil {
		timer = o.tracker.Start(OperationRecovery)
	}
	rep := &RecoveryReport{StartedAt: start.UTC()}
	st := &runState{}
	o.execSteps(ctx, rep, st)
	rep.ReplicaName = st.replicaName
	o.finalize(rep, timer, start)
	return rep
}

// execSteps runs each planned step in order, stopping at the first failure;
// remaining steps are recorded as skipped so the report shows the full plan.
func (o *RecoveryOrchestrator) execSteps(ctx context.Context, rep *RecoveryReport, st *runState) {
	aborted := false
	for _, s := range o.plan() {
		if aborted {
			rep.Steps = append(rep.Steps, StepResult{Name: s.name, Outcome: StepSkipped})
			continue
		}
		res := o.runStep(ctx, s, st)
		rep.Steps = append(rep.Steps, res)
		if res.Outcome == StepFailure {
			aborted = true
			rep.AbortedAtStep = s.name
		}
	}
	rep.Succeeded = !aborted
}

func (o *RecoveryOrchestrator) plan() []namedStep {
	return []namedStep{
		{StepVerifyIntegrity, o.stepVerifyIntegrity},
		{StepPromoteReplica, o.stepPromote},
		{StepRestoreState, o.stepRestore},
		{StepReadinessProbe, o.stepReadiness},
	}
}

// runStep times one step and classifies its result. errStepSkipped => skipped.
func (o *RecoveryOrchestrator) runStep(ctx context.Context, s namedStep, st *runState) StepResult {
	begin := o.clock()
	detail, err := s.fn(ctx, st)
	res := StepResult{Name: s.name, DurationSeconds: o.clock().Sub(begin).Seconds(), Detail: detail}
	switch {
	case errors.Is(err, errStepSkipped):
		res.Outcome = StepSkipped
	case err != nil:
		res.Outcome = StepFailure
		res.Error = err.Error()
	default:
		res.Outcome = StepSuccess
	}
	return res
}

// stepVerifyIntegrity fetches the newest replica and runs it through the
// integrity verifier. A failure here aborts before anything is promoted.
func (o *RecoveryOrchestrator) stepVerifyIntegrity(ctx context.Context, st *runState) (string, error) {
	name, data, err := o.replicator.LatestReplica()
	if err != nil {
		return "", err
	}
	st.replicaName, st.replicaData = name, data
	if err := o.verifier.VerifyReplica(ctx, name, data); err != nil {
		return "", err
	}
	return fmt.Sprintf("verified %s (%d bytes)", name, len(data)), nil
}

func (o *RecoveryOrchestrator) stepPromote(ctx context.Context, _ *runState) (string, error) {
	if o.promoter == nil {
		return "no promoter wired", errStepSkipped
	}
	if err := o.promoter.Promote(ctx); err != nil {
		return "", err
	}
	return "replica promoted", nil
}

func (o *RecoveryOrchestrator) stepRestore(ctx context.Context, st *runState) (string, error) {
	if o.restorer == nil {
		return "no restorer wired", errStepSkipped
	}
	return o.restorer.RestoreReplica(ctx, st.replicaName, st.replicaData)
}

func (o *RecoveryOrchestrator) stepReadiness(ctx context.Context, _ *runState) (string, error) {
	if o.readiness == nil {
		return "no readiness probe wired", errStepSkipped
	}
	if err := o.readiness.ReadyCheck(ctx); err != nil {
		return "", err
	}
	return "readiness probe passed", nil
}

// finalize stamps the measured RTO (from the tracker when wired so the report
// and the RTO history agree, else a local wall-clock delta), compares it to
// the target, and retains the report.
func (o *RecoveryOrchestrator) finalize(rep *RecoveryReport, timer *RecoveryTimer, start time.Time) {
	var recErr error
	if !rep.Succeeded {
		recErr = errors.New("dr: recovery aborted at " + rep.AbortedAtStep)
	}
	if timer != nil {
		rep.MeasuredRTOSeconds = timer.Stop(recErr).DurationSeconds
	} else {
		rep.MeasuredRTOSeconds = o.clock().Sub(start).Seconds()
	}
	if o.rtoTarget > 0 {
		rep.RTOTargetSeconds = o.rtoTarget.Seconds()
		rep.RTOWithinTarget = rep.Succeeded && rep.MeasuredRTOSeconds <= o.rtoTarget.Seconds()
	} else {
		rep.RTOWithinTarget = rep.Succeeded
	}
	o.mu.Lock()
	o.lastReport = rep
	o.mu.Unlock()
}

// LastReport returns the most recent RecoveryReport, or nil when Run has never
// been called.
func (o *RecoveryOrchestrator) LastReport() *RecoveryReport {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastReport
}

// clock defaults to time.Now when now is unset (a zero-value literal never
// panics), matching how the other aggregates in this package guard their
// injected clock.
func (o *RecoveryOrchestrator) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}
