package controller

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	drift "github.com/yangwb1123/snaplink/cmd/sso-operator/apiv1alpha1"
)

const (
	rollbackApprovalAnnotationKey = "sso.snaplink.io/rollback-approve"
	rollbackPath                  = "/api/v1/admin/config/rollback"
	rollbackStateRolledBack       = "rolled_back"
	rollbackStateConflict         = "conflict"
	rollbackStateRejected         = "rejected"
	rollbackStateFailed           = "failed"
)

// rollbackOutcome is the token-free result persisted in Status.Rollback.
type rollbackOutcome struct {
	state             string
	versionID         string
	expectedVersionID string
	message           string
	failed            bool
}

func (o *rollbackOutcome) rolledBack() bool {
	return o != nil && o.state == rollbackStateRolledBack
}

// maybeWrites enforces the one-write-per-reconcile boundary. Apply and
// rollback approvals cannot be acted on together, even if only one mode is
// enabled, because silently choosing one would make an operator typo unsafe.
func (r *Reconciler) maybeWrites(ctx context.Context, cr *drift.SSOConfigDrift, running map[string]interface{}, result checkResult) (*applyOutcome, *rollbackOutcome, error) {
	if bothWriteApprovals(cr) {
		applyOut := &applyOutcome{state: applyStateRejected, failed: true, message: "apply and rollback approvals cannot be combined"}
		rollbackOut := &rollbackOutcome{state: rollbackStateRejected, failed: true, message: "apply and rollback approvals cannot be combined"}
		applyApplyResult(cr, applyOut)
		applyRollbackResult(cr, rollbackOut)
		return applyOut, rollbackOut, nil
	}
	applyOut, err := r.maybeApply(ctx, cr, running, result)
	if err != nil || applyOut != nil {
		return applyOut, nil, err
	}
	return nil, r.maybeRollback(ctx, cr, result), nil
}

func bothWriteApprovals(cr *drift.SSOConfigDrift) bool {
	return cr.Annotations[approvalAnnotationKey] == "true" && cr.Annotations[rollbackApprovalAnnotationKey] == "true"
}

func (r *Reconciler) maybeRollback(ctx context.Context, cr *drift.SSOConfigDrift, result checkResult) *rollbackOutcome {
	if !shouldRollback(cr, result) {
		return nil
	}
	out := r.runRollback(ctx, cr)
	applyRollbackResult(cr, out)
	return out
}

func shouldRollback(cr *drift.SSOConfigDrift, result checkResult) bool {
	if !cr.Spec.Rollback.Enabled || result.failed {
		return false
	}
	return cr.Annotations[rollbackApprovalAnnotationKey] == "true"
}

func (r *Reconciler) runRollback(ctx context.Context, cr *drift.SSOConfigDrift) *rollbackOutcome {
	reason := strings.TrimSpace(cr.Spec.Rollback.Reason)
	expected := strings.TrimSpace(cr.Spec.Rollback.ExpectedVersionID)
	if reason == "" || expected == "" {
		return &rollbackOutcome{state: rollbackStateRejected, expectedVersionID: expected, failed: true, message: "rollback rejected: reason and expected_version_id are required"}
	}
	token, err := r.resolveBearer(ctx, cr.Namespace, cr.Spec.ClusterB.BearerSecretRef)
	if err != nil {
		return rollbackFailed(expected, fmt.Sprintf("rollback failed: cluster B secret lookup: %s", err))
	}
	resp, status, err := postConfigRollback(ctx, r.httpClient(), cr.Spec.ClusterB.BaseURL, token, expected, reason)
	if err != nil {
		return classifyRollbackFailure(status, expected, err)
	}
	if resp.Version == "" {
		return rollbackFailed(expected, "rollback failed: cluster B response missing version")
	}
	return &rollbackOutcome{
		state: rollbackStateRolledBack, versionID: resp.Version, expectedVersionID: expected,
		message: fmt.Sprintf("rolled back: baseline version %s recorded on cluster B", resp.Version),
	}
}

func classifyRollbackFailure(status int, expected string, err error) *rollbackOutcome {
	state := rollbackStateFailed
	if status == 400 {
		state = rollbackStateRejected
	} else if status == 409 {
		state = rollbackStateConflict
	}
	return &rollbackOutcome{state: state, expectedVersionID: expected, failed: true, message: fmt.Sprintf("rollback request failed: %s", err)}
}

func rollbackFailed(expected, message string) *rollbackOutcome {
	return &rollbackOutcome{state: rollbackStateFailed, expectedVersionID: expected, failed: true, message: message}
}

func applyRollbackResult(cr *drift.SSOConfigDrift, out *rollbackOutcome) {
	cr.Status.Rollback = drift.RollbackStatus{
		State: out.state, LastAttemptAt: metav1.Now(), VersionID: out.versionID,
		ExpectedVersionID: out.expectedVersionID, Message: out.message,
	}
}

func (r *Reconciler) consumeRollbackApproval(ctx context.Context, cr *drift.SSOConfigDrift) error {
	if cr.Annotations == nil {
		return nil
	}
	if _, ok := cr.Annotations[rollbackApprovalAnnotationKey]; !ok {
		return nil
	}
	patched := cr.DeepCopy()
	delete(patched.Annotations, rollbackApprovalAnnotationKey)
	return r.Patch(ctx, patched, client.MergeFrom(cr))
}
