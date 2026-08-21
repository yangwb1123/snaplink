// Package controller implements the SSOConfigDrift reconciler: a loop that
// fetches cluster A's running SSO config, POSTs it to cluster B's
// cluster-diff endpoint, and records the resulting RFC 6902 patch summary in
// the CR's Status — plus explicitly approved declared-baseline apply or
// rollback writes. See ../../doc.go for the full scope: no canary, no
// automatic remediation, and no GitOps source-of-truth resolution.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	drift "github.com/yangwb1123/snaplink/cmd/sso-operator/apiv1alpha1"
)

// shortRequeueInterval governs the retry cadence after a failed attempt
// (secret lookup, HTTP call, non-2xx, malformed body, failed apply). Short
// relative to the default poll interval so a transient blip (a rolling
// restart on either cluster, a momentarily-expired token) self-heals
// quickly, without hammering either admin API — this mirrors
// platform/configaudit's own report-only fail-open loop, which never treats
// a comparison failure as fatal to the reconcile itself.
const shortRequeueInterval = 30 * time.Second

// approvalAnnotationKey is the one-shot apply approval annotation: present
// with value "true" on an opted-in CR, it authorizes the NEXT apply
// (consumed — deleted — by the controller after a successful apply, so no
// standing approval can ever cause repeated applies). Deliberately an
// annotation, not a spec field: annotations do not bump Generation (no
// self-triggered reconcile) and never enter GitOps diffs of desired state —
// approval is transient, per-action state. See
// docs/design/operator-config-apply.md Decision 1.
const approvalAnnotationKey = "sso.snaplink.io/apply-approve"

// Status.Apply.State values (empty = never attempted). conflict/rejected
// are server or contract refusals, failed covers transport and 5xx errors;
// all three keep the approval pending for retry (design doc Decision 2).
const (
	applyStateApplied  = "applied"
	applyStateConflict = "conflict"
	applyStateRejected = "rejected"
	applyStateFailed   = "failed"
)

// runningConfigPath and clusterDiffPath are appended to each cluster's
// BaseURL. Kept as constants (not literals scattered through the file) per
// AGENTS.md's "no literal leaks" convention.
const (
	runningConfigPath = "/api/v1/admin/config/running"
	clusterDiffPath   = "/api/v1/admin/config/cluster-diff"
)

// defaultHTTPTimeout bounds the ENTIRE round trip (connect + write + read,
// covers a slow-loris or black-holed target) for the production default
// client. http.DefaultClient has NO timeout, which would let one CR
// pointed at an unreachable or malicious BaseURL hang the single-worker
// reconcile loop indefinitely — stalling every other SSOConfigDrift object
// in the cluster, not just the misconfigured one. Deliberately generous
// (the whole check + apply sequence should finish in low single-digit
// seconds against a healthy target) rather than tuned tight, since this is
// an observability feature where a slow success still beats a false
// failure.
const defaultHTTPTimeout = 15 * time.Second

// defaultHTTPClient is the production default — see defaultHTTPTimeout.
// Package-level (not http.DefaultClient, which this code never mutates)
// so nothing else in the process is affected by this timeout choice.
var defaultHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}

// Reconciler drives SSOConfigDrift objects. HTTPClient defaults to
// defaultHTTPClient when nil (SetupWithManager leaves it nil for
// production use; tests inject one pointed at httptest servers).
type Reconciler struct {
	client.Client
	HTTPClient *http.Client
}

// httpClient returns the configured client, or defaultHTTPClient as a
// convenience default for production wiring.
func (r *Reconciler) httpClient() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return defaultHTTPClient
}

// Reconcile implements the fetch-post-report cycle described in the package
// doc, plus explicitly approved apply or expected-version-guarded rollback
// writes to cluster B (see maybeWrites). It NEVER returns a non-nil error for
// an HTTP/parse failure — this is a report-only feature at heart (AGENTS.md
// fail-open doctrine); the only errors returned are ones the
// controller-runtime retry/backoff machinery should own (e.g. a transient
// failure to read, update, or patch the CR itself).
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr drift.SSOConfigDrift
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	result, running := r.runCheck(ctx, &cr)
	r.applyResult(&cr, result)

	applyOut, rollbackOut, err := r.maybeWrites(ctx, &cr, running, result)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Persist status BEFORE consuming the approval: the annotation removal
	// below is a main-resource JSON merge patch without a resourceVersion
	// (unconditional), so it cannot conflict with this write regardless of
	// which order the two hit the apiserver.
	if err := r.Status().Update(ctx, &cr); err != nil {
		return ctrl.Result{}, err
	}
	if applyOut != nil && applyOut.applied() {
		if err := r.consumeApproval(ctx, &cr); err != nil {
			return ctrl.Result{}, err
		}
	}
	if rollbackOut != nil && rollbackOut.rolledBack() {
		if err := r.consumeRollbackApproval(ctx, &cr); err != nil {
			return ctrl.Result{}, err
		}
	}
	failed := result.failed || (applyOut != nil && applyOut.failed) || (rollbackOut != nil && rollbackOut.failed)
	return ctrl.Result{RequeueAfter: requeueInterval(&cr, failed)}, nil
}

// checkResult is the outcome of one fetch+diff attempt, kept separate from
// SSOConfigDriftStatus so runCheck can be tested/reasoned about without a
// live client.Object.
type checkResult struct {
	failed        bool
	driftDetected bool
	patchOpCount  int
	message       string
}

// applyOutcome is the result of one apply attempt: the classified state for
// Status.Apply, the evidence (server version id + submitted digest), a
// token-free message, and whether the reconcile should requeue short
// (failed=true for every non-applied outcome — the approval stays pending
// and the next reconcile retries; design doc Decision 2).
type applyOutcome struct {
	state     string
	versionID string
	digest    string
	message   string
	failed    bool
}

// applied reports whether the apply succeeded — the only outcome that
// consumes the approval.
func (o *applyOutcome) applied() bool {
	return o.state == applyStateApplied
}

// validateBaseURL requires an absolute https:// URL. Rejecting http (and
// any other scheme) up front means a bearer token can never be placed on
// the wire in plaintext, regardless of what a CR's author points BaseURL
// at — see the package doc's "Trust model" section for the fuller
// confused-deputy discussion this is one layer of (RBAC on who may write
// SSOConfigDrift/read Secrets is the other, operator-owned layer).
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse baseURL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("baseURL %q must be an absolute https:// URL", raw)
	}
	return nil
}

// checkFailed returns the failed checkResult pair every runCheck failure
// path shares — keeps the failure return sites one line each.
func checkFailed(message string) (checkResult, map[string]interface{}) {
	return checkResult{failed: true, message: message}, nil
}

// runCheck performs the two HTTP calls this reconciler exists for, and
// returns the validated running snapshot (nil on any failure) so an opted-in
// apply phase can re-submit it. Every failure path returns failed=true with
// a message safe to persist — never the bearer token, never the raw
// Authorization header.
func (r *Reconciler) runCheck(ctx context.Context, cr *drift.SSOConfigDrift) (checkResult, map[string]interface{}) {
	if err := validateBaseURL(cr.Spec.ClusterA.BaseURL); err != nil {
		return checkFailed(fmt.Sprintf("cluster A: %s", err))
	}
	if err := validateBaseURL(cr.Spec.ClusterB.BaseURL); err != nil {
		return checkFailed(fmt.Sprintf("cluster B: %s", err))
	}

	tokenA, err := r.resolveBearer(ctx, cr.Namespace, cr.Spec.ClusterA.BearerSecretRef)
	if err != nil {
		return checkFailed(fmt.Sprintf("cluster A secret lookup failed: %s", err))
	}
	tokenB, err := r.resolveBearer(ctx, cr.Namespace, cr.Spec.ClusterB.BearerSecretRef)
	if err != nil {
		return checkFailed(fmt.Sprintf("cluster B secret lookup failed: %s", err))
	}

	running, err := fetchRunningConfig(ctx, r.httpClient(), cr.Spec.ClusterA.BaseURL, tokenA)
	if err != nil {
		return checkFailed(fmt.Sprintf("fetch cluster A running config failed: %s", err))
	}
	if err := validateRunningSnapshot(running); err != nil {
		return checkFailed(fmt.Sprintf("cluster A running config failed structural validation: %s", err))
	}

	patch, err := postClusterDiff(ctx, r.httpClient(), cr.Spec.ClusterB.BaseURL, tokenB, running)
	if err != nil {
		return checkFailed(fmt.Sprintf("cluster B diff request failed: %s", err))
	}
	if err := validatePatch(patch, running); err != nil {
		return checkFailed(fmt.Sprintf("cluster B diff response failed structural validation: %s", err))
	}

	return checkResult{
		driftDetected: len(patch) > 0,
		patchOpCount:  len(patch),
		message:       summarize(len(patch)),
	}, running
}

// maybeApply runs the apply phase: nil unless the CR is opted in, the
// one-shot approval annotation is present, and the just-completed check
// found drift — then it issues ONE apply to cluster B and records the
// outcome in Status.Apply (in memory). Persisting the status and consuming
// the approval are the caller's job, so this function stays write-free and
// an apply failure never suppresses the drift report (the check result was
// already written by the caller); it only affects the requeue interval via
// out.failed.
func (r *Reconciler) maybeApply(ctx context.Context, cr *drift.SSOConfigDrift, running map[string]interface{}, result checkResult) (*applyOutcome, error) {
	if !shouldApply(cr, result) {
		return nil, nil
	}
	out := r.runApply(ctx, cr, running)
	applyApplyResult(cr, out)
	return out, nil
}

// shouldApply is the apply-phase gate: opt-in, one-shot approval present,
// and a SUCCESSFUL check that found drift. The approval check runs even
// while a check-failure loop is active, so an approval added mid-retry is
// picked up by the next short requeue rather than silently ignored.
func shouldApply(cr *drift.SSOConfigDrift, result checkResult) bool {
	if !cr.Spec.Apply.Enabled || result.failed || !result.driftDetected {
		return false
	}
	return cr.Annotations[approvalAnnotationKey] == "true"
}

// runApply issues the single write this controller can make: POST cluster
// B's /api/v1/admin/config/apply?approve=true with cluster A's (already
// server-redacted) running snapshot, its canonical digest, and the CR's
// declared reason. The snapshot is never persisted anywhere by this
// controller — it lives only in memory for this call; Status stores only
// the digest hash and the server's version id.
func (r *Reconciler) runApply(ctx context.Context, cr *drift.SSOConfigDrift, running map[string]interface{}) *applyOutcome {
	if strings.TrimSpace(cr.Spec.Apply.Reason) == "" {
		return &applyOutcome{
			state:   applyStateRejected,
			failed:  true,
			message: "apply rejected: spec.apply.reason is required when spec.apply.enabled is true",
		}
	}
	digest, err := snapshotDigest(running)
	if err != nil {
		return &applyOutcome{state: applyStateFailed, failed: true, message: fmt.Sprintf("apply failed: compute snapshot digest: %s", err)}
	}
	tokenB, err := r.resolveBearer(ctx, cr.Namespace, cr.Spec.ClusterB.BearerSecretRef)
	if err != nil {
		return &applyOutcome{state: applyStateFailed, failed: true, message: fmt.Sprintf("cluster B secret lookup failed: %s", err)}
	}
	resp, status, err := postConfigApply(ctx, r.httpClient(), cr.Spec.ClusterB.BaseURL, tokenB, digest, cr.Spec.Apply.Reason, running)
	if err != nil {
		out := &applyOutcome{failed: true, digest: digest, message: fmt.Sprintf("cluster B apply request failed: %s", err)}
		switch status {
		case http.StatusConflict:
			out.state = applyStateConflict
		case http.StatusBadRequest:
			out.state = applyStateRejected
		default:
			out.state = applyStateFailed
		}
		return out
	}
	if resp.Version == "" {
		return &applyOutcome{state: applyStateFailed, failed: true, digest: digest, message: "cluster B apply response failed structural validation: missing version"}
	}
	return &applyOutcome{
		state:     applyStateApplied,
		versionID: resp.Version,
		digest:    digest,
		message:   fmt.Sprintf("applied: baseline version %s recorded on cluster B", resp.Version),
	}
}

// applyApplyResult copies an applyOutcome into Status.Apply. Called only
// when an apply was attempted; otherwise ApplyStatus stays empty (omitted
// from the CR, so report-only CRs never grow an apply field).
func applyApplyResult(cr *drift.SSOConfigDrift, out *applyOutcome) {
	cr.Status.Apply = drift.ApplyStatus{
		State:         out.state,
		LastAttemptAt: metav1.Now(),
		VersionID:     out.versionID,
		Digest:        out.digest,
		Message:       out.message,
	}
}

// consumeApproval deletes the one-shot approval annotation after a
// successful apply. A metadata-only JSON merge patch on a DeepCopy — never
// a spec mutation, no Generation bump, no reconcile loop — whose diff (the
// annotation removal only, resourceVersion unchanged) is unconditional, so
// it cannot conflict with the Status().Update that just ran. The original
// cr is left untouched: a main-resource write must not clobber the status
// that Status().Update already persisted (status-subresource semantics).
func (r *Reconciler) consumeApproval(ctx context.Context, cr *drift.SSOConfigDrift) error {
	if cr.Annotations == nil {
		return nil
	}
	if _, ok := cr.Annotations[approvalAnnotationKey]; !ok {
		return nil
	}
	patched := cr.DeepCopy()
	delete(patched.Annotations, approvalAnnotationKey)
	return r.Patch(ctx, patched, client.MergeFrom(cr))
}

// snapshotDigest computes the canonical sha256 hex digest of a config
// snapshot — MUST stay byte-identical to platform/configaudit.Digest
// (sorted-key encoding/json marshal, then sha256, then hex): the server
// recomputes the same digest over the submitted snapshot and compares
// byte-wise (split-brain guard, config-apply-mode.md Decision 4). Byte
// identity is pinned by a known-answer test — this module cannot import
// platform/configaudit without dragging otelhttp transitives into its
// go.sum (design doc Decision 6).
func snapshotDigest(snapshot map[string]interface{}) (string, error) {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// summarize builds the human-readable Status.Message for a successful
// check. Kept separate so the wording lives in one place.
func summarize(opCount int) string {
	if opCount == 0 {
		return "no drift: cluster B matches cluster A's running config"
	}
	return fmt.Sprintf("drift detected: %d patch operation(s) needed on cluster B", opCount)
}

// applyResult copies a checkResult into the CR's Status. On failure,
// DriftDetected/PatchOpCount deliberately KEEP their previous values — a
// transient HTTP error is not itself evidence of "no drift" (see
// SSOConfigDriftStatus.DriftDetected's doc comment).
func (r *Reconciler) applyResult(cr *drift.SSOConfigDrift, result checkResult) {
	cr.Status.LastCheckedAt = metav1.Now()
	cr.Status.Message = result.message
	cr.Status.ObservedGeneration = cr.Generation
	if !result.failed {
		cr.Status.DriftDetected = result.driftDetected
		cr.Status.PatchOpCount = result.patchOpCount
	}
}

// resolveBearer reads the referenced Secret key in the given namespace.
// Namespace is always the CR's own namespace — a SecretKeySelector has no
// namespace field of its own (core/v1 convention: same-namespace only),
// which also keeps this from becoming a cross-namespace credential-read
// primitive.
func (r *Reconciler) resolveBearer(ctx context.Context, namespace string, ref corev1.SecretKeySelector) (string, error) {
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: namespace, Name: ref.Name}
	if err := r.Get(ctx, key, &secret); err != nil {
		return "", fmt.Errorf("get secret %s: %w", ref.Name, err)
	}
	value, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("secret %s has no key %q", ref.Name, ref.Key)
	}
	return string(value), nil
}

// requeueInterval picks the next reconcile delay: the short fixed backoff
// after a failure, else the CR's configured (or default) poll interval.
func requeueInterval(cr *drift.SSOConfigDrift, failed bool) time.Duration {
	if failed {
		return shortRequeueInterval
	}
	interval, err := time.ParseDuration(cr.Spec.PollInterval)
	if cr.Spec.PollInterval == "" || err != nil {
		interval, _ = time.ParseDuration(drift.DefaultPollInterval)
	}
	return interval
}

// SetupWithManager wires this reconciler into mgr, watching SSOConfigDrift
// objects only — Secret changes deliberately do NOT trigger a reconcile
// (a rotated token takes effect on the next poll tick, not instantly; wiring
// a Secret watch would mean indexing every SSOConfigDrift's two
// SecretKeySelectors, a complexity this reporting feature does not
// warrant). Annotation-only changes (the apply or rollback approval) deliberately do
// NOT trigger a reconcile either: that is the apply-mode throttle — an
// approval takes effect on the next scheduled poll, at most once per
// approval (see docs/design/operator-config-apply.md Decision 2).
//
// GenerationChangedPredicate is REQUIRED, not an optimization: every
// Reconcile ends with r.Status().Update, and controller-runtime's default
// Update handler re-enqueues on ANY Update event to the watched object —
// including that very status-subresource write, which does NOT bump
// Generation. Without this predicate the controller would re-trigger
// itself in a tight loop immediately after every reconcile, never actually
// honoring PollInterval/shortRequeueInterval, and sending live bearer
// tokens to both clusters continuously instead of on the intended cadence.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&drift.SSOConfigDrift{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
