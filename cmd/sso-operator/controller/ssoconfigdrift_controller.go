// Package controller implements the SSOConfigDrift reconciler: a read-only
// loop that fetches cluster A's running SSO config, POSTs it to cluster B's
// cluster-diff endpoint, and records the resulting RFC 6902 patch summary in
// the CR's Status. See ../../doc.go for the full non-goals list (no apply,
// no canary, no remediation).
package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
// (secret lookup, HTTP call, non-2xx, malformed body). Short relative to
// the default poll interval so a transient blip (a rolling restart on
// either cluster, a momentarily-expired token) self-heals quickly, without
// hammering either admin API — this mirrors platform/configaudit's own
// report-only fail-open loop, which never treats a comparison failure as
// fatal to the reconcile itself.
const shortRequeueInterval = 30 * time.Second

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
// (both HTTP calls together should finish in low single-digit seconds
// against a healthy target) rather than tuned tight, since this is a
// report-only feature where a slow success still beats a false failure.
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

// Reconcile implements the read-fetch-post-report cycle described in the
// package doc. It NEVER returns a non-nil error for an HTTP/parse failure —
// this is a report-only feature (AGENTS.md fail-open doctrine); the only
// errors returned are ones the controller-runtime retry/backoff machinery
// should own (e.g. a transient failure to read or patch the CR itself).
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cr drift.SSOConfigDrift
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	result := r.runCheck(ctx, &cr)
	r.applyResult(&cr, result)

	if err := r.Status().Update(ctx, &cr); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueInterval(&cr, result.failed)}, nil
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

// runCheck performs the two HTTP calls this reconciler exists for. Every
// failure path returns failed=true with a message safe to persist — never
// the bearer token, never the raw Authorization header.
func (r *Reconciler) runCheck(ctx context.Context, cr *drift.SSOConfigDrift) checkResult {
	if err := validateBaseURL(cr.Spec.ClusterA.BaseURL); err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster A: %s", err)}
	}
	if err := validateBaseURL(cr.Spec.ClusterB.BaseURL); err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster B: %s", err)}
	}

	tokenA, err := r.resolveBearer(ctx, cr.Namespace, cr.Spec.ClusterA.BearerSecretRef)
	if err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster A secret lookup failed: %s", err)}
	}
	tokenB, err := r.resolveBearer(ctx, cr.Namespace, cr.Spec.ClusterB.BearerSecretRef)
	if err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster B secret lookup failed: %s", err)}
	}

	running, err := fetchRunningConfig(ctx, r.httpClient(), cr.Spec.ClusterA.BaseURL, tokenA)
	if err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("fetch cluster A running config failed: %s", err)}
	}

	patch, err := postClusterDiff(ctx, r.httpClient(), cr.Spec.ClusterB.BaseURL, tokenB, running)
	if err != nil {
		return checkResult{failed: true, message: fmt.Sprintf("cluster B diff request failed: %s", err)}
	}

	return checkResult{
		driftDetected: len(patch) > 0,
		patchOpCount:  len(patch),
		message:       summarize(len(patch)),
	}
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
// SecretKeySelectors, a complexity this read-only reporting feature does
// not warrant).
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
