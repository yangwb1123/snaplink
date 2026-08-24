package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	drift "github.com/yangwb1123/snaplink/cmd/sso-operator/apiv1alpha1"
)

// testRunningConfig is the cluster-A running snapshot used throughout the
// apply tests. Its canonical digest (knownDigestRunningConfig) is the
// byte-identical configaudit.Digest output — see
// TestSnapshotDigest_MatchesConfigAuditKnownAnswers.
var testRunningConfig = map[string]interface{}{"issuer": "https://a.example", "n": float64(1)}

// knownDigestRunningConfig is sha256 over the configaudit-canonical
// (sorted-key) JSON marshal of testRunningConfig, derived once from the
// root module's platform/configaudit.Digest — the exact value the operator
// must submit so the server's split-brain check passes.
const knownDigestRunningConfig = "c80484feac36abef3ffd4e1e1a101f1a3d9190686100ec0327e35f570847807a"

const testApplyReason = "align staging with prod (INC-1234)"

var testDriftOps = []map[string]interface{}{
	{"op": "replace", "path": "/issuer", "value": "https://b.example"},
}

// recordedApply captures one apply request exactly as the controller sent
// it, so tests can assert the wire shape (method, path, query, bearer
// header, body) against the documented contract.
type recordedApply struct {
	method string
	path   string
	query  string
	auth   string
	body   applyRequestBody
}

// applyRecorder collects apply requests from the fake cluster B.
type applyRecorder struct {
	mu    sync.Mutex
	calls []recordedApply
}

func (r *applyRecorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *applyRecorder) at(i int) recordedApply {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[i]
}

// applyRecordingServer simulates cluster B's full admin surface: the
// read-only cluster-diff handler (replying patchOps) and the apply handler,
// which records every request and replies with applyStatus + applyBody. A
// wrong bearer token gets 401 on both, like the real bearer-auth middleware.
func applyRecordingServer(t *testing.T, wantToken string, patchOps []map[string]interface{}, applyStatus int, applyBody string) (*httptest.Server, *applyRecorder) {
	t.Helper()
	rec := &applyRecorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}
		switch req.URL.Path {
		case clusterDiffPath:
			var body map[string]interface{}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body["snapshot"] == nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "missing snapshot"})
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"patch": patchOps})
		case applyPath:
			var recCall recordedApply
			recCall.method = req.Method
			recCall.path = req.URL.Path
			recCall.query = req.URL.RawQuery
			recCall.auth = req.Header.Get("Authorization")
			if err := json.NewDecoder(req.Body).Decode(&recCall.body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
				return
			}
			rec.mu.Lock()
			rec.calls = append(rec.calls, recCall)
			rec.mu.Unlock()
			w.WriteHeader(applyStatus)
			_, _ = io.WriteString(w, applyBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, rec
}

// fetchCR re-reads the full CR (metadata included) so tests can assert the
// approval annotation was consumed.
func fetchCR(t *testing.T, r *Reconciler, key types.NamespacedName) drift.SSOConfigDrift {
	t.Helper()
	var cr drift.SSOConfigDrift
	if err := r.Get(t.Context(), key, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	return cr
}

// TestReconcile_Apply_OptInApproved_AppliesWithExactRequestShape is the
// core happy path: opt-in + approval + drift must produce EXACTLY one apply
// POST with the documented wire shape, a recorded Status.Apply, and a
// consumed approval.
func TestReconcile_Apply_OptInApproved_AppliesWithExactRequestShape(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := applyRecordingServer(t, "token-b-secret-value", testDriftOps, http.StatusOK,
		`{"applied":{"issuer":"https://a.example","n":1},"version":"v3","prev_version":"v2","patch":[]}`)
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: testApplyReason},
		map[string]string{approvalAnnotationKey: "true"})

	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if res.RequeueAfter != 1*time.Minute {
		t.Errorf("RequeueAfter = %v, want PollInterval (1m) after a successful apply", res.RequeueAfter)
	}

	if rec.len() != 1 {
		t.Fatalf("apply calls = %d, want exactly 1", rec.len())
	}
	call := rec.at(0)
	if call.method != http.MethodPost {
		t.Errorf("apply method = %q, want POST", call.method)
	}
	if call.path != applyPath {
		t.Errorf("apply path = %q, want %q", call.path, applyPath)
	}
	if call.query != "approve=true" {
		t.Errorf("apply query = %q, want the mandatory approve=true", call.query)
	}
	if call.auth != "Bearer token-b-secret-value" {
		t.Errorf("apply Authorization = %q, want cluster B's bearer token", call.auth)
	}
	if !reflect.DeepEqual(call.body.Snapshot, testRunningConfig) {
		t.Errorf("apply snapshot = %v, want cluster A's running config %v", call.body.Snapshot, testRunningConfig)
	}
	if call.body.Digest != knownDigestRunningConfig {
		t.Errorf("apply digest = %q, want the canonical configaudit digest %q", call.body.Digest, knownDigestRunningConfig)
	}
	if call.body.Reason != testApplyReason {
		t.Errorf("apply reason = %q, want the spec reason %q", call.body.Reason, testApplyReason)
	}

	status := fetchStatus(t, r, key)
	if status.Apply.State != applyStateApplied {
		t.Errorf("status.apply.state = %q, want %q", status.Apply.State, applyStateApplied)
	}
	if status.Apply.VersionID != "v3" {
		t.Errorf("status.apply.versionID = %q, want v3", status.Apply.VersionID)
	}
	if status.Apply.Digest != knownDigestRunningConfig {
		t.Errorf("status.apply.digest = %q, want the canonical digest", status.Apply.Digest)
	}
	if status.Apply.LastAttemptAt.IsZero() {
		t.Errorf("status.apply.lastAttemptAt not set")
	}
	if !strings.Contains(status.Apply.Message, "v3") {
		t.Errorf("status.apply.message = %q, want it to name version v3", status.Apply.Message)
	}
	// The apply result coexists with the drift summary.
	if !status.DriftDetected || status.PatchOpCount != 1 {
		t.Errorf("drift fields not reported alongside the apply result: %+v", status)
	}

	// The one-shot approval was consumed by the successful apply.
	cr := fetchCR(t, r, key)
	if cr.Annotations[approvalAnnotationKey] != "" {
		t.Errorf("approval annotation still present after a successful apply: %v", cr.Annotations)
	}
}

// TestReconcile_Apply_NotOptedIn_ZeroApplyCalls pins the hard boundary: a
// CR that never opts in must make zero apply calls and grow no apply
// status, with the report-only behavior unchanged.
func TestReconcile_Apply_NotOptedIn_ZeroApplyCalls(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := applyRecordingServer(t, "token-b-secret-value", testDriftOps, http.StatusOK, `{}`)
	defer serverB.Close()

	// Report-only CR: ApplySpec zero value, no annotation.
	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if rec.len() != 0 {
		t.Errorf("apply calls = %d, want 0 for a non-opted-in CR", rec.len())
	}
	status := fetchStatus(t, r, key)
	if status.Apply != (drift.ApplyStatus{}) {
		t.Errorf("status.apply = %+v, want empty for a non-opted-in CR", status.Apply)
	}
	if !status.DriftDetected || status.PatchOpCount != 1 {
		t.Errorf("report-only drift reporting changed for a non-opted-in CR: %+v", status)
	}
}

// TestReconcile_Apply_NotApproved_ZeroApplyCalls pins the approval gate:
// opt-in alone must not apply — the one-shot annotation is required.
func TestReconcile_Apply_NotApproved_ZeroApplyCalls(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := applyRecordingServer(t, "token-b-secret-value", testDriftOps, http.StatusOK, `{}`)
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: testApplyReason}, nil)
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if rec.len() != 0 {
		t.Errorf("apply calls = %d, want 0 without the approval annotation", rec.len())
	}
	if status := fetchStatus(t, r, key); status.Apply != (drift.ApplyStatus{}) {
		t.Errorf("status.apply = %+v, want empty without approval", status.Apply)
	}
}

// TestReconcile_Apply_Conflict_RecordsStatusAndRetainsApproval pins the 409
// split-brain outcome: Status records it, the drift report still lands
// (fail-open), and the approval stays pending for retry.
func TestReconcile_Apply_Conflict_RecordsStatusAndRetainsApproval(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := applyRecordingServer(t, "token-b-secret-value", testDriftOps, http.StatusConflict,
		`{"error":"config_apply_conflict"}`)
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: testApplyReason},
		map[string]string{approvalAnnotationKey: "true"})

	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if res.RequeueAfter != shortRequeueInterval {
		t.Errorf("RequeueAfter = %v, want short backoff on a failed apply", res.RequeueAfter)
	}
	if rec.len() != 1 {
		t.Fatalf("apply calls = %d, want 1", rec.len())
	}

	status := fetchStatus(t, r, key)
	if status.Apply.State != applyStateConflict {
		t.Errorf("status.apply.state = %q, want conflict", status.Apply.State)
	}
	if !strings.Contains(status.Apply.Message, "config_apply_conflict") {
		t.Errorf("status.apply.message = %q, want the server wire code", status.Apply.Message)
	}
	if !status.DriftDetected || status.PatchOpCount != 1 {
		t.Errorf("drift fields suppressed by the failed apply: %+v", status)
	}
	cr := fetchCR(t, r, key)
	if cr.Annotations[approvalAnnotationKey] != "true" {
		t.Errorf("approval consumed on a failed apply, want retained for retry")
	}
}

// TestReconcile_Apply_ServerError_FailOpenContinuesDriftReporting pins the
// fail-open doctrine: a 500 on apply is recorded as failed, the drift report
// still lands, and no token ever reaches Status.
func TestReconcile_Apply_ServerError_FailOpenContinuesDriftReporting(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := applyRecordingServer(t, "token-b-secret-value", testDriftOps, http.StatusInternalServerError,
		`{"error":"internal_error"}`)
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: testApplyReason},
		map[string]string{approvalAnnotationKey: "true"})

	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if res.RequeueAfter != shortRequeueInterval {
		t.Errorf("RequeueAfter = %v, want short backoff on a failed apply", res.RequeueAfter)
	}
	if rec.len() != 1 {
		t.Fatalf("apply calls = %d, want 1", rec.len())
	}

	status := fetchStatus(t, r, key)
	if status.Apply.State != applyStateFailed {
		t.Errorf("status.apply.state = %q, want failed", status.Apply.State)
	}
	if !status.DriftDetected || status.PatchOpCount != 1 {
		t.Errorf("failed apply suppressed the drift report: %+v", status)
	}
	for _, m := range []string{status.Apply.Message, status.Message} {
		if strings.Contains(m, "token-a-secret-value") || strings.Contains(m, "token-b-secret-value") {
			t.Errorf("Status leaked a bearer token: %q", m)
		}
	}
}

// TestReconcile_Apply_NoDrift_NoApplyApprovalRetained pins the trigger
// condition: with nothing to apply, no apply is issued and the approval
// stays pending for the next drift.
func TestReconcile_Apply_NoDrift_NoApplyApprovalRetained(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := applyRecordingServer(t, "token-b-secret-value", []map[string]interface{}{}, http.StatusOK, `{}`)
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: testApplyReason},
		map[string]string{approvalAnnotationKey: "true"})
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if rec.len() != 0 {
		t.Errorf("apply calls = %d, want 0 when there is no drift", rec.len())
	}
	cr := fetchCR(t, r, key)
	if cr.Annotations[approvalAnnotationKey] != "true" {
		t.Errorf("approval consumed with no drift, want retained")
	}
}

// TestReconcile_Apply_OneShotThrottle_SecondReconcileMakesNoApply pins the
// "don't call apply every round" throttle: drift persists after a
// successful apply (apply does not change running configs), yet the second
// reconcile issues zero apply calls because the approval was consumed.
func TestReconcile_Apply_OneShotThrottle_SecondReconcileMakesNoApply(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := applyRecordingServer(t, "token-b-secret-value", testDriftOps, http.StatusOK,
		`{"applied":{"issuer":"https://a.example","n":1},"version":"v3","prev_version":"v2","patch":[]}`)
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: testApplyReason},
		map[string]string{approvalAnnotationKey: "true"})

	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("first Reconcile returned error: %v", err)
	}
	if rec.len() != 1 {
		t.Fatalf("apply calls after first reconcile = %d, want 1", rec.len())
	}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("second Reconcile returned error: %v", err)
	}
	if rec.len() != 1 {
		t.Errorf("apply calls after second reconcile = %d, want still 1 (one-shot approval)", rec.len())
	}
	if status := fetchStatus(t, r, key); !status.DriftDetected {
		t.Errorf("drift not reported on the second reconcile")
	}
}

// TestReconcile_Apply_BlankReason_RejectedWithoutContactingServer pins the
// controller-side guard: a blank spec.apply.reason refuses the apply BEFORE
// any HTTP call (the server would 400 it anyway; the guard keeps the wire
// clean and the State honest).
func TestReconcile_Apply_BlankReason_RejectedWithoutContactingServer(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case clusterDiffPath:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"patch": testDriftOps})
		case applyPath:
			t.Errorf("apply must not be contacted when spec.apply.reason is blank")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: "   "},
		map[string]string{approvalAnnotationKey: "true"})
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if status.Apply.State != applyStateRejected {
		t.Errorf("status.apply.state = %q, want rejected", status.Apply.State)
	}
	if !strings.Contains(status.Apply.Message, "spec.apply.reason") {
		t.Errorf("status.apply.message = %q, want it to name the missing reason", status.Apply.Message)
	}
	if !status.DriftDetected {
		t.Errorf("blank-reason rejection suppressed the drift report")
	}
}

// TestSnapshotDigest_MatchesConfigAuditKnownAnswers pins snapshotDigest to
// the server-side canonicalization (platform/configaudit.Digest: sorted-key
// encoding/json marshal, then sha256, then hex) via known answers derived
// ONCE from the root module. This nested module must not import
// platform/configaudit in production (it would drag otelhttp transitives
// into this go.sum), so the wire contract is pinned as constants instead —
// a mismatch here means the operator would submit a digest the server's
// split-brain check rejects with 409.
func TestSnapshotDigest_MatchesConfigAuditKnownAnswers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		snapshot map[string]interface{}
		want     string
	}{
		{
			name:     "scalar only",
			snapshot: map[string]interface{}{"issuer": "https://a.example"},
			want:     "f2b20c1adb83ddfe950f76ed4fc2ad8053f7063acd6bc00b8907fbaaaec7f293",
		},
		{
			name:     "numeric value decoded from JSON (float64)",
			snapshot: testRunningConfig,
			want:     knownDigestRunningConfig,
		},
		{
			name:     "nested map and array",
			snapshot: map[string]interface{}{"issuer": "https://a.example", "keys": []interface{}{"k1", "k2"}, "tls": map[string]interface{}{"min": "1.2"}},
			want:     "7dedab369319cdac89106a042f23ded199b8e6aead1b60007831dd75f7d6b8d3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := snapshotDigest(tc.snapshot)
			if err != nil {
				t.Fatalf("snapshotDigest: %v", err)
			}
			if got != tc.want {
				t.Errorf("snapshotDigest = %q, want configaudit.Digest known answer %q", got, tc.want)
			}
		})
	}
}

// TestReconcile_Apply_StatusApplyEmptyOnCheckFailure pins that a failed
// check (never reaching the diff phase) leaves Status.Apply empty even for
// an opted-in, approved CR — apply is only attempted on a SUCCESSFUL check
// with drift.
func TestReconcile_Apply_StatusApplyEmptyOnCheckFailure(t *testing.T) {
	serverA := runningServer(t, "the-real-token-A", nil) // wrong token -> 401
	defer serverA.Close()
	serverB := applyRecordingServerMustNotApply(t)
	defer serverB.Close()

	r, key := buildReconcilerCustom(t, serverA, serverB, "1m",
		drift.ApplySpec{Enabled: true, Reason: testApplyReason},
		map[string]string{approvalAnnotationKey: "true"})
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if status.Apply != (drift.ApplyStatus{}) {
		t.Errorf("status.apply = %+v, want empty when the check failed before any diff", status.Apply)
	}
	if status.Message == "" {
		t.Errorf("status.message empty, want the check failure summary")
	}
}

// applyRecordingServerMustNotApply is a cluster-B server that fails the
// test if the apply path is ever hit (the check-failure case must not reach
// it), serving only the cluster-diff path.
func applyRecordingServerMustNotApply(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == applyPath {
			t.Errorf("apply must not be contacted when the check failed")
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
}
